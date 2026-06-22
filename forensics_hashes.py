"""Cálculo de hashes criptográficos de la imagen e información de particiones."""
import hashlib
import os

import pyewf
import pytsk3

from utils import get_logger

log = get_logger()


def calcular_hashes(ruta_imagen, on_update=None):
    """
    Calcula MD5, SHA-1 y SHA-256 de la imagen, emitiendo eventos granulares.

    Comportamiento por formato:
      - E01/EWF: MD5 y SHA-1 se leen de los metadatos (instantáneo). SHA-256
        se calcula sobre el contenido descomprimido (con barra de progreso).
      - .dd/.raw/.img: los tres hashes se calculan en una sola pasada de
        lectura del archivo, por lo que comparten la misma barra de progreso
        y finalizan a la vez.

    Args:
        ruta_imagen: Ruta al archivo de imagen.
        on_update:   callback(algo, status, value=None, progress=None) llamado
                     en transiciones. `algo` {"MD5", "SHA-1", "SHA-256"},
                     `status` {"calculating", "done", "error"}.

    Returns:
        dict con keys 'MD5', 'SHA-1', 'SHA-256', 'fuente', 'tamaño_bytes'.
    """
    def _notify(algo, status, value=None, progress=None):
        if on_update:
            try:
                on_update(algo, status, value=value, progress=progress)
            except Exception as e:
                # nunca dejar que un callback de UI rompa el cálculo de hashes
                log.debug("Callback de progreso de hash falló: %s", e)

    resultado = {"MD5": None, "SHA-1": None, "SHA-256": None,
                 "fuente": "", "tamaño_bytes": 0}
    ruta_lower = ruta_imagen.lower()

    # --- Caso 1: E01/EWF ---
    if ruta_lower.endswith((".e01", ".ex01", ".l01")):
        try:
            filenames = pyewf.glob(ruta_imagen)
            handle = pyewf.handle()
            handle.open(filenames)
            resultado["tamaño_bytes"] = handle.get_media_size()

            # MD5 desde metadatos
            _notify("MD5", "calculating", progress=0.0)
            try:
                md5_val = handle.get_hash_value("MD5")
                if md5_val:
                    resultado["MD5"] = md5_val
                    _notify("MD5", "done", value=md5_val, progress=1.0)
                else:
                    _notify("MD5", "error")
            except Exception as e:
                log.warning("MD5 de metadatos EWF no disponible: %s", e)
                _notify("MD5", "error")

            # SHA-1 desde metadatos
            _notify("SHA-1", "calculating", progress=0.0)
            try:
                sha1_val = handle.get_hash_value("SHA1")
                if sha1_val:
                    resultado["SHA-1"] = sha1_val
                    _notify("SHA-1", "done", value=sha1_val, progress=1.0)
                else:
                    _notify("SHA-1", "error")
            except Exception as e:
                log.warning("SHA-1 de metadatos EWF no disponible: %s", e)
                _notify("SHA-1", "error")

            resultado["fuente"] = "Metadatos EWF + cálculo de SHA-256 sobre el contenido"
            handle.close()
        except Exception as e:
            resultado["fuente"] = f"Error leyendo E01: {e}"
            _notify("MD5", "error")
            _notify("SHA-1", "error")
            _notify("SHA-256", "error")
            return resultado

        # SHA-256: hay que leer el contenido descomprimido (lento)
        _notify("SHA-256", "calculating", progress=0.0)
        try:
            def _cb(p):
                _notify("SHA-256", "calculating", progress=p)

            sha256_val = _hash_ewf_sha256(ruta_imagen, log_callback=_cb)
            resultado["SHA-256"] = sha256_val
            _notify("SHA-256", "done", value=sha256_val, progress=1.0)
        except Exception as e:
            log.warning("Cálculo de SHA-256 sobre contenido EWF falló: %s", e)
            _notify("SHA-256", "error")

        return resultado

    # --- Caso 2: .dd/.raw/.img (single-pass) ---
    try:
        total_size = os.path.getsize(ruta_imagen)
        resultado["tamaño_bytes"] = total_size
        resultado["fuente"] = "Calculado sobre archivo en bruto (single-pass)"

        # En .dd los tres hashes comparten la pasada de lectura.
        _notify("MD5", "calculating", progress=0.0)
        _notify("SHA-1", "calculating", progress=0.0)
        _notify("SHA-256", "calculating", progress=0.0)

        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        bytes_read = 0
        chunk = 64 * 1024 * 1024  # 64 MB
        last_pct_reported = 0.0

        with open(ruta_imagen, "rb") as f:
            while True:
                data = f.read(chunk)
                if not data:
                    break
                md5.update(data)
                sha1.update(data)
                sha256.update(data)
                bytes_read += len(data)

                # Notificar solo si avanzamos al menos un 1% para no saturar
                if total_size:
                    pct = bytes_read / total_size
                    if pct - last_pct_reported >= 0.01 or pct >= 1.0:
                        last_pct_reported = pct
                        _notify("MD5", "calculating", progress=pct)
                        _notify("SHA-1", "calculating", progress=pct)
                        _notify("SHA-256", "calculating", progress=pct)

        resultado["MD5"] = md5.hexdigest()
        resultado["SHA-1"] = sha1.hexdigest()
        resultado["SHA-256"] = sha256.hexdigest()
        _notify("MD5", "done", value=resultado["MD5"], progress=1.0)
        _notify("SHA-1", "done", value=resultado["SHA-1"], progress=1.0)
        _notify("SHA-256", "done", value=resultado["SHA-256"], progress=1.0)
    except Exception as e:
        resultado["fuente"] = f"Error: {e}"
        for algo in ("MD5", "SHA-1", "SHA-256"):
            if resultado[algo] is None:
                _notify(algo, "error")

    return resultado


def _hash_ewf_sha256(ruta_imagen, log_callback=None):
    """Calcula SHA-256 leyendo el contenido descomprimido del E01."""
    filenames = pyewf.glob(ruta_imagen)
    handle = pyewf.handle()
    handle.open(filenames)
    total = handle.get_media_size()
    sha256 = hashlib.sha256()

    bytes_read = 0
    chunk = 64 * 1024 * 1024
    last_pct_reported = 0.0
    handle.seek(0)
    while bytes_read < total:
        data = handle.read(min(chunk, total - bytes_read))
        if not data:
            break
        sha256.update(data)
        bytes_read += len(data)
        if log_callback and total:
            pct = bytes_read / total
            if pct - last_pct_reported >= 0.01 or pct >= 1.0:
                last_pct_reported = pct
                log_callback(pct)
    handle.close()
    return sha256.hexdigest()


# --- Información de particiones  ---
_FS_TYPES = {
    pytsk3.TSK_FS_TYPE_NTFS: "NTFS",
    pytsk3.TSK_FS_TYPE_FAT12: "FAT12",
    pytsk3.TSK_FS_TYPE_FAT16: "FAT16",
    pytsk3.TSK_FS_TYPE_FAT32: "FAT32",
    pytsk3.TSK_FS_TYPE_EXFAT: "exFAT",
    pytsk3.TSK_FS_TYPE_EXT2: "EXT2",
    pytsk3.TSK_FS_TYPE_EXT3: "EXT3",
    pytsk3.TSK_FS_TYPE_EXT4: "EXT4",
    pytsk3.TSK_FS_TYPE_HFS:  "HFS+",
    pytsk3.TSK_FS_TYPE_ISO9660: "ISO9660",
}


def _detectar_fs(img_info, offset_bytes):
    """Devuelve el nombre del sistema de archivos de una partición."""
    try:
        fs = pytsk3.FS_Info(img_info, offset=offset_bytes)
        fs_type = fs.info.ftype
        return _FS_TYPES.get(fs_type, f"Tipo {fs_type}")
    except Exception as e:
        log.debug("Sin FS reconocible en offset %s: %s", offset_bytes, e)
        return "Sin sistema de archivos"


def extraer_particiones(img_info):
    """
    Devuelve lista de particiones de la imagen con su tamaño y FS.
    """
    particiones = []
    try:
        volume = pytsk3.Volume_Info(img_info)
        for i, part in enumerate(volume, 1):
            try:
                desc = part.desc
                if isinstance(desc, bytes):
                    desc = desc.decode("utf-8", errors="ignore")

                if part.len < 10:
                    continue

                offset_bytes = part.start * 512
                fs_type = _detectar_fs(img_info, offset_bytes)
                tam_bytes = part.len * 512

                particiones.append({
                    "Nº": i,
                    "Descripción": desc,
                    "Sector Inicio": part.start,
                    "Total Sectores": part.len,
                    "Tamaño": _fmt_size(tam_bytes),
                    "Tamaño (bytes)": tam_bytes,
                    "Sistema Archivos": fs_type,
                })
            except Exception as e:
                log.debug("Partición ilegible: %s", e)
                continue
    except Exception as e:
        log.debug("Sin tabla de particiones, intentando FS único: %s", e)
        try:
            fs = pytsk3.FS_Info(img_info, offset=0)
            fs_type = _FS_TYPES.get(fs.info.ftype, "Desconocido")
            size = img_info.get_size()
            particiones.append({
                "Nº": 1,
                "Descripción": "Partición única (sin tabla MBR/GPT)",
                "Sector Inicio": 0,
                "Total Sectores": size // 512,
                "Tamaño": _fmt_size(size),
                "Tamaño (bytes)": size,
                "Sistema Archivos": fs_type,
            })
        except Exception as e:
            log.warning("No se pudo determinar la estructura de particiones: %s", e)

    return particiones


def _fmt_size(size_bytes):
    if not size_bytes:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"
