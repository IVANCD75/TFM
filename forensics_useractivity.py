"""Actividad del usuario: documentos recientes, papelera, navegador, drives de red."""
import struct
from datetime import datetime

from utils import filetime_to_dt, get_registry_value, get_logger

log = get_logger()


_BROWSER_MAP = {
    "chromehtml":   "Google Chrome",
    "firefoxurl":   "Mozilla Firefox",
    "msedgehtm":    "Microsoft Edge",
    "ie.http":      "Internet Explorer",
    "operastable":  "Opera",
    "bravehtml":    "Brave",
    "safarihtml":   "Safari",
    "vivaldihtm":   "Vivaldi",
}


def _extraer_recent_docs(user_hives):
    """Cuenta documentos recientes agrupados por extensión, devolviendo
    tanto el agregado como el desglose por usuario.

    Returns:
        dict con:
          - "aggregated":  list[{Extensión, Cantidad}] sumado entre usuarios.
          - "by_user":     dict[username, list[{Extensión, Cantidad}]].
    """
    by_user_raw = {}   # {username: {ext: count}}

    for username, hive in user_hives.items():
        user_data = {}
        try:
            recent = hive.open(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"
            )
            for ext_key in recent.subkeys():
                ext = ext_key.name().lower()
                count = sum(1 for v in ext_key.values() if v.name() != "MRUListEx")
                if count > 0:
                    user_data[ext] = count
        except Exception as e:
            log.debug("RecentDocs ausente para %s: %s", username, e)
            continue
        if user_data:
            by_user_raw[username] = user_data

    # Lista agregada (suma entre todos los usuarios)
    agg = {}
    for ud in by_user_raw.values():
        for ext, c in ud.items():
            agg[ext] = agg.get(ext, 0) + c
    aggregated = sorted(
        [{"Extensión": k, "Cantidad": v} for k, v in agg.items()],
        key=lambda x: x["Cantidad"],
        reverse=True,
    )

    # Por usuario
    by_user = {
        u: sorted(
            [{"Extensión": k, "Cantidad": v} for k, v in d.items()],
            key=lambda x: x["Cantidad"],
            reverse=True,
        )
        for u, d in by_user_raw.items()
    }

    return {"aggregated": aggregated, "by_user": by_user}


def _parse_i_file(data):
    """Parsea un $I de papelera y devuelve (size, deleted_datetime, filename)."""
    if not data or len(data) < 24:
        return None, None, None
    try:
        version = struct.unpack_from("<q", data, 0)[0]
        file_size = struct.unpack_from("<q", data, 8)[0]
        deleted_ft = struct.unpack_from("<Q", data, 16)[0]
        deleted_dt = filetime_to_dt(deleted_ft)

        if version >= 2 and len(data) >= 28:
            name_len = struct.unpack_from("<i", data, 24)[0]
            raw_name = data[28:28 + name_len * 2]
        else:
            raw_name = data[24:24 + 520]

        fname = raw_name.decode("utf-16-le", errors="ignore").rstrip("\x00")
        return file_size, deleted_dt, fname
    except (struct.error, UnicodeDecodeError, ValueError) as e:
        log.debug("$I de papelera no parseable: %s", e)
        return None, None, None


def _extraer_recycle_bin(fs):
    """Lee todos los $I de /$Recycle.Bin/<SID>/."""
    files = []
    total_size = 0

    try:
        rb_root = fs.open_dir("/$Recycle.Bin")
        for sid_entry in rb_root:
            try:
                sid = sid_entry.info.name.name
                if isinstance(sid, bytes):
                    sid = sid.decode("utf-8", errors="ignore")
                if sid in (".", ".."):
                    continue

                user_path = f"/$Recycle.Bin/{sid}"
                try:
                    user_dir = fs.open_dir(user_path)
                except Exception as e:
                    log.debug("No se pudo abrir %s: %s", user_path, e)
                    continue

                for entry in user_dir:
                    try:
                        name = entry.info.name.name
                        if isinstance(name, bytes):
                            name = name.decode("utf-8", errors="ignore")
                        if not name.startswith("$I") or name in (".", ".."):
                            continue

                        f = fs.open(f"{user_path}/{name}")
                        data = f.read_random(0, min(f.info.meta.size, 2048))

                        size, deleted, fname = _parse_i_file(data)
                        if fname:
                            total_size += size or 0
                            files.append({
                                "Archivo Original": fname,
                                "Tamaño (bytes)": size or 0,
                                "Fecha Borrado": deleted,
                                "SID Usuario": sid,
                            })
                    except Exception as e:
                        log.debug("Archivo de papelera ilegible: %s", e)
                        continue
            except Exception as e:
                log.debug("SID de papelera ilegible: %s", e)
                continue
    except Exception as e:
        log.debug("No se pudo abrir /$Recycle.Bin: %s", e)

    files.sort(key=lambda x: x["Fecha Borrado"] or datetime.min, reverse=True)
    return {
        "files": files,
        "total_count": len(files),
        "total_size": total_size,
    }


def _extraer_navegador(user_hives):
    """Obtiene el navegador por defecto declarado por cada usuario."""
    browsers = {}
    for username, hive in user_hives.items():
        try:
            key = hive.open(
                "Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\http\\UserChoice"
            )
            prog_id = (get_registry_value(key, "ProgId") or "").lower()
            for slug, nice in _BROWSER_MAP.items():
                if slug in prog_id:
                    browsers[username] = nice
                    break
            else:
                browsers[username] = prog_id or "Desconocido"
        except Exception as e:
            log.debug("UserChoice de navegador ausente para %s: %s", username, e)
            browsers[username] = "Desconocido"
    return browsers


def _extraer_network_mru(user_hives):
    """Extrae drives de red mapeados desde Map Network Drive MRU + RunMRU."""
    drives_mapeados = []
    run_mru_red = []

    for username, hive in user_hives.items():
        # Map Network Drive MRU: rutas que se han mapeado vía explorador
        try:
            key = hive.open(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Map Network Drive MRU"
            )
            for val in key.values():
                if val.name() == "MRUList":
                    continue
                path = val.value()
                if isinstance(path, str) and path.strip():
                    drives_mapeados.append({
                        "Usuario": username,
                        "Ruta UNC": path,
                        "Última Modif.": key.timestamp(),
                    })
        except Exception as e:
            log.debug("Map Network Drive MRU ausente para %s: %s", username, e)

        # RunMRU: cosas tecleadas en la ventana Ejecutar (Win+R)
        try:
            key = hive.open(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU"
            )
            for val in key.values():
                if val.name() == "MRUList":
                    continue
                cmd = val.value()
                if isinstance(cmd, str):
                    # El \1 final marca el slot en el MRU
                    cmd_clean = cmd.split("\\1")[0].strip()
                    if cmd_clean:
                        es_red = cmd_clean.startswith("\\\\") or "://" in cmd_clean.lower()
                        run_mru_red.append({
                            "Usuario": username,
                            "Comando": cmd_clean,
                            "Es Ruta Red": es_red,
                            "Última Modif.": key.timestamp(),
                        })
        except Exception as e:
            log.debug("RunMRU ausente para %s: %s", username, e)

        # Network: drives de red persistentes (con letra asignada)
        try:
            net_key = hive.open("Network")
            for letter_key in net_key.subkeys():
                try:
                    remote = get_registry_value(letter_key, "RemotePath") or ""
                    user_attr = get_registry_value(letter_key, "UserName") or ""
                    provider = get_registry_value(letter_key, "ProviderName") or ""
                    drives_mapeados.append({
                        "Usuario": username,
                        "Letra": letter_key.name() + ":",
                        "Ruta UNC": remote,
                        "Usuario Conexión": user_attr,
                        "Proveedor": provider,
                        "Última Modif.": letter_key.timestamp(),
                    })
                except Exception as e:
                    log.debug("Drive de red persistente ilegible (%s): %s", username, e)
                    continue
        except Exception as e:
            log.debug("Clave Network ausente para %s: %s", username, e)

    return {
        "mapped": drives_mapeados,
        "run_mru": run_mru_red,
    }


def extraer_actividad_usuario(fs, user_hives):
    """Combina documentos recientes, papelera, navegador y drives de red."""
    rd = _extraer_recent_docs(user_hives)
    return {
        # Mantenemos `recent_docs` con el agregado para retrocompatibilidad
        # (lo consume el informe pericial), y añadimos `recent_docs_by_user`.
        "recent_docs": rd["aggregated"],
        "recent_docs_by_user": rd["by_user"],
        "recycle_bin": _extraer_recycle_bin(fs),
        "browsers": _extraer_navegador(user_hives),
        "network_mru": _extraer_network_mru(user_hives),
    }
