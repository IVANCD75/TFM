"""Línea temporal de actividad: Prefetch, UserAssist y Amcache."""
import codecs
import os
import struct
from datetime import datetime, timezone

from utils import filetime_to_dt, get_registry_hive, get_registry_value, get_logger

log = get_logger()


def _extraer_prefetch(fs):
    """Lista archivos prefetch con su última ejecución (filesystem mtime)."""
    entries = []
    try:
        prefetch_dir = fs.open_dir("/Windows/Prefetch")
        for entry in prefetch_dir:
            try:
                name = entry.info.name.name
                if isinstance(name, bytes):
                    name = name.decode("utf-8", errors="ignore")
                if not name.upper().endswith(".PF") or name.startswith("."):
                    continue

                # APPNAME-HASH.pf → APPNAME
                exe_name = name.rsplit("-", 1)[0] if "-" in name else name[:-3]

                last_run = None
                if entry.info.meta and entry.info.meta.mtime:
                    try:
                        last_run = datetime.fromtimestamp(
                            entry.info.meta.mtime, tz=timezone.utc
                        ).replace(tzinfo=None)
                    except (ValueError, OverflowError, OSError) as e:
                        log.debug("mtime Prefetch inválido en %s: %s", name, e)

                entries.append({
                    "Ejecutable": exe_name,
                    "Última Ejecución": last_run,
                    "Archivo Prefetch": name,
                })
            except Exception as e:
                log.debug("Entrada Prefetch ilegible: %s", e)
                continue
    except Exception as e:
        log.info("No se pudo listar /Windows/Prefetch: %s", e)

    return sorted(entries, key=lambda x: x["Última Ejecución"] or datetime.min, reverse=True)


def _extraer_userassist(user_hives):
    """Extrae las entradas UserAssist de cada NTUSER.DAT."""
    GUIDS = (
        "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}",  # Ejecutables
        "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}",  # Enlaces (.lnk)
    )
    entries = []

    for username, hive in user_hives.items():
        for guid in GUIDS:
            try:
                key = hive.open(
                    f"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{guid}\\Count"
                )
                for val in key.values():
                    try:
                        encoded = val.name()
                        decoded = codecs.encode(encoded, "rot_13")

                        data = val.value()
                        if not isinstance(data, bytes) or len(data) < 68:
                            continue

                        run_count = struct.unpack_from("<I", data, 4)[0]
                        if run_count == 0 or run_count > 100000:
                            continue

                        ft = struct.unpack_from("<Q", data, 60)[0]
                        last_run = filetime_to_dt(ft)

                        exe = os.path.basename(decoded.replace("\\", "/"))
                        if not exe or exe.startswith("UEME_"):
                            continue

                        entries.append({
                            "Usuario": username,
                            "Aplicación": exe,
                            "Ruta": decoded,
                            "Veces Ejecutado": run_count,
                            "Última Ejecución": last_run,
                        })
                    except Exception as e:
                        log.debug("Valor UserAssist ilegible (%s): %s", username, e)
                        continue
            except Exception as e:
                log.debug("UserAssist ausente para %s/%s: %s", username, guid, e)
                continue

    return sorted(entries, key=lambda x: x["Última Ejecución"] or datetime.min, reverse=True)


def _extraer_amcache(fs):
    """Extrae programas ejecutados desde Amcache.hve."""
    entries = []
    hive = get_registry_hive(fs, "/Windows/AppCompat/Programs/Amcache.hve")
    if not hive:
        return entries

    # Win10+: Root\InventoryApplicationFile
    try:
        root = hive.open("Root\\InventoryApplicationFile")
        for app in root.subkeys():
            try:
                name = get_registry_value(app, "Name") or ""
                path = (
                    get_registry_value(app, "LowerCaseLongPath")
                    or get_registry_value(app, "PathHint")
                    or ""
                )
                publisher = get_registry_value(app, "Publisher") or ""
                size = get_registry_value(app, "Size") or 0
                if name:
                    entries.append({
                        "Programa": name,
                        "Editor": publisher,
                        "Ruta": path,
                        "Tamaño (bytes)": size if isinstance(size, int) else 0,
                        "Modificado": app.timestamp(),
                    })
            except Exception as e:
                log.debug("Entrada Amcache (Win10+) ilegible: %s", e)
                continue
    except Exception as e:
        log.debug("Amcache InventoryApplicationFile ausente: %s", e)

    # Win7/8: Root\File\<VolumeGUID>\<FileID>
    if not entries:
        try:
            file_root = hive.open("Root\\File")
            for vol in file_root.subkeys():
                for ent in vol.subkeys():
                    try:
                        name = (
                            get_registry_value(ent, "OriginalFileName")
                            or get_registry_value(ent, "FileDescription")
                            or ""
                        )
                        publisher = get_registry_value(ent, "Publisher") or ""
                        if name:
                            entries.append({
                                "Programa": name,
                                "Editor": publisher,
                                "Ruta": "",
                                "Tamaño (bytes)": 0,
                                "Modificado": ent.timestamp(),
                            })
                    except Exception as e:
                        log.debug("Entrada Amcache (Win7/8) ilegible: %s", e)
                        continue
        except Exception as e:
            log.debug("Amcache Root\\File ausente: %s", e)

    return sorted(entries, key=lambda x: x["Modificado"] or datetime.min, reverse=True)


def extraer_actividad(fs, user_hives):
    """Extrae toda la actividad de ejecución del equipo."""
    return {
        "prefetch": _extraer_prefetch(fs),
        "userassist": _extraer_userassist(user_hives),
        "amcache": _extraer_amcache(fs),
    }
