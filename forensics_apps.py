"""Aplicaciones instaladas y detección de herramientas anti-forenses."""
from utils import get_registry_value, get_logger

log = get_logger()


# Lista de palabras clave indicadoras de herramientas anti-forenses.
ANTI_FORENSIC_KEYWORDS = (
    "ccleaner", "eraser", "bleachbit", "bcwipe", "darik", "dban",
    "secure erase", "fileshredder", "shred", "wipe", "privazer",
    "anti-forensic", "antiforensic", "ccenhancer", "wisecare",
    "tor browser", "vpn", "ghostery", "freedom of the press",
    "veracrypt", "truecrypt", "axcrypt", "cryptomator",
    "ccleaner browser",
)


def _safe_extract(sub, value_name):
    """Lee un valor con string clean-up básico."""
    v = get_registry_value(sub, value_name)
    if v is None:
        return ""
    if isinstance(v, bytes):
        try:
            v = v.decode("utf-16-le", errors="ignore").rstrip("\x00")
        except Exception as e:
            log.debug("Fallo decodificando valor '%s': %s", value_name, e)
            v = v.decode("utf-8", errors="ignore")
    return str(v).strip()


def _parse_install_date(raw):
    """Convierte fechas de instalación con formato 'YYYYMMDD' o ISO."""
    if not raw:
        return ""
    s = str(raw).strip()
    if len(s) == 8 and s.isdigit():
        return f"{s[:4]}-{s[4:6]}-{s[6:8]}"
    return s


def extraer_apps_instaladas(reg_software, user_hives):
    """
    Lee aplicaciones instaladas desde:
      - SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall
      - SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall (32-bit)
      - NTUSER\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall (por usuario)

    Devuelve también una lista con las apps identificadas como anti-forenses.
    """
    apps = []
    vistos = set()

    fuentes = []
    if reg_software:
        fuentes.append((reg_software,
                        "Microsoft\\Windows\\CurrentVersion\\Uninstall",
                        "Máquina (64-bit)"))
        fuentes.append((reg_software,
                        "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                        "Máquina (32-bit)"))

    for username, hive in user_hives.items():
        fuentes.append((hive,
                        "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                        f"Usuario: {username}"))

    for hive, path, label in fuentes:
        try:
            uninstall = hive.open(path)
            for sub in uninstall.subkeys():
                try:
                    display_name = _safe_extract(sub, "DisplayName")
                    if not display_name or display_name in vistos:
                        continue

                    # Filtrar componentes/updates de Windows
                    if (_safe_extract(sub, "SystemComponent") == "1" or
                            _safe_extract(sub, "ParentKeyName") or
                            display_name.startswith("KB") or
                            "Update for" in display_name):
                        continue

                    vistos.add(display_name)

                    apps.append({
                        "Nombre": display_name,
                        "Versión": _safe_extract(sub, "DisplayVersion"),
                        "Editor": _safe_extract(sub, "Publisher"),
                        "Fecha Instalación": _parse_install_date(
                            _safe_extract(sub, "InstallDate")
                        ),
                        "Ruta": _safe_extract(sub, "InstallLocation"),
                        "Origen": label,
                    })
                except Exception as e:
                    log.debug("Subclave Uninstall ilegible en '%s': %s", label, e)
                    continue
        except Exception as e:
            log.debug("Rama Uninstall ausente '%s' (%s): %s", path, label, e)
            continue

    # Detección de anti-forensics
    anti_forensic = []
    for app in apps:
        nombre_lower = app["Nombre"].lower()
        for kw in ANTI_FORENSIC_KEYWORDS:
            if kw in nombre_lower:
                anti_forensic.append({
                    **app,
                    "Indicador": kw,
                })
                break

    apps.sort(key=lambda x: x["Nombre"].lower())

    return {
        "instaladas": apps,
        "anti_forensic": anti_forensic,
    }
