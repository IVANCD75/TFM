"""Análisis de persistencia: Run/RunOnce y Tareas Programadas."""
import xml.etree.ElementTree as ET

import pytsk3

from forensics_apps import ANTI_FORENSIC_KEYWORDS
from utils import get_logger

log = get_logger()


_SUSPICIOUS_PATHS = ("\\temp\\", "\\tmp\\", "appdata\\local\\temp", "\\downloads\\", "\\public\\", "%temp%")
_SUSPICIOUS_EXTS = (".vbs", ".ps1", ".bat", ".cmd", ".js", ".jse", ".wsf", ".hta")


def _es_sospechoso(value):
    """Heurística para marcar comandos sospechosos.

    Marca como sospechoso si:
      - El comando apunta a una ruta sensible (temp, downloads, etc.).
      - Acaba en una extensión de scripting típica de malware.
      - Contiene el nombre de una herramienta anti-forense conocida.
    """
    if not value:
        return False
    v = str(value).lower()
    if any(p in v for p in _SUSPICIOUS_PATHS):
        return True
    if any(v.rstrip('"').endswith(ext) for ext in _SUSPICIOUS_EXTS):
        return True
    if any(kw in v for kw in ANTI_FORENSIC_KEYWORDS):
        return True
    return False


def _extraer_run_keys(reg_software, user_hives):
    """Lee Run y RunOnce de SOFTWARE y de cada NTUSER.DAT."""
    entries = []

    if reg_software:
        for sub in ("Run", "RunOnce", "RunServices", "RunServicesOnce"):
            try:
                key = reg_software.open(f"Microsoft\\Windows\\CurrentVersion\\{sub}")
                for val in key.values():
                    try:
                        value = val.value()
                        entries.append({
                            "Origen": f"SOFTWARE\\{sub}",
                            "Usuario": "(Máquina)",
                            "Nombre": val.name(),
                            "Comando": str(value),
                            "Sospechoso": _es_sospechoso(value),
                        })
                    except Exception as e:
                        log.debug("Valor Run de máquina ilegible: %s", e)
                        continue
            except Exception as e:
                log.debug("Clave Run de máquina ausente '%s': %s", sub, e)
                continue

    for username, hive in user_hives.items():
        for sub in ("Run", "RunOnce"):
            try:
                key = hive.open(f"Software\\Microsoft\\Windows\\CurrentVersion\\{sub}")
                for val in key.values():
                    try:
                        value = val.value()
                        entries.append({
                            "Origen": f"NTUSER\\{sub}",
                            "Usuario": username,
                            "Nombre": val.name(),
                            "Comando": str(value),
                            "Sospechoso": _es_sospechoso(value),
                        })
                    except Exception as e:
                        log.debug("Valor Run de usuario %s ilegible: %s", username, e)
                        continue
            except Exception as e:
                log.debug("Clave Run de usuario %s ausente '%s': %s", username, sub, e)
                continue

    return entries


def _decodificar_task_xml(content):
    """Detecta encoding y devuelve el texto XML."""
    if content.startswith(b"\xff\xfe"):
        return content[2:].decode("utf-16-le", errors="ignore")
    if content.startswith(b"<"):
        return content.decode("utf-8", errors="ignore")
    try:
        s = content.decode("utf-16-le", errors="ignore").lstrip("\ufeff")
        if s.lstrip().startswith("<"):
            return s
    except (UnicodeDecodeError, AttributeError) as e:
        log.debug("Decodificación XML de tarea fallida: %s", e)
    return content.decode("utf-8", errors="ignore")


def _parse_task(fs, full_path, name, subpath):
    """Parsea un archivo XML de tarea programada."""
    try:
        f = fs.open(full_path)
        content = f.read_random(0, f.info.meta.size)
        xml_str = _decodificar_task_xml(content).strip()
        if not xml_str.startswith("<"):
            return None

        # Eliminar el namespace para simplificar el parseo
        xml_str = xml_str.replace(
            'xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"', ""
        )
        root = ET.fromstring(xml_str)

        author = ""
        created = ""
        reg_info = root.find("RegistrationInfo")
        if reg_info is not None:
            a = reg_info.find("Author")
            d = reg_info.find("Date")
            author = a.text if a is not None and a.text else ""
            created = d.text if d is not None and d.text else ""

        action_str = ""
        actions = root.find("Actions")
        if actions is not None:
            exec_el = actions.find("Exec")
            if exec_el is not None:
                cmd = exec_el.find("Command")
                args = exec_el.find("Arguments")
                cmd_s = cmd.text if cmd is not None and cmd.text else ""
                args_s = args.text if args is not None and args.text else ""
                action_str = f"{cmd_s} {args_s}".strip()

        trigger_str = ""
        triggers = root.find("Triggers")
        if triggers is not None:
            for child in triggers:
                trigger_str = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                break

        is_microsoft = "microsoft" in subpath.lower() or "microsoft" in author.lower()
        suspicious = (not is_microsoft) and _es_sospechoso(action_str)

        return {
            "Nombre": name,
            "Ruta": subpath or "/",
            "Autor": author,
            "Creada": created.replace("T", " ")[:19] if created else "",
            "Acción": action_str,
            "Disparador": trigger_str,
            "Sospechoso": suspicious,
        }
    except Exception as e:
        log.debug("Tarea programada '%s' no parseable: %s", name, e)
        return None


def _extraer_tareas_programadas(fs):
    """Recorre recursivamente /Windows/System32/Tasks."""
    tasks = []

    def walk(dir_path, subpath=""):
        try:
            d = fs.open_dir(dir_path)
            for entry in d:
                try:
                    name = entry.info.name.name
                    if isinstance(name, bytes):
                        name = name.decode("utf-8", errors="ignore")
                    if name in (".", ".."):
                        continue
                    full = f"{dir_path}/{name}"

                    if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                        walk(full, f"{subpath}/{name}".lstrip("/"))
                    else:
                        task = _parse_task(fs, full, name, subpath)
                        if task:
                            tasks.append(task)
                except Exception as e:
                    log.debug("Entrada de Tasks ilegible: %s", e)
                    continue
        except Exception as e:
            log.debug("No se pudo recorrer '%s': %s", dir_path, e)

    walk("/Windows/System32/Tasks")
    return tasks


def extraer_persistencia(fs, reg_software, user_hives):
    """Extrae todas las fuentes de persistencia conocidas."""
    return {
        "run_keys": _extraer_run_keys(reg_software, user_hives),
        "scheduled_tasks": _extraer_tareas_programadas(fs),
    }
