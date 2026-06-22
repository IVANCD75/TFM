"""Estado de seguridad: Defender, Firewall, BitLocker, Eventos críticos."""
import os
import tempfile
import xml.etree.ElementTree as ET

from utils import get_registry_value, get_logger

LOGON_TYPES = {
    "2": "Interactivo",
    "3": "Red",
    "7": "Desbloqueo",
    "10": "Remoto Interactivo (RDP)",
    "11": "Interactivo en caché",
}

log = get_logger()

# --- Defender / AV  ---
def _extraer_defender(reg_software):
    """Estado de Windows Defender y detección de AV de terceros."""
    result = {
        "rt_monitoring": True,
        "tamper_protection": None,
        "product": "Windows Defender",
        "third_party_av": [],
    }
    if not reg_software:
        return result

    try:
        key = reg_software.open("Microsoft\\Windows Defender\\Real-Time Protection")
        disabled = get_registry_value(key, "DisableRealtimeMonitoring")
        result["rt_monitoring"] = not bool(disabled)
    except Exception as e:
        log.debug("Defender Real-Time Protection no disponible: %s", e)

    try:
        key = reg_software.open("Microsoft\\Windows Defender\\Features")
        result["tamper_protection"] = bool(get_registry_value(key, "TamperProtection"))
    except Exception as e:
        log.debug("Defender TamperProtection no disponible: %s", e)

    # Detectar AV de terceros desde Uninstall
    av_keywords = (
        "antivirus", "kaspersky", "norton", "bitdefender", "avast", "avg",
        "eset", "malwarebytes", "mcafee", "trend micro", "sophos", "f-secure",
        "panda", "comodo", "webroot", "crowdstrike", "sentinelone",
    )
    for base in (
        "Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    ):
        try:
            key = reg_software.open(base)
            for sub in key.subkeys():
                try:
                    dn = (get_registry_value(sub, "DisplayName") or "").lower()
                    if any(kw in dn for kw in av_keywords):
                        full = get_registry_value(sub, "DisplayName")
                        if full not in result["third_party_av"]:
                            result["third_party_av"].append(full)
                except Exception as e:
                    log.debug("Entrada Uninstall (AV) ilegible: %s", e)
                    continue
        except Exception as e:
            log.debug("Rama Uninstall '%s' ausente: %s", base, e)
            continue

    return result

# --- Firewall  ---
def _extraer_firewall(reg_system):
    """Estado del firewall en sus 3 perfiles."""
    result = {"domain": None, "private": None, "public": None}
    if not reg_system:
        return result

    profiles = {
        "domain": "DomainProfile",
        "private": "StandardProfile",
        "public": "PublicProfile",
    }
    for key_name, reg_path in profiles.items():
        try:
            key = reg_system.open(
                f"ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\{reg_path}"
            )
            enabled = get_registry_value(key, "EnableFirewall")
            if enabled is not None:
                result[key_name] = bool(enabled)
        except Exception as e:
            log.debug("Perfil de firewall '%s' no disponible: %s", reg_path, e)

    return result


# --- BitLocker  ---
def _extraer_bitlocker(reg_software, reg_system):
    """Detección best-effort del estado de BitLocker."""
    volumes = []

    if reg_software:
        try:
            key = reg_software.open("Microsoft\\Windows\\CurrentVersion\\BitLockerStatus")
            for vol in key.subkeys():
                volumes.append({
                    "Volumen": vol.name(),
                    "Estado": "Protegido" if get_registry_value(vol, "ProtectionStatus") else "No protegido",
                })
        except Exception as e:
            log.debug("BitLockerStatus no disponible: %s", e)

    # Política GPO de FVE
    if reg_software and not volumes:
        try:
            key = reg_software.open("Policies\\Microsoft\\FVE")
            volumes.append({
                "Volumen": "Política GPO",
                "Estado": "FVE configurado (revisar manualmente)",
            })
        except Exception as e:
            log.debug("Política FVE no disponible: %s", e)

    if reg_system and not volumes:
        try:
            key = reg_system.open("ControlSet001\\Services\\BDESVC")
            start = get_registry_value(key, "Start")
            if start is not None and start in (2, 3):
                volumes.append({
                    "Volumen": "Servicio BDE",
                    "Estado": f"Servicio configurado (Start={start})",
                })
        except Exception as e:
            log.debug("Servicio BDESVC no disponible: %s", e)

    return volumes


# --- Event Log  ---
def _volcar_evtx_a_tmp(fs, evtx_path, max_size):
    """Vuelca el Security.evtx a un tempfile escribiendo en streaming.

    Escribe cada bloque leído directamente al fichero temporal, sin acumular
    toda la imagen del log (hasta cientos de MB) en memoria.
    """
    f = fs.open(evtx_path)
    size = min(f.info.meta.size, max_size)

    tmp = tempfile.NamedTemporaryFile(prefix="tfm_evtx_", suffix=".evtx", delete=False)
    try:
        offset = 0
        chunk = 8 * 1024 * 1024
        while offset < size:
            block = f.read_random(offset, min(chunk, size - offset))
            if not block:
                break
            tmp.write(block)
            offset += len(block)
    finally:
        tmp.close()
    return tmp.name


def _extraer_eventos(fs):
    """Lee eventos críticos 4624 / 4625 / 1102 del Security.evtx."""
    result = {
        "logon_success": [],
        "logon_failed": [],
        "audit_cleared": [],
        "error": None,
        "total_revisados": 0,
    }

    try:
        import Evtx.Evtx as evtx_lib
    except ImportError:
        result["error"] = "python-evtx no instalado (pip install python-evtx)"
        log.warning(result["error"])
        return result

    evtx_path = "/Windows/System32/winevt/Logs/Security.evtx"
    tmp_path = None

    try:
        tmp_path = _volcar_evtx_a_tmp(fs, evtx_path, max_size=200 * 1024 * 1024)

        target_ids = {4624, 4625, 1102}
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

        with evtx_lib.Evtx(tmp_path) as log_evtx:
            for record in log_evtx.records():
                try:
                    root = ET.fromstring(record.xml())
                    result["total_revisados"] += 1

                    eid_el = root.find(".//e:EventID", ns)
                    if eid_el is None or not eid_el.text:
                        continue
                    eid = int(eid_el.text)
                    if eid not in target_ids:
                        continue

                    time_el = root.find(".//e:TimeCreated", ns)
                    ts = time_el.get("SystemTime", "") if time_el is not None else ""
                    ts_clean = ts[:19].replace("T", " ") if ts else ""

                    event_data = {}
                    for d in root.findall(".//e:Data", ns):
                        n = d.get("Name", "")
                        if n and d.text:
                            event_data[n] = d.text

                    entry = {
                        "Fecha": ts_clean,
                        "Usuario": event_data.get("TargetUserName", event_data.get("SubjectUserName", "")),
                        "Dominio": event_data.get("TargetDomainName", ""),
                        "IP Origen": event_data.get("IpAddress", ""),
                        "Tipo Logon": event_data.get("LogonType", ""),
                        "Estado": event_data.get("Status", event_data.get("SubStatus", "")),
                    }

                    if eid == 4624:
                        # Filtrar logons relevantes (interactivos, remotos y de red)
                        if entry["Tipo Logon"] in LOGON_TYPES:
                            entry["Tipo Logon"] = (
                                f'{entry["Tipo Logon"]} - {LOGON_TYPES[entry["Tipo Logon"]]}'
                            )
                            result["logon_success"].append(entry)
                    elif eid == 4625:
                        result["logon_failed"].append(entry)
                    elif eid == 1102:
                        result["audit_cleared"].append({"Fecha": ts_clean, "Usuario": entry["Usuario"]})
                except Exception as e:
                    log.debug("Registro evtx ilegible: %s", e)
                    continue

        # Limitar resultados
        result["logon_success"] = result["logon_success"][-100:]
        result["logon_failed"] = result["logon_failed"][-200:]

    except Exception as e:
        if not result["error"]:
            result["error"] = f"Error leyendo Security.evtx: {e}"
        log.warning("Error procesando Security.evtx: %s", e)
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError as e:
                log.warning("No se pudo borrar el tempfile evtx '%s': %s", tmp_path, e)

    return result


def extraer_seguridad(fs, reg_system, reg_software):
    """Devuelve toda la información de seguridad."""
    return {
        "defender": _extraer_defender(reg_software),
        "firewall": _extraer_firewall(reg_system),
        "bitlocker": _extraer_bitlocker(reg_software, reg_system),
        "eventos": _extraer_eventos(fs),
    }
