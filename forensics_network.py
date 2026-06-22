"""Extracción de actividad de red: perfiles e interfaces."""
import struct
from datetime import datetime

from utils import get_registry_value, get_logger

log = get_logger()


def _systemtime_to_dt(data):
    """Convierte SYSTEMTIME (16 bytes) a datetime."""
    if not data or len(data) < 16:
        return None
    try:
        year, month, dow, day, hour, minute, second, ms = struct.unpack_from("<8H", bytes(data), 0)
        if year < 1980 or year > 2200:
            return None
        return datetime(year, month, day, hour, minute, second, ms * 1000)
    except (struct.error, ValueError) as e:
        log.debug("SYSTEMTIME no parseable: %s", e)
        return None


_NAME_TYPES = {
    6: "Wi-Fi",
    23: "VPN",
    71: "Wi-Fi",
    243: "Móvil",
    1: "Cableada",
    0: "Desconocida",
}


def _extraer_perfiles_red(reg_software):
    """Extrae perfiles de NetworkList\\Profiles."""
    profiles = []
    if not reg_software:
        return profiles

    try:
        root = reg_software.open(
            "Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles"
        )
        for profile in root.subkeys():
            try:
                name = get_registry_value(profile, "ProfileName") or "Desconocido"
                name_type = get_registry_value(profile, "NameType") or 0
                net_type = _NAME_TYPES.get(name_type, f"Tipo {name_type}")

                created = _systemtime_to_dt(get_registry_value(profile, "DateCreated"))
                last_conn = _systemtime_to_dt(get_registry_value(profile, "DateLastConnected"))

                profiles.append({
                    "Nombre (SSID)": name,
                    "Tipo": net_type,
                    "Creada": created,
                    "Última Conexión": last_conn,
                    "Categoría": _categoria(get_registry_value(profile, "Category")),
                })
            except Exception as e:
                log.debug("Perfil de red ilegible: %s", e)
                continue
    except Exception as e:
        log.debug("NetworkList\\Profiles ausente: %s", e)

    return sorted(profiles, key=lambda x: x["Última Conexión"] or datetime.min, reverse=True)


def _categoria(cat):
    return {0: "Pública", 1: "Privada", 2: "Dominio"}.get(cat, "")


def _extraer_interfaces_red(reg_system):
    """Extrae configuración IP de cada interfaz de red."""
    interfaces = []
    if not reg_system:
        return interfaces

    try:
        ifaces = reg_system.open(
            "ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces"
        )
        for iface in ifaces.subkeys():
            try:
                dhcp = bool(get_registry_value(iface, "EnableDHCP"))

                if dhcp:
                    ip = get_registry_value(iface, "DhcpIPAddress") or ""
                    subnet = get_registry_value(iface, "DhcpSubnetMask") or ""
                    gateway = get_registry_value(iface, "DhcpDefaultGateway") or ""
                    dns = get_registry_value(iface, "DhcpNameServer") or ""
                    server = get_registry_value(iface, "DhcpServer") or ""
                else:
                    ip_list = get_registry_value(iface, "IPAddress") or []
                    ip = ip_list[0] if isinstance(ip_list, list) and ip_list else (ip_list or "")
                    subnet_list = get_registry_value(iface, "SubnetMask") or []
                    subnet = subnet_list[0] if isinstance(subnet_list, list) and subnet_list else ""
                    gw_list = get_registry_value(iface, "DefaultGateway") or []
                    gateway = gw_list[0] if isinstance(gw_list, list) and gw_list else ""
                    dns = get_registry_value(iface, "NameServer") or ""
                    server = ""

                if isinstance(gateway, list):
                    gateway = gateway[0] if gateway else ""

                if not ip or ip == "0.0.0.0":
                    continue

                interfaces.append({
                    "Interfaz (GUID)": iface.name(),
                    "Modo": "DHCP" if dhcp else "Estática",
                    "IP": str(ip),
                    "Máscara": str(subnet),
                    "Gateway": str(gateway),
                    "DNS": str(dns),
                    "Servidor DHCP": str(server),
                })
            except Exception as e:
                log.debug("Interfaz de red ilegible: %s", e)
                continue
    except Exception as e:
        log.debug("Tcpip\\Parameters\\Interfaces ausente: %s", e)

    return interfaces


def extraer_red(reg_system, reg_software):
    """Extrae perfiles de red e interfaces."""
    return {
        "profiles": _extraer_perfiles_red(reg_software),
        "interfaces": _extraer_interfaces_red(reg_system),
    }
