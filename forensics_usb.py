"""Extracción del historial de dispositivos USB conectados al equipo."""
import re
from datetime import datetime

from utils import get_registry_value, get_logger

log = get_logger()


def _parse_setupapi(fs):
    """Parsea setupapi.dev.log para obtener la primera fecha de conexión por serial."""
    first_seen = {}
    for path in ("/Windows/INF/setupapi.dev.log", "/Windows/setupapi.dev.log"):
        try:
            f = fs.open(path)
            raw = f.read_random(0, min(f.info.meta.size, 15 * 1024 * 1024))
            try:
                content = raw.decode("utf-16-le", errors="ignore")
                if "USBSTOR" not in content:
                    content = raw.decode("utf-8", errors="ignore")
            except Exception as e:
                log.debug("Fallo decodificando %s: %s", path, e)
                content = raw.decode("utf-8", errors="ignore")

            current_serial = None
            for line in content.splitlines():
                if "USBSTOR" in line:
                    m = re.search(r"USBSTOR\\[^\\]+\\([^&\]\\]+)", line)
                    if m:
                        current_serial = m.group(1)
                elif current_serial and "Section start" in line:
                    m = re.search(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})", line)
                    if m:
                        try:
                            ts = datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S")
                            first_seen.setdefault(current_serial, ts)
                        except ValueError as e:
                            log.debug("Fecha setupapi no parseable '%s': %s", m.group(1), e)
                    current_serial = None
            break
        except Exception as e:
            log.debug("No se pudo leer setupapi en %s: %s", path, e)
            continue
    return first_seen


def extraer_usb(fs, reg_system, reg_software):
    """Extrae el historial completo de dispositivos USB."""
    devices = []
    if not reg_system:
        log.info("Sin hive SYSTEM: no se puede extraer historial USB.")
        return devices

    first_seen = _parse_setupapi(fs)

    # Nombres amigables desde Portable Devices
    friendly_extra = {}
    if reg_software:
        try:
            wpd = reg_software.open("Microsoft\\Windows Portable Devices\\Devices")
            for dev in wpd.subkeys():
                fname = get_registry_value(dev, "FriendlyName") or ""
                if fname:
                    # La key contiene el serial al final
                    key_name = dev.name().upper()
                    parts = key_name.split("#")
                    if parts:
                        friendly_extra[parts[-1].split("&")[0]] = fname
        except Exception as e:
            log.debug("No se pudieron leer Portable Devices: %s", e)

    try:
        usbstor = reg_system.open("ControlSet001\\Enum\\USBSTOR")
        for device_type in usbstor.subkeys():
            parts = device_type.name().split("&")
            vendor = next((p[4:] for p in parts if p.startswith("Ven_")), "Desconocido")
            product = next((p[5:] for p in parts if p.startswith("Prod_")), "Desconocido")
            vendor = vendor.replace("_", " ").strip()
            product = product.replace("_", " ").strip()

            for serial_key in device_type.subkeys():
                serial = serial_key.name().split("&")[0]
                friendly = (
                    get_registry_value(serial_key, "FriendlyName")
                    or friendly_extra.get(serial.upper())
                    or f"{vendor} {product}".strip()
                )
                last_conn = serial_key.timestamp()
                first_conn = first_seen.get(serial, device_type.timestamp())

                devices.append({
                    "Fabricante": vendor or "Desconocido",
                    "Modelo": product or "Desconocido",
                    "Nombre": friendly,
                    "Nº Serie": serial,
                    "Primera Conexión": first_conn,
                    "Última Conexión": last_conn,
                })
    except Exception as e:
        log.warning("Error extrayendo USBSTOR del registro SYSTEM: %s", e)

    # Protección frente a timestamps None: evita TypeError al comparar
    # datetime con NoneType durante la ordenación.
    return sorted(devices, key=lambda x: x["Última Conexión"] or datetime.min, reverse=True)
