"""Orquestador principal del análisis forense."""
import time
import struct

import pyewf
import pytsk3

from utils import filetime_to_dt, get_registry_hive, get_registry_value, get_logger

log = get_logger()


class EvidenciaError(Exception):
    """Error recuperable durante el procesamiento de la evidencia.

    La capa de extracción es agnóstica a la UI: en lugar de pintar el error
    con Streamlit, lo comunica por excepción para que la capa de presentación
    decida cómo mostrarlo. Esto permite usar `procesar_evidencia` desde tests
    o desde una CLI sin arrastrar la dependencia de Streamlit.
    """
from forensics_hashes import extraer_particiones
from forensics_apps import extraer_apps_instaladas
from forensics_browser import extraer_navegacion
from forensics_usb import extraer_usb
from forensics_activity import extraer_actividad
from forensics_persistence import extraer_persistencia
from forensics_network import extraer_red
from forensics_useractivity import extraer_actividad_usuario
from forensics_security import extraer_seguridad


class EWFImgInfo(pytsk3.Img_Info):
    """Wrapper para leer imágenes en formato E01/EWF."""

    def __init__(self, ewf_handle):
        self._ewf_handle = ewf_handle
        super(EWFImgInfo, self).__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def read(self, offset, size):
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)

    def get_size(self):
        return self._ewf_handle.get_media_size()


def _abrir_imagen(ruta_imagen):
    """Abre la imagen forense según su formato."""
    ruta_lower = ruta_imagen.lower()
    if ruta_lower.endswith((".e01", ".ex01", ".l01")):
        filenames = pyewf.glob(ruta_imagen)
        ewf_handle = pyewf.handle()
        ewf_handle.open(filenames)
        return EWFImgInfo(ewf_handle)
    return pytsk3.Img_Info(ruta_imagen)


def _encontrar_fs_windows(img_info):
    """Localiza la partición de Windows."""
    try:
        volume = pytsk3.Volume_Info(img_info)
        for part in volume:
            if part.len < 1000:
                continue
            try:
                offset = part.start * 512
                temp_fs = pytsk3.FS_Info(img_info, offset=offset)
                try:
                    temp_fs.open_dir("/Windows")
                    return temp_fs
                except Exception as e:
                    log.debug("Partición sin /Windows en offset %s: %s", offset, e)
            except Exception as e:
                log.debug("Partición ilegible: %s", e)
    except IOError as e:
        log.debug("Sin tabla de volúmenes: %s", e)

    try:
        temp_fs = pytsk3.FS_Info(img_info, offset=0)
        temp_fs.open_dir("/Windows")
        return temp_fs
    except Exception as e:
        log.debug("No hay /Windows en offset 0: %s", e)

    return None


def _cargar_user_hives(fs):
    """Carga el NTUSER.DAT de cada usuario en /Users/."""
    hives = {}
    try:
        users_dir = fs.open_dir("/Users")
        for entry in users_dir:
            try:
                name = entry.info.name.name
                if isinstance(name, bytes):
                    name = name.decode("utf-8", errors="ignore")
                if name in (".", "..", "Public", "Default", "Default User",
                            "All Users", "desktop.ini"):
                    continue
                if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    hive = get_registry_hive(fs, f"/Users/{name}/NTUSER.DAT")
                    if hive:
                        hives[name] = hive
            except Exception as e:
                log.debug("Hive de usuario ilegible: %s", e)
                continue
    except Exception as e:
        log.debug("No se pudo abrir /Users: %s", e)
    return hives


def _extraer_software_hive(fs, data):
    reg = get_registry_hive(fs, "/Windows/System32/config/SOFTWARE")
    if not reg:
        return None
    try:
        key_nt = reg.open("Microsoft\\Windows NT\\CurrentVersion")
        data["os_name"] = get_registry_value(key_nt, "ProductName")
        data["owner"] = get_registry_value(key_nt, "RegisteredOwner")
        data["install_date_unix"] = get_registry_value(key_nt, "InstallDate")
        data["release"] = (
            get_registry_value(key_nt, "DisplayVersion")
            or get_registry_value(key_nt, "ReleaseId")
            or get_registry_value(key_nt, "CSDVersion")
            or "Desconocido"
        )
        data["build"] = (
            get_registry_value(key_nt, "CurrentBuild")
            or get_registry_value(key_nt, "CurrentBuildNumber")
            or ""
        )
    except Exception as e:
        log.debug("Lectura parcial de hive SOFTWARE: %s", e)
    return reg


def _extraer_system_hive(fs, data):
    reg = get_registry_hive(fs, "/Windows/System32/config/SYSTEM")
    if not reg:
        return None
    try:
        k = reg.open("ControlSet001\\Control\\ComputerName\\ComputerName")
        data["hostname"] = get_registry_value(k, "ComputerName")
    except Exception as e:
        log.debug("Hostname no disponible: %s", e)
        data["hostname"] = "Unknown"
    try:
        k = reg.open("ControlSet001\\Control\\TimeZoneInformation")
        data["timezone"] = get_registry_value(k, "TimeZoneKeyName")
    except Exception as e:
        log.debug("Zona horaria no disponible: %s", e)
        data["timezone"] = "Unknown"
    try:
        k = reg.open("ControlSet001\\Control\\Windows")
        shutdown_bytes = get_registry_value(k, "ShutdownTime")
        if shutdown_bytes:
            ts_int = struct.unpack("<Q", bytes(shutdown_bytes))[0]
            data["last_shutdown"] = filetime_to_dt(ts_int)
    except Exception as e:
        log.debug("ShutdownTime no disponible: %s", e)
        data["last_shutdown"] = "N/A"
    return reg


def _extraer_sam_hive(fs, data):
    reg = get_registry_hive(fs, "/Windows/System32/config/SAM")
    users_list = []
    if reg:
        for ruta in ("SAM\\Domains\\Account\\Users\\Names",
                     "Domains\\Account\\Users\\Names"):
            try:
                key_users = reg.open(ruta)
                for user_key in key_users.subkeys():
                    users_list.append(user_key.name())
                break
            except Exception as e:
                log.debug("Ruta SAM '%s' no válida: %s", ruta, e)
                continue
        if not users_list:
            users_list.append("Error leyendo SAM")
    data["users"] = users_list


# --- Logger de pasos  ---
class _NullLogger:
    """Logger por defecto que no hace nada."""
    def start(self, nombre): pass
    def end(self, nombre, duracion): pass


def _run_step(logger, nombre, fn, label_fn=None):
    """Ejecuta un paso del análisis instrumentándolo en AMBOS loggers.

    - `logger` (UIStatusLogger): progreso en vivo + expander de la interfaz.
    - `log` (logging de Python → triaje_forense.log): traza persistente, que es
      el registro de auditoría real de la herramienta. Antes solo se escribía en
      él ante errores, por lo que un análisis correcto no dejaba ninguna huella.

    `label_fn`, si se indica, recibe el resultado del paso y construye la etiqueta
    de fin, permitiendo incluir contadores dinámicos (p. ej. "USB (5 dispositivos)")
    sin perder el reporte previo a conocer ese resultado.
    """
    logger.start(nombre)
    log.info("▶ Inicio: %s", nombre)
    t = time.time()
    result = fn()
    dur = time.time() - t
    fin_label = label_fn(result) if label_fn else nombre
    logger.end(fin_label, dur)
    log.info("✔ Fin: %s (%.2fs)", fin_label, dur)
    return result


# --- Principal ---
def procesar_evidencia(ruta_imagen, logger=None):
    """Extrae todos los datos forenses de una imagen de disco.

    Los hashes criptográficos se calculan en un hilo aparte desde
    `dashboard_tfm.py` y no forman parte de este flujo, ya que pueden
    ser muy lentos (varios minutos en imágenes grandes).

    Args:
        ruta_imagen: Ruta al archivo de imagen.
        logger:      objeto opcional con métodos `start(nombre)` y
                     `end(nombre, duracion)` para reportar progreso.
    """
    logger = logger or _NullLogger()
    log.info("===== Inicio del análisis de evidencia: %s =====", ruta_imagen)
    data = {"ruta_imagen": ruta_imagen}

    # -------- 1. APERTURA DE IMAGEN --------
    def _abrir():
        try:
            return _abrir_imagen(ruta_imagen)
        except Exception as e:
            log.error("Error al abrir la imagen '%s': %s", ruta_imagen, e)
            raise EvidenciaError(f"Error al abrir la imagen: {e}") from e

    img_info = _run_step(logger, "Apertura de imagen", _abrir)

    # -------- 2. PARTICIONES --------
    data["particiones"] = _run_step(
        logger, "Detección de particiones",
        lambda: extraer_particiones(img_info),
        label_fn=lambda r: f"Detección de particiones ({len(r)})",
    )

    # -------- 3. PARTICIÓN DE WINDOWS --------
    fs = _run_step(
        logger, "Localización del sistema de archivos Windows",
        lambda: _encontrar_fs_windows(img_info),
    )
    if not fs:
        log.error("No se encontró partición de Windows válida en '%s'", ruta_imagen)
        raise EvidenciaError("No se encontró partición de Windows válida.")

    # -------- 4. HIVES PRINCIPALES --------
    reg_software = _run_step(
        logger, "Hive SOFTWARE", lambda: _extraer_software_hive(fs, data)
    )
    reg_system = _run_step(
        logger, "Hive SYSTEM", lambda: _extraer_system_hive(fs, data)
    )
    _run_step(logger, "Hive SAM (usuarios)", lambda: _extraer_sam_hive(fs, data))

    # -------- 5. HIVES DE USUARIO --------
    user_hives = _run_step(
        logger, "Hives de usuario",
        lambda: _cargar_user_hives(fs),
        label_fn=lambda r: f"Hives de usuario ({len(r)} cargadas)",
    )

    # -------- 6. APPS INSTALADAS + ANTI-FORENSE --------
    data["apps"] = _run_step(
        logger, "Aplicaciones instaladas y anti-forenses",
        lambda: extraer_apps_instaladas(reg_software, user_hives),
        label_fn=lambda r: (
            f"Apps instaladas ({len(r['instaladas'])} totales, "
            f"{len(r['anti_forensic'])} anti-forenses)"
        ),
    )

    # -------- 7. USB --------
    data["usb"] = _run_step(
        logger, "Historial de dispositivos USB",
        lambda: extraer_usb(fs, reg_system, reg_software),
        label_fn=lambda r: f"Historial USB ({len(r)} dispositivos)",
    )

    # -------- 8. ACTIVIDAD DE EJECUCIÓN --------
    data["actividad"] = _run_step(
        logger, "Actividad de ejecución (Prefetch/UserAssist/Amcache)",
        lambda: extraer_actividad(fs, user_hives),
        label_fn=lambda r: (
            f"Actividad (Prefetch={len(r['prefetch'])}, "
            f"UserAssist={len(r['userassist'])}, Amcache={len(r['amcache'])})"
        ),
    )

    # -------- 9. PERSISTENCIA --------
    data["persistencia"] = _run_step(
        logger, "Análisis de persistencia (Run keys / Tareas)",
        lambda: extraer_persistencia(fs, reg_software, user_hives),
        label_fn=lambda r: (
            f"Persistencia (Run={len(r['run_keys'])}, "
            f"Tareas={len(r['scheduled_tasks'])})"
        ),
    )

    # -------- 10. RED --------
    data["red"] = _run_step(
        logger, "Actividad de red (perfiles e interfaces)",
        lambda: extraer_red(reg_system, reg_software),
        label_fn=lambda r: (
            f"Red ({len(r['profiles'])} perfiles, {len(r['interfaces'])} interfaces)"
        ),
    )

    # -------- 11. ACTIVIDAD USUARIO --------
    data["actividad_usuario"] = _run_step(
        logger, "Actividad de usuario (papelera, recientes, drives)",
        lambda: extraer_actividad_usuario(fs, user_hives),
        label_fn=lambda r: (
            f"Actividad usuario (Papelera={r['recycle_bin']['total_count']}, "
            f"Drives red={len(r['network_mru']['mapped'])})"
        ),
    )

    # -------- 12. NAVEGACIÓN --------
    data["navegacion"] = _run_step(
        logger, "Historial de navegación web",
        lambda: extraer_navegacion(fs),
        label_fn=lambda r: (
            f"Navegación ({len(r['urls'])} URLs, {len(r['keywords'])} keywords, "
            f"{len(r['downloads'])} descargas)"
        ),
    )

    # -------- 13. SEGURIDAD --------
    data["seguridad"] = _run_step(
        logger, "Estado de seguridad y eventos críticos",
        lambda: extraer_seguridad(fs, reg_system, reg_software),
        label_fn=lambda r: (
            f"Seguridad (Logons OK={len(r['eventos']['logon_success'])}, "
            f"Fallos={len(r['eventos']['logon_failed'])}, "
            f"Auditoría borrada={len(r['eventos']['audit_cleared'])})"
        ),
    )

    log.info("===== Análisis completado: %s =====", ruta_imagen)
    return data
