"""Utilidades compartidas: logging, rutas, conversión de tiempos y registro.

Este módulo centraliza:
  - La configuración de logging de la herramienta (`get_logger`), para sustituir
    los `except Exception: pass` silenciosos por trazas auditables.
  - Helpers de formato (`format_size`, `format_dt`) usados por la UI y por el
    generador de informes, evitando duplicar la misma función en tres sitios.
  - Conversión de marcas de tiempo de Windows y acceso seguro al registro.
"""
import logging
import os
import sys
from io import BytesIO
from datetime import datetime, timedelta

from Registry import Registry



# --- LOGGING ---
_LOG_CONFIGURED = False


def get_logger(name="forense"):
    """Devuelve un logger configurado una sola vez para toda la herramienta.

    En una herramienta forense, descartar silenciosamente una excepción puede
    traducirse en artefactos omitidos del informe sin que el perito lo sepa.
    Por eso cada captura de error debe dejar traza con este logger.
    """
    global _LOG_CONFIGURED
    if not _LOG_CONFIGURED:
        try:
            base_dir = (
                os.path.dirname(sys.executable)
                if getattr(sys, "frozen", False)
                else os.path.dirname(os.path.abspath(__file__))
            )

            logs_dir = os.path.join(base_dir, "logs")
            os.makedirs(logs_dir, exist_ok=True)

            handlers = [logging.StreamHandler(sys.stderr)]
            try:
                handlers.append(
                    logging.FileHandler(os.path.join(logs_dir, "triaje_forense.log"),
                                        encoding="utf-8")
                )
            except Exception:
                # Si no se puede escribir el fichero (p. ej. ruta de solo lectura),
                # seguimos solo con la salida estándar de error.
                pass
            logging.basicConfig(
                level=logging.INFO,
                format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                handlers=handlers,
            )
        except Exception:
            logging.basicConfig(level=logging.INFO)
        _LOG_CONFIGURED = True
    return logging.getLogger(name)


log = get_logger()


# --- RUTAS / EMPAQUETADO ---
def resolve_path(path):
    """Resuelve rutas tanto en desarrollo como empaquetado con PyInstaller."""
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, path)
    return os.path.join(os.path.abspath("."), path)


# --- HELPERS DE FORMATO ---
def format_dt(dt):
    """Formatea un datetime (o string ya formateado) de forma robusta."""
    if dt is None:
        return "—"
    if isinstance(dt, str):
        return dt
    try:
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(dt)


def format_size(size_bytes):
    """Convierte un número de bytes a una cadena legible (B/KB/MB/…)."""
    if not size_bytes:
        return "0 B"
    s = float(size_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if s < 1024:
            return f"{s:.1f} {unit}"
        s /= 1024
    return f"{s:.1f} PB"


def safe_unix_dt(ts, fmt="%Y-%m-%d %H:%M:%S", default="Desconocida"):
    """Convierte un timestamp Unix a texto, tolerando valores corruptos.

    Los valores del registro de Windows pueden venir fuera de rango y
    `datetime.fromtimestamp` lanzaría OverflowError/OSError/ValueError. Evita
    que un único valor inválido tumbe la generación completa del informe.
    """
    if not ts:
        return default
    try:
        return datetime.fromtimestamp(ts).strftime(fmt)
    except (TypeError, ValueError, OverflowError, OSError) as e:
        log.warning("Timestamp Unix inválido (%r): %s", ts, e)
        return default



# --- TIEMPOS DE WINDOWS ---
def filetime_to_dt(ft_int):
    """Convierte Windows FILETIME (64-bit int) a datetime legible."""
    if not ft_int:
        return None
    try:
        us = ft_int / 10
        return datetime(1601, 1, 1) + timedelta(microseconds=us)
    except (OverflowError, ValueError, OSError) as e:
        log.debug("FILETIME fuera de rango (%r): %s", ft_int, e)
        return None


def get_registry_hive(fs, path):
    """Extrae una hive del sistema de archivos y la carga en memoria."""
    try:
        f = fs.open(path)
        file_content = f.read_random(0, f.info.meta.size)
        return Registry.Registry(BytesIO(file_content))
    except Exception as e:
        # No todas las hives existen en todas las imágenes: es esperable, por
        # eso se registra a nivel DEBUG, pero queda traza de qué no se pudo abrir.
        log.debug("No se pudo cargar la hive '%s': %s", path, e)
        return None


def get_registry_value(key, value_name):
    """Obtiene un valor de registro de forma segura."""
    try:
        return key.value(value_name).value()
    except Exception as e:
        log.debug("Valor de registro ausente '%s': %s", value_name, e)
        return None
