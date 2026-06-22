"""Watchdog que cierra la aplicación cuando no quedan sesiones activas."""
import glob
import os
import shutil
import tempfile
import threading
import time

import streamlit as st
from streamlit.runtime import get_instance

from utils import get_logger

log = get_logger()

# Prefijos de los temporales que crea la herramienta (browser + evtx).
_TEMP_PREFIXES = ("tfm_browser_", "tfm_evtx_")
# Nº de sondeos vacíos consecutivos requeridos para cerrar (≈ 3 × 2 s = 6 s).
_EMPTY_POLLS_TO_EXIT = 3
_POLL_INTERVAL_S = 2


def _purgar_temporales():
    """Limpieza best-effort de temporales huérfanos antes de salir.

    os._exit() omite los bloques `finally`, por lo que un cierre durante un
    análisis dejaría directorios/ficheros temporales sin borrar. Aquí se
    eliminan los que coinciden con los prefijos conocidos de la herramienta.
    """
    tmp_root = tempfile.gettempdir()
    for prefix in _TEMP_PREFIXES:
        for path in glob.glob(os.path.join(tmp_root, prefix + "*")):
            try:
                if os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    os.unlink(path)
                log.info("Temporal huérfano eliminado: %s", path)
            except OSError as e:
                log.debug("No se pudo eliminar el temporal '%s': %s", path, e)


def _hay_sesiones_activas():
    """Devuelve True/False/None según el estado del runtime de Streamlit.

    Encapsula el acceso a la API interna `_session_mgr` en un único punto: si
    una futura versión de Streamlit la elimina o renombra, solo hay que tocar
    aquí, y mientras tanto se registra el fallo en lugar de silenciarlo.
    """
    try:
        runtime = get_instance()
    except Exception as e:
        log.debug("Runtime de Streamlit no accesible: %s", e)
        return None
    if not runtime:
        return None
    try:
        session_mgr = getattr(runtime, "_session_mgr", None)
        if session_mgr is None or not hasattr(session_mgr, "list_active_sessions"):
            log.warning("API de sesiones de Streamlit no disponible; watchdog inactivo.")
            return None
        return len(session_mgr.list_active_sessions()) > 0
    except Exception as e:
        log.debug("No se pudo consultar las sesiones activas: %s", e)
        return None


def _watchdog_loop():
    """Comprueba periódicamente si hay sesiones activas; si no, cierra el proceso."""
    time.sleep(5)  # margen inicial para que el navegador abra la primera sesión

    empty_streak = 0
    while True:
        activas = _hay_sesiones_activas()

        if activas is True:
            empty_streak = 0
        elif activas is False:
            empty_streak += 1
            if empty_streak >= _EMPTY_POLLS_TO_EXIT:
                log.info("Sin sesiones activas tras %d sondeos. Cerrando aplicación…",
                         empty_streak)
                _purgar_temporales()
                os._exit(0)
        # activas is None → runtime no disponible: no contamos la racha,
        # simplemente reintentamos en el siguiente ciclo.

        time.sleep(_POLL_INTERVAL_S)


def start_watchdog():
    """Inicia el watchdog una sola vez por sesión."""
    if "watchdog_started" not in st.session_state:
        t = threading.Thread(target=_watchdog_loop, daemon=True)
        t.start()
        log.info("Programa iniciado.")
        st.session_state["watchdog_started"] = True
