"""Dashboard principal del Triaje Forense Automatizado."""
import os
import threading
import time

import streamlit as st
from PIL import Image as PILImage

from utils import resolve_path
from session_monitor import start_watchdog
from forensics import procesar_evidencia, EvidenciaError
from forensics_hashes import calcular_hashes
from ui_components import render_sidebar, render_landing, render_resultados


# --- INICIALIZACIÓN ---
start_watchdog()

icon_path = resolve_path("img/Logo.ico")
page_icon = PILImage.open(icon_path) if os.path.exists(icon_path) else "🔍"
st.set_page_config(page_title="TFM Iván Carmona Díez", layout="wide", page_icon=page_icon)

# --- CABECERA ---
st.title("Triaje Forense Automatizado")
st.caption("TFM Máster Universitario en Ciberseguridad · Análisis rápido de evidencia forense")
st.divider()

# --- ESTADO ---
def _hash_state_inicial():
    """Estado inicial del cálculo de hashes con un sub-estado por algoritmo."""
    return {
        "estado": "idle",        # idle | calculando | listo | error
        "resultado": None,        # dict final con MD5/SHA-1/SHA-256/fuente/tamaño
        "error": None,
        "ruta": None,
        "inicio": None,
        "fin": None,
        # Sub-estado granular por hash
        "hashes": {
            "MD5":     {"status": "pending", "value": None, "progress": 0.0},
            "SHA-1":   {"status": "pending", "value": None, "progress": 0.0},
            "SHA-256": {"status": "pending", "value": None, "progress": 0.0},
        },
    }


if "resultados" not in st.session_state:
    st.session_state["resultados"] = None
if "analisis_pendiente" not in st.session_state:
    st.session_state["analisis_pendiente"] = False
if "hash_state" not in st.session_state:
    st.session_state["hash_state"] = _hash_state_inicial()
if "analysis_log" not in st.session_state:
    st.session_state["analysis_log"] = None

# Migración: si viene de una sesión anterior con un hash_state "viejo"
if "hashes" not in st.session_state["hash_state"]:
    st.session_state["hash_state"] = _hash_state_inicial()


# --- SIDEBAR ---
render_sidebar()

# --- WORKER DE HASHES EN SEGUNDO PLANO ---
def _hash_worker(ruta, state, lock):
    """Calcula los hashes y va actualizando el sub-estado de cada uno.

    Todas las escrituras sobre `state` (que es `st.session_state["hash_state"]`,
    leído en paralelo por el fragmento de auto-refresco de la UI) se serializan
    con `lock`. Además, el sub-estado de cada algoritmo se sustituye por un dict
    nuevo de forma atómica, de modo que un lector nunca observe una entrada a
    medio escribir (p. ej. `status` actualizado pero `value` aún no).
    """
    def on_update(algo, status, value=None, progress=None):
        with lock:
            h = state["hashes"].get(algo)
            if h is None:
                return
            nuevo = dict(h)
            nuevo["status"] = status
            if value is not None:
                nuevo["value"] = value
            if progress is not None:
                nuevo["progress"] = max(0.0, min(1.0, progress))
            state["hashes"][algo] = nuevo  # swap atómico del sub-estado

    try:
        resultado = calcular_hashes(ruta, on_update=on_update)
        with lock:
            # `resultado` antes que `estado` para que, si la UI ve "listo",
            # el resultado ya esté disponible.
            state["resultado"] = resultado
            state["estado"] = "listo"
    except Exception as e:
        with lock:
            state["error"] = str(e)
            state["estado"] = "error"
    finally:
        with lock:
            state["fin"] = time.time()


def _lanzar_hashes_background(ruta):
    """Inicia el thread de hashes y guarda referencia en session_state."""
    # Reseteamos el estado a inicial limpio
    st.session_state["hash_state"] = _hash_state_inicial()
    state = st.session_state["hash_state"]

    # Lock compartido para las transiciones de estado entre el worker y la UI.
    lock = threading.Lock()
    st.session_state["hash_lock"] = lock

    with lock:
        state["estado"] = "calculando"
        state["ruta"] = ruta
        state["inicio"] = time.time()

    thread = threading.Thread(
        target=_hash_worker, args=(ruta, state, lock), daemon=True
    )
    thread.start()
    st.session_state["hash_thread"] = thread

# --- ANÁLISIS ---
class UIStatusLogger:
    """Logger que pinta en un st.status y guarda las entradas para mostrarlas
    luego en un expander persistente."""

    def __init__(self, status):
        self.status = status
        self.contador = 0
        self.entries = []  # lista de tuplas (nombre, duracion_seg)

    def start(self, nombre):
        self.contador += 1
        self.status.update(label=f"Paso {self.contador}: {nombre}…")

    def end(self, nombre, duracion):
        self.entries.append((nombre, duracion))
        self.status.write(f"**{nombre}** — `{duracion:.2f}s`")


if st.session_state["analisis_pendiente"]:
    st.session_state["analisis_pendiente"] = False
    ruta = st.session_state.get("ruta_archivo", "")

    # 1 Lanzar hashes EN PARALELO antes de empezar el análisis principal
    _lanzar_hashes_background(ruta)

    # 2 Análisis principal con status interactivo
    total_start = time.time()
    with st.status("Iniciando análisis…", expanded=True) as status:
        status.write(
            "*Los hashes criptográficos se están calculando en segundo plano "
            "y aparecerán en la pestaña «Evidencia» cuando estén listos.*"
        )
        logger = UIStatusLogger(status)
        try:
            nuevos_resultados = procesar_evidencia(ruta, logger=logger)
        except EvidenciaError as e:
            # La capa de extracción comunica los fallos por excepción; aquí, en
            # la capa de presentación, decidimos cómo mostrarlos al usuario.
            nuevos_resultados = None
            status.write(f"❌ {e}")
        tiempo_total = time.time() - total_start

        if nuevos_resultados:
            st.session_state["resultados"] = nuevos_resultados
            # Guardamos el log y el tiempo total para mostrarlos
            # después en un expander colapsable
            st.session_state["analysis_log"] = {
                "entries": logger.entries,
                "total_time": tiempo_total,
                "step_count": logger.contador,
            }
            status.update(
                label=f"Análisis completado en {tiempo_total:.2f}s "
                      f"({logger.contador} pasos)",
                state="complete",
                expanded=False,
            )
        else:
            status.update(
                label="Error en el análisis",
                state="error",
                expanded=True,
            )
            st.session_state["resultados"] = None

    # 3 Rerun para refrescar el sidebar con los botones de exportación habilitados
    if nuevos_resultados:
        st.rerun()

# --- COTENIDO PRINCIPAL ---
resultados = st.session_state.get("resultados")

if resultados:
    render_resultados(resultados)
elif not st.session_state.get("analisis_pendiente"):
    render_landing()
