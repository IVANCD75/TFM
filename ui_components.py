"""Componentes de la interfaz Streamlit."""
import time
from datetime import datetime, date

import pandas as pd
import streamlit as st

from utils import get_logger, format_dt, format_size

log = get_logger()

# Helpers de formato: única fuente en utils.py (antes duplicados aquí).
_fmt_dt = format_dt
_fmt_size = format_size


# --- METADATOS PARA DEMO ---
# Valores que aparecerán como marca de agua (placeholder) en el
# formulario del informe pericial. Si el usuario no rellena un campo,
# se usará el valor demo correspondiente al generar PDF/Word.
DEMO_METADATA = {
    "perito": {
        "nombre":      "Iván Carmona Díez",
        "titulacion":  "Máster Universitario en Ciberseguridad (UNIR)",
        "colegiado":   "12345",
        "lugar_firma": "Madrid",
    },
    "caso": {
        "titulo":        "Análisis forense de evidencia digital",
        "referencia":    "TFM-2025-001",
        "procedimiento": "Diligencias Previas 123/2025",
        "solicitante":   "Ministerio Fiscal",
        "juzgado":       "Juzgado de Instrucción nº 5 de Madrid",
        "objeto":        ("Realizar un análisis forense automatizado de triaje sobre "
                          "la evidencia digital aportada, con el fin de extraer y "
                          "documentar los artefactos del sistema operativo más "
                          "relevantes para la investigación."),
        "antecedentes":  ("Se ha recibido la evidencia digital identificada para "
                          "su análisis forense en el contexto del procedimiento "
                          "judicial referenciado."),
    },
}


# --- SIDEBAR ---
def render_sidebar():
    """Panel lateral: carga de evidencias, formulario de informe y descargas."""
    if "ruta_archivo" not in st.session_state:
        st.session_state["ruta_archivo"] = ""
    if "report_metadata" not in st.session_state:
        st.session_state["report_metadata"] = _default_metadata()

    with st.sidebar:
        st.header("Configuración del Caso")

        if st.button("📂 Cargar Evidencia",
                     help="Buscar archivo de imagen forense",
                     width="stretch"):
            # Import perezoso: tkinter solo se necesita al pulsar el botón, y
            # así el módulo de UI sigue importando en entornos sin Tk (headless).
            import tkinter as tk
            from tkinter import filedialog

            root = tk.Tk()
            root.withdraw()
            root.wm_attributes("-topmost", 1)
            try:
                fname = filedialog.askopenfilename(
                    master=root,
                    title="Seleccionar Imagen Forense",
                    filetypes=[
                        ("Archivos Forenses", "*.E01 *.EX01 *.L01 *.dd *.raw *.img"),
                        ("Todos", "*.*"),
                    ],
                )
            finally:
                # Destruir SIEMPRE la raíz Tk para no acumular ventanas ocultas
                # en cada pulsación del botón.
                root.destroy()

            if fname:
                fname = fname.replace("/", "\\")
                st.session_state["ruta_archivo"] = fname
                st.session_state["analisis_pendiente"] = True
                # Limpiamos resultados, log e informes anteriores
                st.session_state["resultados"] = None
                st.session_state["analysis_log"] = None
                st.session_state.pop("informe_pdf", None)
                st.session_state.pop("informe_docx", None)
                st.rerun()

        st.text_input(
            "Ruta de la Evidencia",
            value=st.session_state.get("ruta_archivo", ""),
            disabled=True,
        )

        st.divider()
        _render_export_section()


def _default_metadata():
    """Metadatos por defecto para el informe."""
    return {
        "perito": {
            "nombre": "",
            "titulacion": "",
            "colegiado": "",
            "lugar_firma": "",
        },
        "caso": {
            "titulo": "",
            "referencia": "",
            "procedimiento": "",
            "solicitante": "",
            "juzgado": "",
            "objeto": "",
            "antecedentes": "",
        },
        "fecha_emision": date.today().strftime("%Y-%m-%d"),
    }


@st.fragment(run_every=2)
def _hash_calculating_warning_fragment():
    """Aviso en el sidebar mientras los hashes se calculan.

    Se ejecuta cada 2 segundos. Cuando `hash_state["estado"]` deja de ser
    "calculando", el fragment se redibuja sin contenido y el aviso desaparece.
    """
    hash_state = st.session_state.get("hash_state", {})
    if hash_state.get("estado") == "calculando":
        st.info(
            "Los hashes aún se están calculando en segundo plano. "
            "Puedes exportar ya el informe (sin hashes) o esperar a que terminen "
            "para que el documento incluya la cadena de custodia completa."
        )


def _render_export_section():
    """Sección de exportación del informe pericial."""
    st.subheader("Informe Pericial")

    hay_resultados = bool(st.session_state.get("resultados"))

    if not hay_resultados:
        st.caption("Realiza un análisis para habilitar la generación del informe.")
        return

    # ---- Aviso si los hashes aún se están calculando ----
    # En un fragment con auto-refresh para que desaparezca cuando el thread termine
    _hash_calculating_warning_fragment()

    with st.expander("Datos del Perito y Caso", expanded=False):
        meta = st.session_state["report_metadata"]
        dp = DEMO_METADATA["perito"]
        dc = DEMO_METADATA["caso"]

        meta["perito"]["nombre"] = st.text_input(
            "Nombre del perito", value=meta["perito"]["nombre"],
            placeholder=dp["nombre"], key="m_nombre")
        meta["perito"]["titulacion"] = st.text_input(
            "Titulación", value=meta["perito"]["titulacion"],
            placeholder=dp["titulacion"], key="m_titulacion")
        meta["perito"]["colegiado"] = st.text_input(
            "Nº de colegiado", value=meta["perito"]["colegiado"],
            placeholder=dp["colegiado"], key="m_col")
        meta["perito"]["lugar_firma"] = st.text_input(
            "Lugar de firma", value=meta["perito"]["lugar_firma"],
            placeholder=dp["lugar_firma"], key="m_lugar")

        meta["caso"]["titulo"] = st.text_input(
            "Título del caso", value=meta["caso"]["titulo"],
            placeholder=dc["titulo"], key="m_titulo")
        meta["caso"]["referencia"] = st.text_input(
            "Referencia interna", value=meta["caso"]["referencia"],
            placeholder=dc["referencia"], key="m_ref")
        meta["caso"]["procedimiento"] = st.text_input(
            "Procedimiento judicial", value=meta["caso"]["procedimiento"],
            placeholder=dc["procedimiento"], key="m_proc")
        meta["caso"]["solicitante"] = st.text_input(
            "Solicitante", value=meta["caso"]["solicitante"],
            placeholder=dc["solicitante"], key="m_sol")
        meta["caso"]["juzgado"] = st.text_input(
            "Juzgado / Órgano", value=meta["caso"]["juzgado"],
            placeholder=dc["juzgado"], key="m_juz")

        meta["caso"]["objeto"] = st.text_area(
            "Objeto del encargo (opcional)",
            value=meta["caso"]["objeto"], height=80, key="m_obj",
            placeholder=dc["objeto"],
            help="Si lo dejas en blanco se usará un texto por defecto.")
        meta["caso"]["antecedentes"] = st.text_area(
            "Antecedentes (opcional)",
            value=meta["caso"]["antecedentes"], height=80, key="m_ant",
            placeholder=dc["antecedentes"])

        fecha_obj = st.date_input(
            "Fecha de emisión", value=date.today(), key="m_fecha")
        meta["fecha_emision"] = fecha_obj.strftime("%Y-%m-%d")

    # ---- Botones de exportación ----
    col1, col2 = st.columns(2)
    with col1:
        if st.button("PDF", width="stretch", key="export_pdf_btn"):
            _generar_y_descargar("pdf")
    with col2:
        if st.button("Word", width="stretch", key="export_docx_btn"):
            _generar_y_descargar("docx")

    # Mostrar botón de descarga si hay informe generado
    if st.session_state.get("informe_pdf"):
        st.download_button(
            "⬇ Descargar PDF",
            data=st.session_state["informe_pdf"],
            file_name=_nombre_archivo("pdf"),
            mime="application/pdf",
            width="stretch",
            key="dl_pdf",
        )
    if st.session_state.get("informe_docx"):
        st.download_button(
            "⬇ Descargar Word",
            data=st.session_state["informe_docx"],
            file_name=_nombre_archivo("docx"),
            mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            width="stretch",
            key="dl_docx",
        )


def _nombre_archivo(ext):
    ref = (st.session_state["report_metadata"]["caso"].get("referencia")
           or DEMO_METADATA["caso"]["referencia"])
    fecha = datetime.now().strftime("%Y%m%d_%H%M")
    return f"Informe_Pericial_{ref}_{fecha}.{ext}"


def _metadatos_con_fallback(metadatos):
    """Devuelve una copia de los metadatos sustituyendo los campos vacíos
    por los valores de DEMO_METADATA. Esto permite que el formulario se
    pueda dejar en blanco (mostrando los placeholders) y, al generar el
    informe, los valores demo aparezcan en el documento como si el usuario
    los hubiera introducido."""
    out = {
        "perito": dict(metadatos.get("perito", {})),
        "caso": dict(metadatos.get("caso", {})),
        "fecha_emision": metadatos.get("fecha_emision"),
    }
    for seccion in ("perito", "caso"):
        for k, demo_val in DEMO_METADATA.get(seccion, {}).items():
            if not str(out[seccion].get(k, "")).strip():
                out[seccion][k] = demo_val
    return out


def _generar_y_descargar(formato):
    """Genera el informe en memoria y lo guarda en session_state para descarga.

    Si los hashes aún están en background, se inyectan en los resultados
    en el momento de generar el informe (si están listos).
    Los campos del formulario vacíos se rellenan con los valores demo.
    """
    from report_generator import generar_pdf, generar_docx

    resultados = dict(st.session_state["resultados"])  # copia superficial

    # Inyectar los hashes si están listos
    hash_state = st.session_state.get("hash_state", {})
    if hash_state.get("estado") == "listo" and hash_state.get("resultado"):
        resultados["hashes"] = hash_state["resultado"]
    else:
        resultados["hashes"] = None

    # Aplicar fallback de demo a los campos vacíos
    metadatos = _metadatos_con_fallback(st.session_state["report_metadata"])

    try:
        with st.spinner(f"Generando informe {formato.upper()}..."):
            if formato == "pdf":
                st.session_state["informe_pdf"] = generar_pdf(resultados, metadatos)
                st.success("PDF generado. Pulsa 'Descargar PDF'.")
            else:
                st.session_state["informe_docx"] = generar_docx(resultados, metadatos)
                st.success("Word generado. Pulsa 'Descargar Word'.")
    except ImportError as e:
        st.error(f"Falta una dependencia: {e}. Instala con: "
                 f"`pip install reportlab python-docx`")
    except Exception as e:
        st.error(f"Error al generar el informe: {e}")


# --- LANDING ---
def render_landing():
    st.subheader("Formatos soportados")
    cols = st.columns(6)
    for col, (ext, label) in zip(cols, [
        (".E01", "EnCase"), (".EX01", "EnCase v2"), (".L01", "LEF"),
        (".DD", "Raw"), (".IMG", "Raw"), (".RAW", "Raw"),
    ]):
        col.info(f"**{ext}**\n{label}")

    st.divider()

    st.subheader("Capacidades de análisis")
    caps = [
        ("🖥️ Info del sistema", "SO, hostname, propietario, versión y zona horaria."),
        ("🔐 Hashes de imagen", "MD5, SHA-1 y SHA-256 (en segundo plano)."),
        ("💽 Particiones", "Estructura del soporte y sistemas de archivos."),
        ("👥 Cuentas y actividad de usuario", "Usuarios SAM, Recientes, Papelera, drives."),
        ("📦 Apps instaladas", "Inventario y detección anti-forense."),
        ("🔌 Historial USB", "Dispositivos conectados con fechas."),
        ("📜 Actividad de ejecución", "Prefetch, UserAssist y Amcache."),
        ("🔒 Persistencia", "Run keys y tareas programadas sospechosas."),
        ("🌐 Red", "Perfiles WiFi/Ethernet, interfaces y drives mapeados."),
        ("🌎 Navegación web", "Historial Chrome/Edge y términos de búsqueda."),
        ("🛡️ Seguridad", "Defender, firewall, BitLocker y eventos críticos."),
        ("📑 Informe pericial", "Generación automática en PDF y Word (UNE 197010)."),
    ]
    rows = [caps[i:i + 3] for i in range(0, len(caps), 3)]
    for row in rows:
        cols = st.columns(3)
        for col, (title, desc) in zip(cols, row):
            with col, st.container(border=True):
                st.markdown(f"**{title}**")
                st.caption(desc)

    st.divider()
    st.info("Selecciona la imagen forense en el panel lateral para comenzar.", icon="ℹ️")


def _df_con_fechas(items, cols_fecha):
    if not items:
        return pd.DataFrame()
    df = pd.DataFrame(items)
    for col in cols_fecha:
        if col in df.columns:
            df[col] = df[col].apply(_fmt_dt)
    return df


# --- RESULTADOS ---
def _render_analysis_log_expander():
    """Expander colapsable con el log del análisis (tiempos por paso).

    Se renderiza siempre en la parte superior, sobre las pestañas, para que
    el usuario pueda consultar a posteriori cuánto tardó cada paso.
    """
    log = st.session_state.get("analysis_log")
    if not log:
        return
    total = log.get("total_time", 0)
    n = log.get("step_count", 0)
    with st.expander(
        f"Log del análisis · {n} pasos · {total:.2f}s totales",
        expanded=False,
    ):
        for nombre, duracion in log.get("entries", []):
            st.write(f"**{nombre}** — `{duracion:.2f}s`")
        st.divider()
        st.caption(f"**Tiempo total: `{total:.2f}s`**")


def render_resultados(resultados):
    """Renderiza los resultados en pestañas."""
    # Expander persistente con el log del análisis (siempre arriba, colapsado)
    _render_analysis_log_expander()

    # CSS para que las tabs ocupen todo el ancho
    st.markdown("""
    <style>
    .stTabs [data-baseweb="tab-list"] {
        width: 100%;
    }

    .stTabs [data-baseweb="tab"] {
        flex: 1 1 0;
        justify-content: center;
        text-align: center;
    }
    </style>
    """, unsafe_allow_html=True)

    tabs = st.tabs([
        "📊 Resumen", "🔐 Evidencia", "👥 Usuarios", "📦 Apps", "🔌 USB",
        "⏱️ Actividad", "🔒 Persistencia", "🌐 Red", "🌎 Navegación",
        "🛡️ Seguridad",
    ])

    with tabs[0]:
        _tab_resumen(resultados)
    with tabs[1]:
        _tab_evidencia(resultados)
    with tabs[2]:
        _tab_usuarios(resultados)
    with tabs[3]:
        _tab_apps(resultados.get("apps", {}))
    with tabs[4]:
        _tab_usb(resultados.get("usb", []))
    with tabs[5]:
        _tab_actividad(resultados.get("actividad", {}))
    with tabs[6]:
        _tab_persistencia(resultados.get("persistencia", {}))
    with tabs[7]:
        _tab_red(resultados.get("red", {}))
    with tabs[8]:
        _tab_navegacion(resultados.get("navegacion", {}))
    with tabs[9]:
        _tab_seguridad(resultados.get("seguridad", {}))


# --- TAB RESUMEN ---
def _tab_resumen(resultados):
    col1, col2, col3 = st.columns(3)
    col1.metric("Hostname", resultados.get("hostname", "N/A"))
    col1.caption(f"Dueño: {resultados.get('owner')}")
    col2.metric("Sistema Operativo", resultados.get("os_name", "N/A"))
    col2.caption(f"Versión: {resultados.get('release')} (Build {resultados.get('build', '?')})")
    col3.metric("Zona Horaria", resultados.get("timezone", "N/A"))

    st.divider()
    st.subheader("Línea de Tiempo")
    install_dt = (
        datetime.fromtimestamp(resultados.get("install_date_unix"))
        if resultados.get("install_date_unix") else "Desconocida"
    )
    c1, c2 = st.columns(2)
    c1.info(f"**Fecha Instalación:**\n\n{install_dt}")
    c2.warning(f"**Último Apagado:**\n\n{resultados.get('last_shutdown')}")


# --- TAB EVIDENCIA ---
def _tab_evidencia(resultados):
    """Hashes (con auto-refresh) y estructura de particiones."""
    _evidencia_hashes_fragment()

    st.divider()
    st.subheader("Estructura de particiones")
    particiones = resultados.get("particiones", [])
    if particiones:
        st.metric("Particiones detectadas", len(particiones))
        df = pd.DataFrame(particiones).drop(columns=["Tamaño (bytes)"], errors="ignore")
        st.dataframe(df, width="stretch", hide_index=True)
    else:
        st.warning("No se pudieron leer las particiones.")


@st.fragment(run_every=2)
def _evidencia_hashes_fragment():
    """Fragmento que se auto-refresca cada 2s mientras los hashes se calculan.

    Renderiza una única barra de progreso dividida en 3 segmentos (uno por
    hash) y debajo una tabla con los valores. Cuando estado="listo" o
    "error" el fragment sigue ejecutándose cada 2s pero ya no hay cambios
    visuales, el coste es despreciable.
    """
    st.subheader("Hashes criptográficos de la imagen")
    hash_state = st.session_state.get("hash_state", {})
    estado = hash_state.get("estado", "idle")

    if estado == "idle":
        st.warning("No hay cálculo de hashes en curso. Carga una nueva evidencia para iniciarlo.")
        return

    # ----- Mensaje general según estado global -----
    inicio = hash_state.get("inicio")
    fin = hash_state.get("fin")
    if estado == "calculando" and inicio:
        elapsed = time.time() - inicio
        st.info(
            f"**Cálculo en curso** — Tiempo transcurrido: **{elapsed:.0f}s**. "
            "Mientras tanto puedes explorar el resto de pestañas con normalidad. "
            " (Este panel se actualiza automáticamente cada 2 segundos)"
        )
    elif estado == "listo" and inicio and fin:
        st.success(
            f"Hashes calculados en **{(fin - inicio):.1f}s**. Estos valores "
            "quedan reflejados en el informe pericial como garantía de la cadena de custodia."
        )
    elif estado == "error":
        st.error(f"Error general al calcular los hashes: {hash_state.get('error')}")

    hashes_estado = hash_state.get("hashes", {})

    # ----- Barra única dividida en 3 segmentos (uno por hash) -----
    _render_combined_hash_progress(hashes_estado)

    # ----- Tabla con los valores de los hashes -----
    _render_hash_value_table(hashes_estado)

    # ----- Información de tamaño y fuente, solo cuando hay resultado -----
    resultado = hash_state.get("resultado")
    if resultado:
        c1, c2 = st.columns([1, 3])
        c1.metric("Tamaño imagen", _fmt_size(resultado.get("tamaño_bytes", 0)))
        c2.markdown(f"**Fuente:** {resultado.get('fuente', '—')}")


def _render_combined_hash_progress(hashes_estado):
    """Renderiza UNA barra de progreso dividida en 3 segmentos, uno por hash.

    Cada segmento muestra el icono de estado, el nombre del algoritmo y, si
    está calculando, el porcentaje. El relleno del segmento progresa de
    izquierda a derecha siguiendo el `progress` de cada hash.
    """
    # status -> (color_relleno, color_texto)
    palette = {
        "done":        ("#28a745", "white"),
        "calculating": ("#0d6efd", "white"),
        "error":       ("#dc3545", "white"),
        "pending":     ("rgba(128,128,128,0.35)", "inherit"),
    }

    segments = []
    for i, algo in enumerate(("MD5", "SHA-1", "SHA-256")):
        h = hashes_estado.get(algo, {})
        status = h.get("status", "pending")
        progress = h.get("progress", 0.0)
        fill_pct = (int(progress * 100) if status == "calculating"
                    else 100 if status in ("done", "error") else 0)

        fill_color, text_color = palette.get(status, palette["pending"])

        if status == "calculating":
            label = f"{algo} · {fill_pct}%"
        else:
            label = f"{algo}"

        empty_bg = "rgba(128,128,128,0.12)"
        bg = f"linear-gradient(to right, {fill_color} {fill_pct}%, {empty_bg} {fill_pct}%)"
        border_right = ("border-right:1px solid rgba(128,128,128,0.4);"
                        if i < 2 else "")

        segments.append(
            f'<div style="flex:1; height:32px; background:{bg}; '
            f'display:flex; align-items:center; justify-content:center; '
            f'font-weight:600; font-size:14px; color:{text_color}; '
            f'white-space:nowrap; {border_right}">'
            f'{label}</div>'
        )

    html = (
        '<div style="display:flex; width:100%; '
        'border:1px solid rgba(128,128,128,0.4); border-radius:8px; '
        'overflow:hidden; margin: 0.5rem 0 1rem 0;">'
        + ''.join(segments) +
        '</div>'
    )
    st.markdown(html, unsafe_allow_html=True)


def _render_hash_value_table(hashes_estado):
    """Renderiza una tabla con los valores hexadecimales de los hashes."""
    def _display(h):
        status = h.get("status", "pending")
        value = h.get("value")
        if value:
            return value
        if status == "calculating":
            return "Calculando…"
        if status == "error":
            return "Error"
        return "Pendiente"

    df = pd.DataFrame([
        {"Algoritmo": algo, "Hash": _display(hashes_estado.get(algo, {}))}
        for algo in ("MD5", "SHA-1", "SHA-256")
    ])
    st.dataframe(df, width="stretch", hide_index=True)


# --- TAB USUARIOS ---
def _tab_usuarios(resultados):
    """Cuentas SAM + actividad de usuario. La actividad se filtra por el
    usuario seleccionado en la tabla SAM (click en una fila)."""

    # --------- Sub-sección 1: Cuentas SAM (clicables) ---------
    st.subheader("Cuentas de usuario locales (SAM)")
    st.caption(
        "Selecciona una fila para filtrar la actividad por ese usuario. "
        "Vuelve a hacer click sobre la misma fila para volver a la vista "
        "agregada de todos los usuarios."
    )

    selected_user = None
    if resultados.get("users"):
        df_users = pd.DataFrame(resultados["users"], columns=["Nombre de Usuario"])
        event = st.dataframe(
            df_users, width="stretch", hide_index=True,
            on_select="rerun", selection_mode="single-row",
            key="sam_users_table",
        )
        try:
            selected_rows = event.selection.rows
        except AttributeError:
            selected_rows = []
        if selected_rows:
            selected_user = df_users.iloc[selected_rows[0]]["Nombre de Usuario"]
    else:
        st.warning("No se encontraron usuarios.")

    st.divider()

    # --------- Sub-sección 2: Actividad (con filtrado por usuario) ---------
    if selected_user:
        st.subheader(f"Actividad de **{selected_user}**")
        st.caption(f"Filtrada para el usuario seleccionado.")
    else:
        st.subheader("Actividad del usuario · vista agregada")
        st.caption("Mostrando la actividad combinada de todos los usuarios.")

    actividad_usuario = resultados.get("actividad_usuario", {})
    recent_docs_agg = actividad_usuario.get("recent_docs", [])
    recent_docs_by_user = actividad_usuario.get("recent_docs_by_user", {})
    recycle = actividad_usuario.get("recycle_bin", {})
    browsers = actividad_usuario.get("browsers", {})
    network_mru = actividad_usuario.get("network_mru", {})

    # ---- Filtrar según selected_user ----
    if selected_user:
        recent_docs = recent_docs_by_user.get(selected_user, [])
        mapped_drives = [m for m in network_mru.get("mapped", [])
                         if m.get("Usuario") == selected_user]
        run_mru = [r for r in network_mru.get("run_mru", [])
                   if r.get("Usuario") == selected_user]
        browsers_filtered = ({selected_user: browsers[selected_user]}
                             if selected_user in browsers else {})
        browser_main = browsers.get(selected_user, "—")
    else:
        recent_docs = recent_docs_agg
        mapped_drives = network_mru.get("mapped", [])
        run_mru = network_mru.get("run_mru", [])
        browsers_filtered = browsers
        browser_main = (next(iter(browsers.values()), "Desconocido")
                        if browsers else "—")

    total_docs = sum(d["Cantidad"] for d in recent_docs)
    bin_count = recycle.get("total_count", 0)
    bin_size = _fmt_size(recycle.get("total_size", 0))
    n_drives = len(mapped_drives)

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Docs recientes", total_docs)
    c2.metric("Papelera", bin_count)
    c3.metric("Tamaño papelera", bin_size)
    c4.metric("Navegador", browser_main)
    c5.metric("Drives de red", n_drives)

    if recent_docs:
        with st.expander("Documentos recientes por extensión", expanded=True):
            df = pd.DataFrame(recent_docs)
            st.dataframe(df, width="stretch", hide_index=True)
    elif selected_user:
        st.info(f"Sin documentos recientes para {selected_user}.")

    if mapped_drives:
        with st.expander(
            f"Unidades de almacenamiento de red mapeadas ({n_drives})",
            expanded=True,
        ):
            df = _df_con_fechas(mapped_drives, ["Última Modif."])
            st.dataframe(df, width="stretch", hide_index=True)

    if run_mru:
        with st.expander(f"Historial ventana 'Ejecutar' ({len(run_mru)})"):
            df = _df_con_fechas(run_mru, ["Última Modif."])
            st.dataframe(df, width="stretch", hide_index=True,
                         column_config={"Es Ruta Red": st.column_config.CheckboxColumn(disabled=True)})

    if browsers_filtered:
        with st.expander("Navegador por usuario"):
            df = pd.DataFrame([
                {"Usuario": u, "Navegador": b}
                for u, b in browsers_filtered.items()
            ])
            st.dataframe(df, width="stretch", hide_index=True)

    # La papelera NO se filtra por usuario: $Recycle.Bin usa SIDs y no
    # podemos mapear fiablemente SID→nombre desde el registro offline.
    if recycle.get("files"):
        rb_title = (f"Papelera de reciclaje (global) — {bin_count} archivos "
                    f"({bin_size})")
        with st.expander(rb_title, expanded=not selected_user):
            if selected_user:
                st.caption(
                    "La papelera se identifica por SID, no por nombre de usuario, "
                    "por lo que no es posible filtrarla con fiabilidad desde el "
                    "registro offline. Se muestra siempre la vista global."
                )
            files = recycle["files"]
            st.markdown("**Últimos 5 archivos borrados:**")
            df_top = _df_con_fechas(files[:5], ["Fecha Borrado"])
            st.dataframe(df_top, width="stretch", hide_index=True)
            if len(files) > 5:
                st.markdown(f"**Todos los archivos ({len(files)}):**")
                df_all = _df_con_fechas(files, ["Fecha Borrado"])
                st.dataframe(df_all, width="stretch", hide_index=True)


# --- TAB APPS ---
def _tab_apps(apps_data):
    instaladas = apps_data.get("instaladas", [])
    anti_f = apps_data.get("anti_forensic", [])

    c1, c2 = st.columns(2)
    c1.metric("Aplicaciones instaladas", len(instaladas))
    c2.metric("Anti-forenses detectadas", len(anti_f),
              delta=("Atención" if anti_f else None),
              delta_color="inverse" if anti_f else "off")

    st.divider()

    if anti_f:
        with st.expander(f"Aplicaciones anti-forenses ({len(anti_f)})", expanded=True):
            df = pd.DataFrame(anti_f)
            st.dataframe(df, width="stretch", hide_index=True)
            st.error(
                "La presencia de estas herramientas en el equipo es un indicador relevante "
                "en investigaciones de fuga de información o intentos de borrado de huellas."
            )

    if instaladas:
        with st.expander(f"Todas las aplicaciones instaladas ({len(instaladas)})", expanded=False):
            df = pd.DataFrame(instaladas)
            st.dataframe(df, width="stretch", hide_index=True)
    else:
        st.info("No se encontraron aplicaciones en las claves Uninstall.")


# --- TAB USB ---
def _tab_usb(usb_devices):
    if not usb_devices:
        st.warning("No se encontraron dispositivos USB en USBSTOR.")
        return

    last_dt = usb_devices[0]["Última Conexión"]
    first_dt = min((d["Primera Conexión"] for d in usb_devices if d["Primera Conexión"]), default=None)

    c1, c2, c3 = st.columns(3)
    c1.metric("Dispositivos detectados", len(usb_devices))
    c2.metric("Última conexión", _fmt_dt(last_dt))
    c3.metric("Primera conexión registrada", _fmt_dt(first_dt))

    st.divider()
    with st.expander(f"Detalle de los {len(usb_devices)} dispositivos USB", expanded=True):
        df = _df_con_fechas(usb_devices, ["Primera Conexión", "Última Conexión"])
        st.dataframe(df, width="stretch", hide_index=True)


# --- TAB ACTIVIDAD ---
def _tab_actividad(actividad):
    prefetch = actividad.get("prefetch", [])
    userassist = actividad.get("userassist", [])
    amcache = actividad.get("amcache", [])

    if not (prefetch or userassist or amcache):
        st.warning("No se encontraron datos de actividad.")
        return

    c1, c2, c3 = st.columns(3)
    c1.metric("Archivos Prefetch", len(prefetch))
    c2.metric("Entradas UserAssist", len(userassist))
    c3.metric("Entradas Amcache", len(amcache))

    st.divider()

    if prefetch:
        with st.expander(f"10 ejecuciones más recientes (Prefetch)", expanded=True):
            df = _df_con_fechas(prefetch[:10], ["Última Ejecución"])
            st.dataframe(df, width="stretch", hide_index=True)
        with st.expander(f"Todos los {len(prefetch)} archivos Prefetch"):
            df = _df_con_fechas(prefetch, ["Última Ejecución"])
            st.dataframe(df, width="stretch", hide_index=True)

    if userassist:
        with st.expander(f"Aplicaciones más usadas (UserAssist) — {len(userassist)} entradas",
                         expanded=True):
            top = sorted(userassist, key=lambda x: x["Veces Ejecutado"], reverse=True)[:20]
            df = _df_con_fechas(top, ["Última Ejecución"])
            st.dataframe(df, width="stretch", hide_index=True)

    if amcache:
        with st.expander(f"Programas ejecutados (Amcache) — {len(amcache)} entradas"):
            df = _df_con_fechas(amcache[:200], ["Modificado"])
            st.dataframe(df, width="stretch", hide_index=True)


# --- TAB PERSISTENCIA ---
def _tab_persistencia(persistencia):
    run_keys = persistencia.get("run_keys", [])
    tasks = persistencia.get("scheduled_tasks", [])
    suspicious_runs = sum(1 for r in run_keys if r.get("Sospechoso"))
    suspicious_tasks = sum(1 for t in tasks if t.get("Sospechoso"))

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Entradas Run/RunOnce", len(run_keys))
    c2.metric("Tareas programadas", len(tasks))
    c3.metric("Run sospechosos", suspicious_runs,
              delta=("Atención" if suspicious_runs > 0 else None),
              delta_color="inverse" if suspicious_runs > 0 else "off")
    c4.metric("Tareas sospechosas", suspicious_tasks,
              delta=("Atención" if suspicious_tasks > 0 else None),
              delta_color="inverse" if suspicious_tasks > 0 else "off")

    st.divider()

    if run_keys:
        with st.expander(f"Run / RunOnce — {len(run_keys)} entradas", expanded=True):
            df = pd.DataFrame(run_keys)
            st.dataframe(df, width="stretch", hide_index=True,
                         column_config={"Sospechoso": st.column_config.CheckboxColumn(disabled=True)})

    if tasks:
        with st.expander(f"Tareas programadas — {len(tasks)} entradas"):
            df = pd.DataFrame(tasks)
            st.dataframe(df, width="stretch", hide_index=True,
                         column_config={"Sospechoso": st.column_config.CheckboxColumn(disabled=True)})

        if suspicious_tasks:
            with st.expander(f"Solo tareas SOSPECHOSAS ({suspicious_tasks})", expanded=True):
                df = pd.DataFrame([t for t in tasks if t.get("Sospechoso")])
                st.dataframe(df, width="stretch", hide_index=True)


# --- TAB RED ---
def _tab_red(red):
    profiles = red.get("profiles", [])
    interfaces = red.get("interfaces", [])

    wifi_count = sum(1 for p in profiles if p["Tipo"] == "Wi-Fi")
    eth_count = sum(1 for p in profiles if p["Tipo"] == "Cableada")
    last_net = profiles[0]["Nombre (SSID)"] if profiles else "—"

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Redes Wi-Fi", wifi_count)
    c2.metric("Redes Cableadas", eth_count)
    c3.metric("Última red", last_net)
    c4.metric("Interfaces IP", len(interfaces))

    st.divider()

    if profiles:
        with st.expander(f"Historial de redes — {len(profiles)} perfiles", expanded=True):
            df = _df_con_fechas(profiles, ["Creada", "Última Conexión"])
            st.dataframe(df, width="stretch", hide_index=True)

    if interfaces:
        with st.expander(f"Configuración IP — {len(interfaces)} interfaces"):
            df = pd.DataFrame(interfaces)
            st.dataframe(df, width="stretch", hide_index=True)


# --- TAB NAVEGACIÓN ---
def _tab_navegacion(navegacion):
    urls = navegacion.get("urls", [])
    keywords = navegacion.get("keywords", [])
    downloads = navegacion.get("downloads", [])

    if not (urls or keywords or downloads):
        st.warning("No se encontró historial de navegación. "
                   "Verifica que el equipo usase Chrome, Edge, Brave u Opera.")
        return

    c1, c2, c3 = st.columns(3)
    c1.metric("URLs visitadas", len(urls))
    c2.metric("Búsquedas web", len(keywords))
    c3.metric("Descargas", len(downloads))

    st.divider()

    if keywords:
        with st.expander(f"Términos buscados en internet ({len(keywords)})", expanded=True):
            df = _df_con_fechas(keywords, ["Última Búsqueda"])
            st.dataframe(df, width="stretch", hide_index=True)
            st.caption("Términos extraídos del parámetro `q=` (y equivalentes) de las URLs.")

    if downloads:
        with st.expander(f"Descargas registradas ({len(downloads)})"):
            df = _df_con_fechas(downloads, ["Inicio"])
            st.dataframe(df, width="stretch", hide_index=True)

    if urls:
        with st.expander(f"Top 100 URLs más recientes ({len(urls)} totales)"):
            df = _df_con_fechas(urls[:100], ["Última Visita"])
            st.dataframe(df, width="stretch", hide_index=True)


# --- TAB SEGURIDAD ---
def _tab_seguridad(seguridad):
    defender = seguridad.get("defender", {})
    firewall = seguridad.get("firewall", {})
    bitlocker = seguridad.get("bitlocker", [])
    eventos = seguridad.get("eventos", {})

    if defender.get("third_party_av"):
        av_status = f"AV: {defender['third_party_av'][0]}"
        av_delta = "Activo"
    elif defender.get("rt_monitoring"):
        av_status = "Defender"
        av_delta = "Activo"
    else:
        av_status = "Defender"
        av_delta = "DESACTIVADO"

    fw_profiles = [
        ("Dominio", firewall.get("domain")),
        ("Privado", firewall.get("private")),
        ("Público", firewall.get("public")),
    ]
    fw_active = sum(1 for _, v in fw_profiles if v)
    fw_total = sum(1 for _, v in fw_profiles if v is not None)
    fw_label = f"{fw_active}/{fw_total} perfiles activos" if fw_total else "Sin datos"

    n_logon_ok = len(eventos.get("logon_success", []))
    n_logon_fail = len(eventos.get("logon_failed", []))
    n_cleared = len(eventos.get("audit_cleared", []))

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Antivirus", av_status, av_delta)
    c2.metric("Firewall", fw_label)
    c3.metric("Logons fallidos", n_logon_fail,
              delta="Posible fuerza bruta" if n_logon_fail > 50 else None,
              delta_color="inverse" if n_logon_fail > 50 else "off")
    c4.metric("Registro borrado", n_cleared,
              delta="Evento 1102 detectado" if n_cleared > 0 else None,
              delta_color="inverse" if n_cleared > 0 else "off")

    st.divider()

    with st.expander("Detalle Antivirus y Defender", expanded=False):
        estado_defender = (
            ":green[Activa]" if defender.get('rt_monitoring')
            else ":red[Desactivada]"
        )
        st.write(f"**Monitorización en tiempo real (Defender):** {estado_defender}")
        tp = defender.get("tamper_protection")
        estado_tamper = (
            ":green[Activa]" if tp
            else ":red[Desactivada]" if tp is False
            else ":orange[Sin Datos]"
        )
        st.write(f"**Tamper Protection:** {estado_tamper}")
        if defender.get("third_party_av"):
            st.write("**Antivirus de terceros detectados:**")
            for av in defender["third_party_av"]:
                st.write(f"- {av}")
        else:
            st.write("**Antivirus de terceros:** :blue[Ninguno detectado]")

    with st.expander("Detalle Firewall por perfil"):
        for label, val in fw_profiles:
            estado = (
                ":green[Activo]" if val
                else ":red[Desactivado]" if val is False
                else ":orange[Sin datos]"
            )

            st.markdown(f"**{label}:** {estado}")

    with st.expander("BitLocker"):
        if bitlocker:
            df = pd.DataFrame(bitlocker)
            st.dataframe(df, width="stretch", hide_index=True)
        else:
            st.info("No se detectó configuración de BitLocker en el registro. "
                    "El estado real de cifrado no siempre se almacena de forma "
                    "recuperable en el registro offline.")

    st.markdown("### Eventos críticos de seguridad")
    if eventos.get("error"):
        st.warning(f"{eventos['error']}")
    else:
        st.caption(f"Analizados {eventos.get('total_revisados', 0)} eventos del Security.evtx")

        if eventos.get("audit_cleared"):
            with st.expander(f"Event 1102 — Borrado de auditoría ({n_cleared})", expanded=True):
                df = pd.DataFrame(eventos["audit_cleared"])
                st.dataframe(df, width="stretch", hide_index=True)
                st.error("El borrado del log de auditoría es un indicador típico de actividad maliciosa.")

        if eventos.get("logon_failed"):
            with st.expander(f"Event 4625 — Logons fallidos ({n_logon_fail})",
                             expanded=n_logon_fail > 50):
                df = pd.DataFrame(eventos["logon_failed"])
                st.dataframe(df, width="stretch", hide_index=True)
                if n_logon_fail > 50:
                    st.warning("Volumen alto de fallos: posible fuerza bruta.")

        if eventos.get("logon_success"):
            with st.expander(f"Event 4624 — Logons exitosos ({n_logon_ok})"):
                df = pd.DataFrame(eventos["logon_success"])
                st.dataframe(df, width="stretch", hide_index=True)
