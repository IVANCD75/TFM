# Triaje Forense Automatizado

> **TFM – Máster Universitario en Ciberseguridad (UNIR)**
> Autor: Iván Carmona Díez

Herramienta de análisis forense automatizado para sistemas Windows, diseñada para realizar un **triaje rápido** sobre evidencias digitales (imágenes de disco) y generar un **informe pericial** conforme al estándar **UNE 197010:2015**.

La aplicación se distribuye como un **ejecutable portable** para Windows que arranca un dashboard local en el navegador, sin necesidad de instalar Python ni dependencias en la máquina del perito.

---

## Características principales

| Módulo | Funcionalidad |
| --- | --- |
| **Soporte de imágenes** | E01, EX01, L01 (EWF) y dd, raw, img |
| **Hashes criptográficos** | MD5, SHA-1 y SHA-256 calculados en segundo plano |
| **Sistema** | SO, hostname, propietario, build, zona horaria y última apagada |
| **Particiones** | Estructura del soporte y sistemas de archivos detectados |
| **Cuentas** | Usuarios SAM + carga automática de hives `NTUSER.DAT` |
| **Apps instaladas** | Inventario completo y detección de software **anti-forense** |
| **Historial USB** | Dispositivos conectados con marcas temporales |
| **Actividad de ejecución** | Prefetch, UserAssist y Amcache |
| **Persistencia** | Claves *Run* y *Scheduled Tasks* sospechosas |
| **Red** | Perfiles WiFi/Ethernet, interfaces y *drives* mapeados |
| **Actividad de usuario** | Papelera, recientes, MRU, *network drives* |
| **Navegación web** | Historial y descargas de Chrome/Edge, *keywords* de búsqueda |
| **Seguridad** | Estado de Windows Defender, firewall, BitLocker y eventos críticos del *Event Log* (`.evtx`) |
| **Informe pericial** | Generación automática en **PDF** y **Word** según **UNE 197010:2015** |

---

## Requisitos

### Para usar el ejecutable portable

- Windows 10/11 (x64).
- No requiere instalación de Python ni dependencias.

### Para ejecutar desde el código fuente o compilar el `.exe`

- **Python 3.10+** (recomendado 3.11 o 3.12).
- **Microsoft C++ Build Tools** con el paquete **«Desarrollo para el escritorio con C++»** instalado.
  > Es **obligatorio** para compilar `libewf-python` (el binding de PyEWF), ya que se construye desde código fuente en Windows. Sin estas *Build Tools* el `pip install` fallará.
  > Descarga: <https://visualstudio.microsoft.com/visual-cpp-build-tools/>

---

## Instalación (entorno de desarrollo)

```bash
# 1. Clonar el repositorio
git clone https://github.com/<usuario>/<repositorio>.git
cd <repositorio>

# 2. (Recomendado) Crear un entorno virtual
python -m venv venv
venv\Scripts\activate

# 3. Instalar dependencias
pip install -r requirements.txt
```

Si la instalación de `libewf-python` falla, verifica que tienes las **Microsoft C++ Build Tools** correctamente instaladas (ver sección anterior).

---

## Uso

### Modo desarrollo (Streamlit directo)

```bash
streamlit run dashboard_tfm.py
```

Se abrirá automáticamente en el navegador en `http://localhost:8501`.

### Modo portable (ejecutable `.exe`)

Tras compilar el binario (ver siguiente sección), basta con ejecutar `ForensicTool.exe`. La aplicación arranca un servidor local y abre el navegador apuntando al dashboard.

### Flujo de trabajo dentro de la aplicación

1. Pulsar **«Cargar Evidencia»** en el panel lateral y seleccionar la imagen.
2. La aplicación lanza el **análisis principal** y el **cálculo de hashes en paralelo**.
3. Los resultados se muestran en pestañas: Resumen, Evidencia, Usuarios, Apps, USB, Actividad, Persistencia, Red, Navegación y Seguridad.
4. Rellenar los metadatos del perito y del caso en el panel lateral.
5. Pulsar **Generar PDF** o **Generar Word** para obtener el informe pericial.

---

## Generar el ejecutable portable

Desde la raíz del proyecto, con todas las dependencias instaladas:

```bash
pyinstaller run.spec --clean --noconfirm
```

El binario resultante se genera en `dist/ForensicTool.exe`. El archivo `run.spec` ya está configurado para empaquetar:

- Todos los módulos del proyecto y los recursos de `img/`.
- Streamlit completo con sus *submodules* y metadatos.
- Las librerías de bajo nivel (`pytsk3`, `pyewf`, `python-registry`, `python-evtx`, `lxml`).
- Las librerías de generación de informes (`reportlab`, `python-docx`).
- Tkinter para el diálogo de selección de archivo.

---

## Estructura del proyecto

```
.
├── dashboard_tfm.py          # Entry point del dashboard (Streamlit)
├── run.py                    # Wrapper para arrancar Streamlit desde el .exe
├── run.spec                  # Configuración de PyInstaller
├── ui_components.py          # Sidebar, landing y pestañas de resultados
├── session_monitor.py        # Watchdog: cierra el .exe al cerrar el navegador
├── utils.py                  # Helpers (logging, formateo, Registry, paths)
│
├── forensics.py              # Orquestador del análisis
├── forensics_hashes.py       # Hashes MD5/SHA-1/SHA-256 + particiones
├── forensics_apps.py         # Apps instaladas + detección anti-forense
├── forensics_browser.py      # Historial Chrome/Edge
├── forensics_usb.py          # Historial USB
├── forensics_activity.py     # Prefetch / UserAssist / Amcache
├── forensics_persistence.py  # Run keys + Scheduled Tasks
├── forensics_network.py      # Perfiles e interfaces de red
├── forensics_useractivity.py # Papelera, recientes, MRU
├── forensics_security.py     # Defender / Firewall / BitLocker / Event Log
│
├── report_generator.py       # Generación PDF/DOCX (UNE 197010:2015)
├── report_content.py         # Plantillas y contenidos del informe
│
├── img/                      # Logos e iconos
│   ├── Logo.ico
│   └── Logo.png
│
├── requirements.txt
└── README.md
```

---

## Notas técnicas

- **Hashes en paralelo:** se calculan en un hilo aparte sincronizado con un `threading.Lock` para no bloquear el análisis principal, que típicamente termina en pocos segundos mientras los hashes pueden tardar varios minutos en imágenes grandes.
- **Imports perezosos:** `tkinter` y los módulos de generación de informes (`reportlab`, `python-docx`) se importan bajo demanda para acelerar el arranque.
- **Session watchdog:** un thread monitoriza las sesiones activas de Streamlit y termina el proceso del `.exe` automáticamente cuando se cierra la última pestaña del navegador.
- **Capa de extracción agnóstica:** los módulos `forensics_*` no dependen de Streamlit y pueden invocarse desde una CLI o desde tests unitarios.

---

## Aviso legal

Esta herramienta ha sido desarrollada como Trabajo Fin de Máster con fines **académicos y demostrativos**. Su uso en investigaciones reales debe ir acompañado de los procedimientos de cadena de custodia y validación pericial pertinentes según la jurisdicción correspondiente.
