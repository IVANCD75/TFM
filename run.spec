# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_data_files, copy_metadata, collect_submodules, collect_all

# --- 1. CONFIGURACIÓN INICIAL ---
datas = []
binaries = []
hidden_imports = []

# --- 2. RECOLECCIÓN DE STREAMLIT ---
datas += collect_data_files('streamlit')
datas += copy_metadata('streamlit') 
hidden_imports += collect_submodules('streamlit')
hidden_imports += [
    'streamlit.runtime',
    'streamlit.runtime.scriptrunner.magic_funcs',
    'streamlit.runtime.scriptrunner.script_runner',
    'streamlit.web.cli',
]

# --- 3. RECOLECCIÓN NUCLEAR DE 'REGISTRY' (Mantener esto es vital) ---
tmp_reg_datas, tmp_reg_binaries, tmp_reg_hidden = collect_all('Registry')
datas += tmp_reg_datas
binaries += tmp_reg_binaries
hidden_imports += tmp_reg_hidden

# --- 4. ARREGLO PARA TKINTER (NUEVO) ---
# Forzamos la inclusión de los submódulos de interfaz gráfica
hidden_imports += [
    'tkinter',
    'tkinter.filedialog',
    'tkinter.messagebox',
    'tkinter.simpledialog'
]

# --- 5. TUS ARCHIVOS Y OTRAS LIBRERÍAS ---
datas += [
    ('dashboard_tfm.py', '.'),
    ('utils.py', '.'),
    ('session_monitor.py', '.'),
    ('forensics.py', '.'),
    ('forensics_usb.py', '.'),
    ('forensics_activity.py', '.'),
    ('forensics_persistence.py', '.'),
    ('forensics_network.py', '.'),
    ('forensics_useractivity.py', '.'),
    ('forensics_security.py', '.'),
    ('forensics_hashes.py', '.'),
    ('forensics_apps.py', '.'),
    ('forensics_browser.py', '.'),
    ('report_content.py', '.'),
    ('report_generator.py', '.'),
    ('ui_components.py', '.'),
    ('img/Logo.ico', 'img'),
    ('img/Logo.png', 'img'),
]

hidden_imports += [
    'pytsk3',
    'pyewf',
    'pandas',
    'numpy',
    'altair',
    'pyarrow',
    'blinker',
    'cachetools',
    'click',
    'git',
    'protobuf',
    'rich',
    'tenacity',
    'tornado',
    'tzlocal',
    'validators',
    'watchdog',
    'fpdf',
    'Evtx', 
    'Evtx.Evtx', 
    'Evtx.Views', 
    'Evtx.Nodes',
    'lxml', 
    'lxml.etree',
    'reportlab', 
    'reportlab.pdfgen', 
    'reportlab.platypus', 
    'reportlab.lib',
    'reportlab.lib.pagesizes', 
    'reportlab.lib.styles', 
    'reportlab.lib.units',
    'reportlab.lib.colors', 
    'reportlab.lib.enums',
    'docx', 
    'docx.shared', 
    'docx.enum', 
    'docx.enum.text', 
    'docx.enum.table',
    'sqlite3',
]

block_cipher = None

a = Analysis(
    ['run.py'],
    pathex=[],
    binaries=binaries, 
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='ForensicTool',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='img/Logo.ico',
)