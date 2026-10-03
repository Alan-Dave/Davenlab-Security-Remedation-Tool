# ─────────────────────────────────────────────────────────────────────────────
# Davenlab Security Remediation Tool — PyInstaller Spec
# ─────────────────────────────────────────────────────────────────────────────
# Uso:
#   pyinstaller davenlab.spec
# ─────────────────────────────────────────────────────────────────────────────

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        # Incluir la carpeta de logs vacía (.gitkeep) para que exista en el exe
        ('logs/.gitkeep', 'logs'),
    ],
    hiddenimports=[
        'PyQt6.QtCore',
        'PyQt6.QtGui',
        'PyQt6.QtWidgets',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter', 'matplotlib', 'numpy', 'pandas',
        'scipy', 'PIL.ImageTk',
    ],
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
    name='DavenlabSecurityTool',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,             # Compresión UPX (reduce tamaño del .exe)
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,        # Sin ventana de consola (app gráfica pura)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='assets/icon.ico',
    version='version_info.txt',
    uac_admin=True,       # Solicitar elevación de Admin al ejecutar
)
