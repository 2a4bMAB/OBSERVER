# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all, collect_submodules, collect_data_files

block_cipher = None

# Force-collect every submodule of our local packages
datas = []
binaries = []
hiddenimports = []

for pkg in ['core', 'ui', 'scanner', 'bs4', 'soupsieve']:
    d, b, h = collect_all(pkg)
    datas    += d
    binaries += b
    hiddenimports += h

# Add standard third-party hidden imports that PyInstaller misses
hiddenimports += [
    'sqlite3',
    'ssl',
    'smtplib',
    'email',
    'email.mime',
    'email.mime.text',
    'email.mime.multipart',
    'dotenv',
    'bcrypt',
    'jwt',
    'sqlalchemy',
    'sqlalchemy.dialects.sqlite',
    'sqlalchemy.pool',
    'reportlab',
    'reportlab.lib',
    'reportlab.platypus',
    'reportlab.pdfbase',
    'PIL',
    'lxml',
    'requests',
    'urllib3',
    'certifi',
    'bs4',
    'soupsieve',
]

# Project assets
datas += [
    ('ui/design/assets/logo.png', 'ui/design/assets'),
    ('.env', '.'),
    ('.env.example', '.'),
]

a = Analysis(
    ['main.py'],
    pathex=['.'],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
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
    [],
    exclude_binaries=True,
    name='OBSERVER',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='OBSERVER',
)
