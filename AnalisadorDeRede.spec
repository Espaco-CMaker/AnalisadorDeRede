# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['run.py'],
    pathex=[],
    binaries=[],
    datas=[('oui_database.json', '.'), ('oui_metadata.json', '.'), ('config.json', '.')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

import re
with open('analisador_rede_gui.py', encoding='utf-8') as f:
    content = f.read()
match = re.search(r'APP_VERSION\s*=\s*[\"\\\']([\d\.]+)[\"\\\']', content)
if match:
    version = match.group(1)
else:
    version = '0.0'
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name=f'AnalisadorDeRede_v{version}',
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
)
