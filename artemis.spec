# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller spec for Artemis v15 -- by Arkitexe.
#
# Builds a single-file .exe bundling psutil, pydivert/WinDivert,
# PIL/Pillow, and the resources/ folder (quotes, emojis, GIFs).
#
# To build:
#   pip install pyinstaller psutil pydivert Pillow
#   pyinstaller artemis.spec
# Output: dist\Artemis.exe

import os

block_cipher = None

# Collect pydivert's bundled DLL and driver if pydivert is installed
pydivert_binaries = []
pydivert_hiddenimports = []
try:
    import pydivert
    pd_dir = os.path.dirname(pydivert.__file__)
    for sub in ("", "windivert-2.2/x64", "windivert-2.2/x86"):
        full = os.path.join(pd_dir, sub) if sub else pd_dir
        if os.path.isdir(full):
            for fn in os.listdir(full):
                if fn.lower().endswith((".dll", ".sys")):
                    src = os.path.join(full, fn)
                    dest = sub if sub else "."
                    pydivert_binaries.append((src, dest))
    pydivert_hiddenimports = [
        "pydivert",
        "pydivert.packet",
        "pydivert.windivert",
        "pydivert.consts",
    ]
except ImportError:
    pass

# Bundle the resources/ folder (quotes, emojis, GIFs). At runtime these
# are extracted to _MEIPASS; see _resource_root() in artemis.py for the
# lookup logic that works both from source and from the bundled exe.
resource_datas = []
if os.path.isdir("resources"):
    for root, dirs, files in os.walk("resources"):
        for fn in files:
            src = os.path.join(root, fn)
            rel = os.path.relpath(root, ".")
            resource_datas.append((src, rel))


a = Analysis(
    ['artemis.py'],
    pathex=[],
    binaries=pydivert_binaries,
    datas=resource_datas,
    hiddenimports=[
        'psutil',
        'psutil._psutil_windows',
        'tkinter',
        'tkinter.font',
        'tkinter.ttk',
        'PIL',
        'PIL.Image',
        'PIL.ImageTk',
        'PIL.ImageSequence',
        'azure_regions',
    ] + pydivert_hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'numpy', 'pytesseract', 'mss',
        'matplotlib', 'scipy', 'pandas',
        'pydoc', 'doctest', 'unittest',
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
    name='Artemis',
    icon='resources/artemis_icon.ico',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=['WinDivert.dll', 'WinDivert64.sys', 'WinDivert32.sys'],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
