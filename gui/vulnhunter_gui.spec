# -*- mode: python ; coding: utf-8 -*-
# Build with gui/build_exe.cmd (Windows) or gui/build_exe.sh. Output: dist/VulnHunterGUI/
from pathlib import Path

ROOT = Path(SPECPATH).parent  # SPECPATH is the folder holding this file (gui/)

a = Analysis(
    [str(ROOT / "gui" / "main_gui.py")],
    # the repo root so gui.* and llm_connector.* import, and the agent folder that
    # llm_connector adds to sys.path at run time (its folder name has a hyphen)
    pathex=[str(ROOT), str(ROOT / "vulnhunter-agent" / "agent")],
    binaries=[],
    datas=[],
    hiddenimports=["config"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "tkinter"],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

# One folder, not one file: it starts faster and trips antivirus less often.
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="VulnHunterGUI",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="VulnHunterGUI",
)
