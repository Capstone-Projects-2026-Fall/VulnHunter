#!/usr/bin/env bash
# Builds the GUI into dist/VulnHunterGUI/ with PyInstaller (needs Python 3.11+; creates .venv if missing).
set -euo pipefail
cd "$(dirname "$0")/.."
[ -x .venv/bin/python ] || python3 -m venv .venv
.venv/bin/python -m pip install -r gui/requirements-build.txt
.venv/bin/python -m PyInstaller gui/vulnhunter_gui.spec --noconfirm --clean --distpath dist --workpath build
echo "Built dist/VulnHunterGUI/ (share the whole folder, zipped)"
