#!/usr/bin/env bash
# Starts the VulnHunter GUI from source. Creates .venv and installs PyQt5 on the first run.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ ! -x .venv/bin/python ]; then
    echo "Creating the virtual environment in .venv ..."
    python3 -m venv .venv || { echo "Could not create .venv. Install Python 3.11 or newer."; exit 1; }
fi
.venv/bin/python -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
    || { echo "The GUI needs Python 3.11 or newer. Delete .venv, install a newer Python, and run this again."; exit 1; }
.venv/bin/python -c 'import PyQt5' 2>/dev/null || .venv/bin/python -m pip install -r gui/requirements.txt
exec .venv/bin/python gui/main_gui.py "$@"
