@echo off
rem Starts the VulnHunter GUI from source. Creates .venv and installs PyQt5 on the first run.
setlocal
cd /d "%~dp0.."
if not exist ".venv\Scripts\python.exe" (
    echo Creating the virtual environment in .venv ...
    py -3 -m venv .venv 2>nul || python -m venv .venv
    if errorlevel 1 (
        echo Could not create .venv. Install Python 3.11 or newer from python.org, then run this again.
        exit /b 1
    )
)
".venv\Scripts\python.exe" -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)"
if errorlevel 1 (
    echo The GUI needs Python 3.11 or newer. Delete the .venv folder, install a newer Python, and run this again.
    exit /b 1
)
".venv\Scripts\python.exe" -c "import PyQt5" 2>nul || ".venv\Scripts\python.exe" -m pip install -r gui\requirements.txt
if errorlevel 1 exit /b 1
".venv\Scripts\python.exe" gui\main_gui.py %*
