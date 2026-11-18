@echo off
rem Builds the GUI into dist\VulnHunterGUI\ with PyInstaller (needs Python 3.11+; creates .venv if missing).
setlocal
cd /d "%~dp0.."
if not exist ".venv\Scripts\python.exe" (
    py -3 -m venv .venv 2>nul || python -m venv .venv
    if errorlevel 1 (
        echo Could not create .venv. Install Python 3.11 or newer, then run this again.
        exit /b 1
    )
)
".venv\Scripts\python.exe" -m pip install -r gui\requirements-build.txt
if errorlevel 1 exit /b 1
".venv\Scripts\python.exe" -m PyInstaller gui\vulnhunter_gui.spec --noconfirm --clean --distpath dist --workpath build
if errorlevel 1 exit /b 1
echo.
echo Built dist\VulnHunterGUI\VulnHunterGUI.exe  (share the whole VulnHunterGUI folder, zipped)
