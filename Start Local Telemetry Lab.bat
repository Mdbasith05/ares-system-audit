@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo The workspace Python environment is missing.
    echo Open this folder in VS Code and select a Python environment that includes Tkinter.
    pause
    exit /b 1
)
".venv\Scripts\python.exe" "%~dp0local_lab.py"
if errorlevel 1 pause
