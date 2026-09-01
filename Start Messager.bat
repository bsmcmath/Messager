@echo off
REM Double-click to open the Messager control panel (hosts the server).
cd /d "%~dp0"
if not exist MessagerAdmin.exe (
  echo MessagerAdmin.exe not found. Run build.bat first.
  pause
  exit /b 1
)
start "" MessagerAdmin.exe
