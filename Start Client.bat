@echo off
REM Double-click to open the Messager desktop client.
cd /d "%~dp0"
if not exist MessagerClient.exe (
  echo MessagerClient.exe not found. Run build.bat first.
  pause
  exit /b 1
)
start "" MessagerClient.exe
