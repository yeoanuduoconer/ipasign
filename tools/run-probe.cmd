@echo off
setlocal
cd /d "%~dp0.."
set "PY=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
if not exist "%PY%" (
  echo [!] Python 3.11 not found at "%PY%"
  echo     Edit this file and point PY to a Python with srp/requests/cryptography installed.
  pause
  exit /b 1
)
"%PY%" "tools\appleid_probe.py" %*
if errorlevel 1 pause
