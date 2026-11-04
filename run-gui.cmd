@echo off
chcp 65001 >nul
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
  echo 未找到 Python，请先安装 Python 3.9+ 并加入 PATH。
  pause
  exit /b 1
)
python -m ipasign gui
if errorlevel 1 pause
