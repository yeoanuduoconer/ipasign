@echo off
setlocal

rem Register "ipasign" as a command without wasting disk space.
rem
rem Strategy:
rem   1. same volume  -> hard link (two names, one file, 0 extra bytes)
rem   2. other volume -> tiny .cmd shim (~200 bytes) that calls the exe
rem
rem Nothing is added to PATH; %LOCALAPPDATA%\Microsoft\WindowsApps is
rem already on PATH on Windows 10/11 and needs no admin rights.

set "SOURCE=%~dp0ipasign.exe"
set "TARGETDIR=%LOCALAPPDATA%\Microsoft\WindowsApps"
set "LINK=%TARGETDIR%\ipasign.exe"
set "SHIM=%TARGETDIR%\ipasign.cmd"

if not exist "%SOURCE%" goto :no_source
if not exist "%TARGETDIR%" goto :no_target

rem remove whatever was there before
if exist "%LINK%" del /f /q "%LINK%" >nul 2>&1
if exist "%SHIM%" del /f /q "%SHIM%" >nul 2>&1

mklink /H "%LINK%" "%SOURCE%" >nul 2>&1
if not errorlevel 1 goto :ok_link

rem cross-volume fallback: 200-byte shim instead of an 80 MB copy
> "%SHIM%" echo @echo off
>> "%SHIM%" echo "%SOURCE%" %%*
if exist "%SHIM%" goto :ok_shim
goto :failed

:ok_link
echo.
echo Done (hard link, 0 MB extra). Open any terminal and type:
goto :done

:ok_shim
echo.
echo Done (shim, ~1 KB). Open any terminal and type:
echo NOTE: the shim points at "%SOURCE%"; moving that file breaks it.
goto :done

:done
echo.
echo     ipasign
echo.
echo Uninstall: delete "%LINK%" or "%SHIM%"
echo.
pause
exit /b 0

:no_source
echo [ERROR] ipasign.exe not found next to this script.
pause
exit /b 1

:no_target
echo [ERROR] %TARGETDIR% does not exist on this system.
pause
exit /b 1

:failed
echo [ERROR] Could not create the link or the shim.
pause
exit /b 1
