@echo off
setlocal
cd /d "%~dp0"

echo.
echo   Codex Net Doctor
echo   ----------------
echo   Browser opens at http://127.0.0.1:8787/
echo   One scan takes about 30 seconds (5 rounds).
echo   Close this window to stop the server.
echo.

set "PY="
where py >nul 2>nul
if not errorlevel 1 set "PY=py"
if defined PY goto run

where python >nul 2>nul
if not errorlevel 1 set "PY=python"
if defined PY goto run

echo   [ERROR] Python was not found on PATH.
echo   Install Python 3 from https://www.python.org/downloads/
echo   and tick "Add python.exe to PATH" during setup.
echo.
pause
exit /b 1

:run
if exist "run.py" goto go
echo   [ERROR] run.py was not found next to this file.
echo.
pause
exit /b 1

:go
%PY% run.py
echo.
echo   Server stopped. Press any key to close.
pause
