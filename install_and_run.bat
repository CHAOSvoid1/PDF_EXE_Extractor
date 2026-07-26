@echo off
setlocal
cd /d "%~dp0"

if not exist "requirements.txt" (
  echo ERROR: Program files are incomplete.
  echo Please extract the ENTIRE ZIP to a normal folder before running this file.
  pause
  exit /b 1
)

set "PYEXE="
set "PYARGS="
where py.exe >nul 2>&1
if not errorlevel 1 (
  set "PYEXE=py.exe"
  set "PYARGS=-3"
) else (
  where python.exe >nul 2>&1
  if not errorlevel 1 set "PYEXE=python.exe"
)

if not defined PYEXE (
  echo ERROR: Python 3 was not found.
  echo Download Python 3.10 or newer from python.org.
  echo During installation, enable "Add Python to PATH".
  pause
  exit /b 1
)

echo Installing required Python package...
"%PYEXE%" %PYARGS% -m pip install --upgrade pip
if errorlevel 1 goto :error
"%PYEXE%" %PYARGS% -m pip install -r "%~dp0requirements.txt"
if errorlevel 1 goto :error

echo.
echo Installation completed. Starting the tool...
call "%~dp0run_tool.bat"
exit /b %errorlevel%

:error
echo.
echo ERROR: Dependency installation failed.
echo Check your network, Python installation, proxy, or antivirus settings.
pause
exit /b 1
