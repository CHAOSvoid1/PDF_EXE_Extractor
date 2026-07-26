@echo off
setlocal
cd /d "%~dp0"

if not exist "pdf_extractor_gui.pyw" (
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
  echo Install Python 3.10 or newer, and enable "Add Python to PATH".
  echo Then run install_and_run.bat again.
  pause
  exit /b 1
)

"%PYEXE%" %PYARGS% -c "import sys, tkinter, extractor_core; print(sys.version)" > "%~dp0startup_error.log" 2>&1
if errorlevel 1 (
  echo ERROR: Python environment check failed.
  echo Details:
  type "%~dp0startup_error.log"
  echo.
  echo Run diagnose.bat for more information.
  pause
  exit /b 1
)

"%PYEXE%" %PYARGS% "%~dp0pdf_extractor_gui.pyw" %* 2>> "%~dp0startup_error.log"
if errorlevel 1 (
  echo ERROR: The GUI exited unexpectedly.
  echo Details:
  type "%~dp0startup_error.log"
  pause
  exit /b 1
)
endlocal
