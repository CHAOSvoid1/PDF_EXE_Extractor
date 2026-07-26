@echo off
setlocal
cd /d "%~dp0"

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
  pause
  exit /b 1
)

"%PYEXE%" %PYARGS% -m pip install -r "%~dp0requirements.txt" pyinstaller
if errorlevel 1 goto :error
"%PYEXE%" %PYARGS% -m PyInstaller --noconfirm --clean --onefile --windowed --name "PDF_EXE_Extractor" --collect-all fontTools "%~dp0pdf_extractor_gui.pyw"
if errorlevel 1 goto :error

echo.
echo Build completed:
echo %~dp0dist\PDF_EXE_Extractor.exe
pause
exit /b 0

:error
echo ERROR: Build failed. Review the messages above.
pause
exit /b 1
