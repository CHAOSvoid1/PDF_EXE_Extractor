@echo off
setlocal
cd /d "%~dp0"
set "LOG=%~dp0diagnostic_log.txt"
(
  echo PDF EXE Extractor diagnostic
  echo Date: %date% %time%
  echo Folder: %cd%
  echo.
  echo === Files ===
  dir /b
  echo.
  echo === Python launcher ===
  where py.exe 2^>^&1
  py.exe -0p 2^>^&1
  echo.
  echo === Python command ===
  where python.exe 2^>^&1
  python.exe --version 2^>^&1
  echo.
  echo === Import test via py ===
  py.exe -3 -c "import sys, tkinter, fontTools, extractor_core; print(sys.version); print('tkinter OK'); print('fontTools', fontTools.__version__); print('extractor_core OK')" 2^>^&1
  echo.
  echo === Import test via python ===
  python.exe -c "import sys, tkinter, fontTools, extractor_core; print(sys.version); print('tkinter OK'); print('fontTools', fontTools.__version__); print('extractor_core OK')" 2^>^&1
) > "%LOG%"

type "%LOG%"
echo.
echo Diagnostic log saved to:
echo %LOG%
pause
endlocal
