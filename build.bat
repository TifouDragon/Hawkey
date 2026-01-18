@echo off
setlocal
set ICON=Apple.ico
if not exist "%ICON%" (
  echo Icon not found: %ICON%
  exit /b 1
)
python -m PyInstaller --noconfirm --clean HawkEye.spec
if errorlevel 1 (
  echo Build failed.
)
pause
endlocal
