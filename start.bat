@echo off
cd /d "%~dp0"
where node >nul 2>&1
if errorlevel 1 (
  echo Node.js 18 or newer is required. Install it from https://nodejs.org and run this file again.
  pause
  exit /b 1
)
node server.js
echo.
echo Proofbench stopped.
pause
