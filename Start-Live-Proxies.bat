@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

set "CONFIG_FILE=proxy-service-config.env"

if exist "%CONFIG_FILE%" (
  for /f "usebackq tokens=1,* delims==" %%A in ("%CONFIG_FILE%") do set "%%A=%%B"
)

if /I "%~1"=="__child" goto child_entry

set "MODE=%~1"
if /I "%MODE%"=="live" goto launch_live_only
if /I "%MODE%"=="api" goto launch_api_only

if not exist "%CONFIG_FILE%" (
  echo Missing %CONFIG_FILE%
  echo Run Setup-Authenticated-Proxy-Service.bat first.
  pause
  exit /b 1
)

echo Starting both services...
start "Proxy Generator Live" cmd /k ""%~f0" __child live"
start "Proxy Generator API" cmd /k ""%~f0" __child api"
exit /b 0

:launch_live_only
start "Proxy Generator Live" cmd /k ""%~f0" __child %*"
exit /b 0

:launch_api_only
start "Proxy Generator API" cmd /k ""%~f0" __child %*"
exit /b 0

:child_entry
set "MODE=%~2"
shift
shift
set "FORWARD_ARGS="

:collect_args
if "%~1"=="" goto args_ready
set "FORWARD_ARGS=!FORWARD_ARGS! "%~1""
shift
goto collect_args

:args_ready
if not exist "venv\Scripts\python.exe" (
  echo Missing virtual environment. Create it and install requirements first.
  pause
  exit /b 1
)

if exist "active_proxies.json" del /f /q "active_proxies.json" >nul 2>nul
if exist "working_proxies.txt" del /f /q "working_proxies.txt" >nul 2>nul
if exist "working_proxies.json" del /f /q "working_proxies.json" >nul 2>nul

if /I "%MODE%"=="live" goto run_live
if /I "%MODE%"=="api" goto run_api

echo Invalid mode: %MODE%
pause
exit /b 1

:run_live
title Proxy Generator Live
echo Starting live proxy window...
echo.
venv\Scripts\python.exe -u app.py live --output-root "%~dp0output" !FORWARD_ARGS!
echo.
echo Live proxy session ended.
pause
exit /b 0

:run_api
title Proxy Generator API
echo Starting local proxy API...
echo.
set "API_ARGS=--host 127.0.0.1 --tunnel-host 127.0.0.1"

if defined PROXY_SERVICE_API_PORT    set "API_ARGS=!API_ARGS! --port %PROXY_SERVICE_API_PORT%"
if defined PROXY_SERVICE_TUNNEL_PORT set "API_ARGS=!API_ARGS! --tunnel-port %PROXY_SERVICE_TUNNEL_PORT%"
rem C-2: Keys are passed via environment variables (PROXY_SERVICE_API_KEY,
rem      PROXY_SERVICE_TUNNEL_KEY) which Python reads as argparse defaults.
rem      This prevents keys from appearing in the Windows process list / task manager.
if defined PROXY_SERVICE_TUNNEL_USER set "API_ARGS=!API_ARGS! --tunnel-auth-user %PROXY_SERVICE_TUNNEL_USER%"
if defined PROXY_SERVICE_OUTPUT_ROOT set "API_ARGS=!API_ARGS! --output-root %PROXY_SERVICE_OUTPUT_ROOT%"
rem L-6: warmup is ON by default. Set PROXY_SERVICE_WARMUP=0 in config to disable.
if /I "%PROXY_SERVICE_WARMUP%"=="0" goto skip_warmup
set "API_ARGS=!API_ARGS! --warmup"
:skip_warmup
if /I "%PROXY_SERVICE_LOG_REQUESTS%"=="1" set "API_ARGS=!API_ARGS! --log-requests"

venv\Scripts\python.exe -u app.py api !API_ARGS! !FORWARD_ARGS!
echo.
echo Proxy API stopped.
pause
