@echo off
rem Run the Evomi proxy bridge on Windows.
rem Installs uv automatically if missing, provisions Python via uv,
rem then launches main.py. Extra arguments are forwarded.
rem   run.bat
rem   run.bat --local-port 8900 --upstream-tls
setlocal
cd /d "%~dp0"

where uv >nul 2>nul
if errorlevel 1 (
    echo [*] uv not found - installing from https://astral.sh/uv ...
    powershell -NoProfile -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
    if errorlevel 1 (
        echo [-] uv installation failed. Install manually from https://docs.astral.sh/uv/
        exit /b 1
    )
    set "PATH=%USERPROFILE%\.local\bin;%PATH%"
)

echo [*] launching proxy bridge (Python provisioned by uv as needed)...
uv run --python 3.12 main.py %*
