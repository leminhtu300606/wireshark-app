@echo off
setlocal

:: Define URLs and filenames
set "PYTHON_URL=https://www.python.org/ftp/python/3.11.13/python-3.11.13-amd64.exe"
set "PYTHON_INSTALLER=python-3.11.13-amd64.exe"
set "NPCAP_URL=https://nmap.org/npcap/dist/npcap-1.85.exe"
set "NPCAP_INSTALLER=npcap-1.85.exe"

echo ----------------------------------------------------------------------
echo Starting automated setup...
echo ----------------------------------------------------------------------

:: 1. Download Python
if exist "%PYTHON_INSTALLER%" (
    echo %PYTHON_INSTALLER% already exists. Skipping download.
) else (
    echo Downloading Python 3.11.13...
    powershell -Command "Invoke-WebRequest -Uri '%PYTHON_URL%' -OutFile '%PYTHON_INSTALLER%'"
)

:: 2. Download Npcap
if exist "%NPCAP_INSTALLER%" (
    echo %NPCAP_INSTALLER% already exists. Skipping download.
) else (
    echo Downloading Npcap 1.85...
    powershell -Command "Invoke-WebRequest -Uri '%NPCAP_URL%' -OutFile '%NPCAP_INSTALLER%'"
)

echo.
echo ----------------------------------------------------------------------
echo Installing software...
echo ----------------------------------------------------------------------

:: 3. Install Python
echo Installing Python 3.11...
:: /passive displays progress bar but requires no user interaction.
:: PrependPath=1 adds Python to environment variables.
start /wait "" "%PYTHON_INSTALLER%" /passive PrependPath=1 ALLUSERS=1

:: 4. Install Npcap
echo Installing Npcap...
:: /S runs in silent mode (no UI).
start /wait "" "%NPCAP_INSTALLER%" /S

echo.
echo ----------------------------------------------------------------------
echo Setup completed successfully!
echo You may need to restart your computer or restart your terminal.
echo ----------------------------------------------------------------------
pause
