@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

echo ========================================
echo   PcapQt Build Script (ONEFILE)
echo   Requires Python 3.11
echo ========================================
echo.

REM Kiểm tra Python version
python --version 2>nul | findstr "3.11" >nul
if errorlevel 1 (
    echo [ERROR] Yêu cầu Python 3.11!
    echo Vui lòng cài đặt Python 3.11 và thử lại.
    pause
    exit /b 1
)

echo [INFO] Đang kiểm tra môi trường ảo...

REM Tạo virtual environment nếu chưa có
if not exist ".venv" (
    echo [INFO] Đang tạo virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Không thể tạo virtual environment!
        pause
        exit /b 1
    )
)

REM Kích hoạt virtual environment
echo [INFO] Đang kích hoạt virtual environment...
call .venv\Scripts\activate.bat

REM Cài đặt dependencies
echo [INFO] Đang cài đặt dependencies...
pip install --upgrade pip
pip install -e ".[dev]"
if errorlevel 1 (
    echo [ERROR] Không thể cài đặt dependencies!
    pause
    exit /b 1
)

REM Dọn dẹp thư mục build cũ
echo [INFO] Đang dọn dẹp thư mục build cũ...
if exist "build" rmdir /s /q "build"
if exist "dist" rmdir /s /q "dist"
if exist "*.spec" del /q "*.spec"

REM Build với PyInstaller - ONEFILE
echo [INFO] Đang build ứng dụng (onefile mode)...
echo.

REM Kiểm tra icon có tồn tại không
set ICON_PARAM=
if exist "icons\app.ico" (
    set ICON_PARAM=--icon=icons\app.ico
)

pyinstaller ^
    --name=PcapQt ^
    --onefile ^
    --windowed ^
    %ICON_PARAM% ^
    --add-data="icons;icons" ^
    --add-data="pcapqt;pcapqt" ^
    --hidden-import=scapy.layers.all ^
    --hidden-import=scapy.layers.dns ^
    --hidden-import=scapy.layers.http ^
    --hidden-import=scapy.layers.tls ^
    --hidden-import=scapy.layers.dhcp ^
    --hidden-import=scapy.layers.ntp ^
    --hidden-import=scapy.layers.snmp ^
    --hidden-import=PyQt5 ^
    --hidden-import=PyQt5.QtCore ^
    --hidden-import=PyQt5.QtGui ^
    --hidden-import=PyQt5.QtWidgets ^
    --hidden-import=pcapqt ^
    --hidden-import=pcapqt.main ^
    --hidden-import=pcapqt.views ^
    --hidden-import=pcapqt.views.main_window ^
    --hidden-import=pcapqt.views.capture_filter_dialog ^
    --hidden-import=pcapqt.views.display_filter_dialog ^
    --hidden-import=pcapqt.views.capture_source_dialog ^
    --hidden-import=pcapqt.views.conversations_dialog ^
    --hidden-import=pcapqt.views.endpoints_dialog ^
    --hidden-import=pcapqt.views.find_dialog ^
    --hidden-import=pcapqt.views.hex_dump_widget ^
    --hidden-import=pcapqt.views.protocol_hierarchy_dialog ^
    --hidden-import=pcapqt.views.stream_dialog ^
    --hidden-import=pcapqt.utils ^
    --hidden-import=pcapqt.utils.packet_parser ^
    --hidden-import=pcapqt.utils.packet_coloring ^
    --hidden-import=pcapqt.utils.stream_analyzer ^
    --hidden-import=pcapqt.utils.tcp_analyzer ^
    --hidden-import=pcapqt.utils.expert_info ^
    --hidden-import=pcapqt.utils.statistics_calculator ^
    --hidden-import=pcapqt.utils.protocol_parsers ^
    --hidden-import=pcapqt.utils.protocol_parsers.constants ^
    --hidden-import=pcapqt.utils.protocol_parsers.application_parsers ^
    --hidden-import=pcapqt.utils.protocol_parsers.ipv6_parser ^
    --hidden-import=pcapqt.utils.protocol_parsers.icmpv6_parser ^
    --hidden-import=pcapqt.models ^
    --hidden-import=pcapqt.models.packet_table_model ^
    --collect-all=scapy ^
    --collect-submodules=pcapqt ^
    --noupx ^
    pyinstaller_entry.py

if errorlevel 1 (
    echo.
    echo [ERROR] Build thất bại!
    pause
    exit /b 1
)

echo.
echo ========================================
echo   Build thành công!
echo   File exe: dist\PcapQt.exe
echo ========================================
echo.

REM Mở thư mục dist
explorer dist

pause
