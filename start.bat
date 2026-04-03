@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

:: ============================================================================
:: Reactor 性能监控系统 - Windows一键启动脚本
:: ============================================================================

set PORT=%1
if "%PORT%"=="" set PORT=8080

echo.
echo ╔═══════════════════════════════════════════════════════════════╗
echo ║           🚀 Reactor 性能监控系统 - 一键启动                  ║
echo ╚═══════════════════════════════════════════════════════════════╝
echo.

cd /d "%~dp0"

:: 检查并创建必要目录
echo 📁 检查目录结构...
if not exist "output\data" mkdir "output\data"
if not exist "output\logs" mkdir "output\logs"
if not exist "output\charts" mkdir "output\charts"

:: 检查是否有g++编译器
where g++ >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ 未找到g++编译器，请安装MinGW或MSYS2
    echo.
    echo 安装方法:
    echo   1. 下载MSYS2: https://www.msys2.org/
    echo   2. 安装后运行: pacman -S mingw-w64-x86_64-gcc
    echo   3. 添加到PATH: C:\msys64\mingw64\bin
    echo.
    pause
    exit /b 1
)

:: 编译Web服务器
echo 🔨 编译Web服务器...
if exist "src\webserver.cpp" (
    g++ -std=c++11 -O2 -Isrc src\webserver.cpp -o webserver.exe -lws2_32 2>nul
    if %errorlevel% equ 0 (
        echo ✅ Web服务器编译成功
    ) else (
        echo ⚠️ 编译失败，尝试简化编译...
        g++ -std=c++11 -Isrc src\webserver.cpp -o webserver.exe -lws2_32
        if %errorlevel% neq 0 (
            echo ❌ 编译失败，请检查代码
            pause
            exit /b 1
        )
    )
) else (
    echo ❌ 找不到 src\webserver.cpp
    pause
    exit /b 1
)

:: 检查端口是否被占用
netstat -ano | findstr ":%PORT% " | findstr "LISTENING" >nul 2>&1
if %errorlevel% equ 0 (
    echo ⚠️ 端口 %PORT% 已被占用
    for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":%PORT% " ^| findstr "LISTENING"') do (
        echo 正在关闭进程 %%a...
        taskkill /F /PID %%a >nul 2>&1
    )
    timeout /t 2 >nul
)

:: 启动服务器
echo.
echo ═══════════════════════════════════════════════════════════════
echo   🌐 启动Web服务器 (端口: %PORT%)
echo   📍 访问地址: http://localhost:%PORT%
echo ═══════════════════════════════════════════════════════════════
echo.
echo 按 Ctrl+C 停止服务器
echo.

webserver.exe %PORT%

pause
