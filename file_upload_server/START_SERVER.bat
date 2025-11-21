@echo off
title File Upload Server
color 0A

echo.
echo ========================================
echo   File Upload Server - Dark Mode
echo ========================================
echo.

REM Check if virtual environment exists
if not exist "venv" (
    echo [ERROR] Virtual environment not found!
    echo Please run INSTALL.bat first.
    echo.
    pause
    exit /b 1
)

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Check if Flask is installed
python -c "import flask" 2>nul
if errorlevel 1 (
    echo [ERROR] Flask not installed!
    echo Please run INSTALL.bat first.
    echo.
    pause
    exit /b 1
)

REM Start the server
echo Starting server...
echo.
echo Server will be available at:
echo http://localhost:5000
echo.
echo Press Ctrl+C to stop the server
echo.
python server.py

REM If server stops
echo.
echo Server stopped.
pause
