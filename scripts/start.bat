@echo off
REM Windows startup script for PCS

echo Starting Perfect Charity System...
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.11 or higher
    pause
    exit /b 1
)

REM Check if dependencies are installed
echo Checking dependencies...
pip show fastapi >nul 2>&1
if errorlevel 1 (
    echo Installing dependencies...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo ERROR: Failed to install dependencies
        pause
        exit /b 1
    )
)

echo.
echo ========================================
echo   Perfect Charity System (PCS)
echo ========================================
echo.
echo Starting server...
echo Access the website at: http://localhost:8000
echo Default admin login: admin / admin
echo.
echo Press Ctrl+C to stop the server
echo.

python pcs-website.py
