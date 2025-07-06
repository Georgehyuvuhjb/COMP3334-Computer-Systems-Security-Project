@echo off
REM RPG Game Launcher Script for Windows

echo Starting Text-Based RPG Adventure Game...
echo ==========================================

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3.6 or higher to run this game.
    echo Visit https://python.org to download Python.
    pause
    exit /b 1
)

REM Check Python version
echo Checking Python version...
python --version

REM Change to the script directory
cd /d "%~dp0"

REM Run the RPG game
echo Launching RPG Game...
echo Press Ctrl+C to exit the game at any time.
echo.

python rpg_game.py

REM Pause so user can see any error messages
if %errorlevel% neq 0 (
    echo.
    echo Game exited with an error.
    pause
)