#!/bin/bash
# RPG Game Launcher Script

echo "Starting Text-Based RPG Adventure Game..."
echo "=========================================="

# Check if Python 3 is available
if command -v python3 &> /dev/null; then
    PYTHON_CMD=python3
elif command -v python &> /dev/null; then
    PYTHON_CMD=python
else
    echo "Error: Python is not installed or not in PATH"
    echo "Please install Python 3.6 or higher to run this game."
    exit 1
fi

# Check Python version
echo "Checking Python version..."
$PYTHON_CMD --version

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Change to the script directory
cd "$SCRIPT_DIR"

# Run the RPG game
echo "Launching RPG Game..."
echo "Press Ctrl+C to exit the game at any time."
echo ""

$PYTHON_CMD rpg_game.py