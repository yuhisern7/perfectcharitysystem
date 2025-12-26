#!/bin/bash
# Linux/Mac startup script for PCS

echo "Starting Perfect Charity System..."
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed"
    echo "Please install Python 3.11 or higher"
    exit 1
fi

# Check if dependencies are installed
echo "Checking dependencies..."
if ! python3 -c "import fastapi" &> /dev/null; then
    echo "Installing dependencies..."
    pip3 install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to install dependencies"
        exit 1
    fi
fi

echo ""
echo "========================================"
echo "  Perfect Charity System (PCS)"
echo "========================================"
echo ""
echo "Starting server..."
echo "Access the website at: http://localhost:8000"
echo "Default admin login: admin / admin"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

python3 pcs-website.py
