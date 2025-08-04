#!/bin/bash

# Security Testing Tool Setup Script
# This script sets up the environment for the security testing tool

set -e  # Exit on error

echo "======================================"
echo "Security Testing Tool Setup"
echo "======================================"
echo ""

# Check Python version
echo "Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
required_version="3.7"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then 
    echo "❌ Error: Python 3.7 or higher is required. Found: $python_version"
    exit 1
else
    echo "✅ Python version $python_version is compatible"
fi

# Create virtual environment
echo ""
echo "Creating virtual environment..."
if [ -d "venv" ]; then
    echo "⚠️  Virtual environment already exists. Removing old environment..."
    rm -rf venv
fi

python3 -m venv venv
echo "✅ Virtual environment created"

# Activate virtual environment
echo ""
echo "Activating virtual environment..."
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    # Windows
    source venv/Scripts/activate
else
    # macOS/Linux
    source venv/bin/activate
fi
echo "✅ Virtual environment activated"

# Upgrade pip
echo ""
echo "Upgrading pip..."
pip install --upgrade pip
echo "✅ pip upgraded"

# Install requirements
echo ""
echo "Installing dependencies..."
pip install -r requirements.txt
echo "✅ Dependencies installed"

# Optional: Install development dependencies
echo ""
read -p "Install development dependencies? (y/n): " install_dev
if [[ $install_dev == "y" || $install_dev == "Y" ]]; then
    echo "Installing development dependencies..."
    pip install -r requirements-dev.txt
    echo "✅ Development dependencies installed"
fi

# Create necessary directories
echo ""
echo "Creating output directories..."
mkdir -p reports
mkdir -p logs
mkdir -p results
echo "✅ Directories created"

# Run a test to verify installation
echo ""
echo "Verifying installation..."
python app.py --help > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✅ Installation verified successfully!"
else
    echo "❌ Installation verification failed. Please check for errors."
    exit 1
fi

echo ""
echo "======================================"
echo "✅ Setup completed successfully!"
echo "======================================"
echo ""
echo "To use the tool:"
echo "1. Activate the virtual environment:"
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    echo "   source venv/Scripts/activate"
else
    echo "   source venv/bin/activate"
fi
echo ""
echo "2. Run the security tester:"
echo "   python app.py <target_url> --confirm [options]"
echo ""
echo "3. For help:"
echo "   python app.py --help"
echo ""
echo "⚠️  Remember: Only test systems you own or have permission to test!"
echo ""