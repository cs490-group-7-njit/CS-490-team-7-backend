#!/bin/bash
# Activate virtual environment and run commands

cd /home/shark/GP/CS-490-team-7-backend
source venv/bin/activate

# Run the command passed as argument, or start interactive shell
if [ $# -eq 0 ]; then
    echo "Virtual environment activated. Available commands:"
    echo "  python run.py     - Start the Flask server"
    echo "  pytest           - Run tests"
    echo "  pip list         - Show installed packages"
    bash
else
    "$@"
fi