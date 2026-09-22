#!/usr/bin/env bash
set -euo pipefail

if command -v python3.13 >/dev/null 2>&1; then
  PYTHON_BIN="python3.13"
elif command -v python3.12 >/dev/null 2>&1; then
  PYTHON_BIN="python3.12"
else
  PYTHON_BIN="python3"
fi

$PYTHON_BIN -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

echo
echo "Local target environment ready."
echo "Start it with: ./start_target.sh"
