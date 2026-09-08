#!/bin/zsh
# BUGBOUNTY HARNESS launcher (example).
# Auto-detects the harness dir from this script's location.
HARNESS_DIR="$(cd "$(dirname "${0:A}")" && pwd)"
cd "$HARNESS_DIR"

# Setup once:
#   python3 -m venv .venv
#   source .venv/bin/activate
#   pip install -r requirements.txt
#   cp config.example.yaml config.yaml && edit
#   cp scope.example.txt scope.txt && edit

if [ -f ".venv/bin/activate" ]; then
  source .venv/bin/activate
fi
python harness.py --help
echo ""
read "?Press Enter to start the harness (or Ctrl+C to cancel)..."
python harness.py
