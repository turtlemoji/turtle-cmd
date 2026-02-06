#!/usr/bin/env bash
# Turtle Security Scanner - Installer
set -euo pipefail

REPO="https://raw.githubusercontent.com/turtlemoji/turtle-cmd/main/turtle"
DEST="${1:-$HOME/.local/bin/turtle}"

mkdir -p "$(dirname "$DEST")"
curl -fsSL "$REPO" -o "$DEST"
chmod +x "$DEST"

echo "🐢 Installed to $DEST"

if ! echo "$PATH" | tr ':' '\n' | grep -qx "$(dirname "$DEST")"; then
    echo "Add to PATH: export PATH=\"$(dirname "$DEST"):\$PATH\""
fi
