#!/usr/bin/env bash
# Turtle Security Scanner - Installer
set -euo pipefail

REPO="https://raw.githubusercontent.com/turtlemoji/turtle-cmd/main/turtle"

# Pick a directory already in PATH, or fall back to ~/.local/bin
if [[ -w /usr/local/bin ]]; then
    DEST="${1:-/usr/local/bin/turtle}"
else
    DEST="${1:-$HOME/.local/bin/turtle}"
fi

mkdir -p "$(dirname "$DEST")"
curl -fsSL "$REPO" -o "$DEST"
chmod +x "$DEST"

echo "🐢 Installed to $DEST"

if ! echo "$PATH" | tr ':' '\n' | grep -qx "$(dirname "$DEST")"; then
    SHELL_RC="$HOME/.bashrc"
    [[ -n "${ZSH_VERSION:-}" ]] || [[ "$SHELL" == */zsh ]] && SHELL_RC="$HOME/.zshrc"
    echo "export PATH=\"$(dirname "$DEST"):\$PATH\"" >> "$SHELL_RC"
    echo "Added $(dirname "$DEST") to PATH in $(basename "$SHELL_RC")"
    echo "Run: source $SHELL_RC"
fi
