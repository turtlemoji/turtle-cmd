#!/usr/bin/env bash
#
# Turtle Security Scanner - Installer
#

set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RESET='\033[0m'

info() {
    echo -e "${GREEN}[INFO]${RESET} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${RESET} $1"
}

error() {
    echo -e "${RED}[ERROR]${RESET} $1"
    exit 1
}

# Check if running with sudo/root for system install
check_permissions() {
    if [[ "$INSTALL_DIR" == /usr/* ]] && [[ $EUID -ne 0 ]]; then
        error "Installing to $INSTALL_DIR requires root privileges. Run with sudo."
    fi
}

install_turtle() {
    local source_file="$SCRIPT_DIR/turtle"

    if [[ ! -f "$source_file" ]]; then
        error "turtle script not found in $SCRIPT_DIR"
    fi

    info "Installing turtle to $INSTALL_DIR..."

    # Create install directory if needed
    if [[ ! -d "$INSTALL_DIR" ]]; then
        mkdir -p "$INSTALL_DIR"
    fi

    # Copy or link the script
    if [[ "${LINK:-}" == "1" ]]; then
        ln -sf "$source_file" "$INSTALL_DIR/turtle"
        info "Created symlink: $INSTALL_DIR/turtle -> $source_file"
    else
        cp "$source_file" "$INSTALL_DIR/turtle"
        chmod +x "$INSTALL_DIR/turtle"
        info "Copied turtle to $INSTALL_DIR/turtle"
    fi

    # Verify installation
    if command -v turtle &>/dev/null; then
        info "Installation successful! Run 'turtle' to start scanning."
    else
        warn "Installed to $INSTALL_DIR but it may not be in your PATH."
        warn "Add it to PATH or run directly: $INSTALL_DIR/turtle"
    fi
}

uninstall_turtle() {
    local target="$INSTALL_DIR/turtle"

    if [[ -f "$target" ]] || [[ -L "$target" ]]; then
        rm -f "$target"
        info "Removed $target"
    else
        warn "turtle not found at $target"
    fi
}

show_help() {
    cat << EOF
Turtle Security Scanner - Installer

Usage: ./install.sh [OPTIONS]

Options:
  -h, --help        Show this help message
  -u, --uninstall   Remove turtle from system
  -l, --link        Create symlink instead of copying
  -d, --dir DIR     Install to DIR instead of /usr/local/bin

Examples:
  sudo ./install.sh              Install to /usr/local/bin
  ./install.sh -d ~/.local/bin   Install to user's local bin
  ./install.sh --link            Create symlink (for development)
  sudo ./install.sh --uninstall  Remove turtle

Environment variables:
  INSTALL_DIR   Installation directory (default: /usr/local/bin)
  LINK=1        Create symlink instead of copying
EOF
}

main() {
    local uninstall=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            -u|--uninstall)
                uninstall=true
                shift
                ;;
            -l|--link)
                LINK=1
                shift
                ;;
            -d|--dir)
                INSTALL_DIR="$2"
                shift 2
                ;;
            *)
                error "Unknown option: $1. Use --help for usage."
                ;;
        esac
    done

    check_permissions

    if [[ "$uninstall" == "true" ]]; then
        uninstall_turtle
    else
        install_turtle
    fi
}

main "$@"
