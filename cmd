#!/usr/bin/env bash

set -euo pipefail

VERSION="1.0.0"

# ═══════════════════════════════════════════════════════════════════════════════
# OS DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

detect_os() {
    OS="$(uname -s)"
    case "$OS" in
        Linux)  OS_TYPE="linux" ;;
        Darwin) OS_TYPE="macos" ;;
        *)      OS_TYPE="unknown" ;;
    esac

    # macOS doesn't have timeout (GNU coreutils)
    if ! command -v timeout &>/dev/null; then
        if command -v gtimeout &>/dev/null; then
            timeout() { gtimeout "$@"; }
        else
            # Use perl's alarm() as timeout - perl is always on macOS
            timeout() { command perl -e 'alarm shift; exec @ARGV' "$@"; }
        fi
    fi
}


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

main() {

    # Setup
    detect_os

    if [[ "$OS_TYPE" == "unknown" ]]; then
        echo -e "${RED}Error: Unsupported operating system${RESET}"
        exit 1
    fi

    echo "HI"

    sleep 5

}

# Cleanup on exit
cleanup() {
    tput cnorm 2>/dev/null || true
}
trap cleanup EXIT

# Run main
main "$@"
