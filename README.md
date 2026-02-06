# Turtle Security Scanner

A portable security scanner for Linux/macOS with animated turtle and gamified scoring.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/turtlemoji/turtle-cmd/main/install.sh | bash
```

## Usage

```bash
turtle              # Run full scan with animation
turtle --quiet      # Run without animation
turtle --json       # Output as JSON
turtle --help       # Show help
```

## Features

- Rotating turtle animation during scan
- 22 security checks across 6 categories
- Gamified scoring (0-1400 points)
- Works on Linux and macOS
- No dependencies beyond core utils

## Security Checks

| Category | Checks |
|----------|--------|
| System | Firewall, auto-updates, SIP/SELinux, disk encryption, secure boot |
| SSH | Root login, password auth, port, authorized_keys, protocol |
| User | Passwords, sudo, screen lock, guest account |
| File System | PATH permissions, home dir, SUID files, tmp noexec, umask |
| Network | Open ports, encrypted DNS, listeners, IPv6 privacy |
| Services | Cron jobs, core dumps, kernel hardening |

## Rating Scale

| Score | Rating |
|-------|--------|
| 90%+ | Diamond Shell |
| 75%+ | Shell Guardian |
| 60%+ | Steady Swimmer |
| 40%+ | Soft Shell |
| <40% | Hatchling |
