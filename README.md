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

- Hacker-style animated turtle with matrix rain, binary, hex dump, and glitch effects
- 55+ security checks across 10 categories
- Infostealer target detection (crypto wallets, session tokens, dev credentials)
- Breach detection via XposedOrNot API
- Public port exposure scanning
- Rootkit indicator detection
- Gamified scoring with penalties for bad findings
- Works on Linux and macOS
- No dependencies beyond core utils + curl

## Security Checks

| Category | Checks |
|----------|--------|
| System | Firewall, auto-updates, SIP/SELinux, disk encryption, secure boot |
| SSH | Root login, password auth, port, authorized_keys, protocol |
| User | Passwords, sudo, screen lock, guest account |
| File System | PATH permissions, home dir, SUID files, tmp noexec, umask, .env files |
| Secrets & Creds | History secrets (API keys, crypto keys, seed phrases), cloud creds, private keys, shell config, git creds, SSH agent, Docker socket, dev tokens (npm/pypi/kube/docker/terraform), crypto wallets, app sessions (Discord/Slack/Telegram), VPN/WiFi configs, GPG keys, password vaults |
| Network | Open ports, encrypted DNS, IPv6 privacy |
| Services | Cron jobs, core dumps, kernel hardening |
| Hardening | Failed logins, exposed services, USB automount, Bluetooth, WiFi auto-connect |
| Best Practices | Password manager, git signing, security updates, swap encryption, kernel, SSH key audit, backup encryption, package vulnerabilities |
| Privacy | Hostname privacy, login banner info leak, browser/VS Code telemetry, MAC randomization |
| Advanced | ARP spoofing protection, email breach check, public port exposure, rootkit indicators |

## Rating Scale

| Score | Rating |
|-------|--------|
| 90%+ | Diamond Shell |
| 75%+ | Shell Guardian |
| 60%+ | Steady Swimmer |
| 40%+ | Soft Shell |
| <40% | Hatchling |
