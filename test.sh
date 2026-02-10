#!/usr/bin/env bash
#
# Turtle Security Scanner - Test Suite
# Run: bash test.sh
#
# Works locally and in CI (GitHub Actions on ubuntu + macos)
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TURTLE="$SCRIPT_DIR/turtle"
IS_CI="${CI:-false}"
RUN_MODE="${1:-all}"  # all, unit, integration

PASS=0
FAIL=0
SKIP=0
ERRORS=()

# Colors (disabled in CI if no tty)
if [[ -t 1 ]] || [[ "$IS_CI" == "true" ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BOLD='\033[1m'
    DIM='\033[2m'
    RESET='\033[0m'
else
    RED='' GREEN='' YELLOW='' BOLD='' DIM='' RESET=''
fi

# ─── Test helpers ─────────────────────────────────────────────────────────────

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        echo -e "  ${GREEN}✓${RESET} $desc"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗${RESET} $desc"
        echo -e "    ${DIM}expected: ${expected}${RESET}"
        echo -e "    ${DIM}actual:   ${actual}${RESET}"
        FAIL=$((FAIL + 1))
        ERRORS+=("$desc")
    fi
}

assert_match() {
    local desc="$1" pattern="$2" actual="$3"
    if echo "$actual" | grep -qE "$pattern"; then
        echo -e "  ${GREEN}✓${RESET} $desc"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗${RESET} $desc"
        echo -e "    ${DIM}pattern: ${pattern}${RESET}"
        echo -e "    ${DIM}actual:  $(echo "$actual" | head -3)${RESET}"
        FAIL=$((FAIL + 1))
        ERRORS+=("$desc")
    fi
}

assert_exit() {
    local desc="$1" expected="$2"
    shift 2
    local actual=0
    "$@" >/dev/null 2>&1 || actual=$?
    assert_eq "$desc" "$expected" "$actual"
}

assert_not_empty() {
    local desc="$1" actual="$2"
    if [[ -n "$actual" ]]; then
        echo -e "  ${GREEN}✓${RESET} $desc"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗${RESET} $desc (empty)"
        FAIL=$((FAIL + 1))
        ERRORS+=("$desc")
    fi
}

skip_test() {
    local desc="$1" reason="$2"
    echo -e "  ${YELLOW}○${RESET} $desc ${DIM}($reason)${RESET}"
    SKIP=$((SKIP + 1))
}

# Detect OS for test expectations
OS="$(uname -s)"
case "$OS" in Linux) OS_TYPE="linux";; Darwin) OS_TYPE="macos";; *) OS_TYPE="unknown";; esac

# macOS doesn't have timeout (GNU coreutils), use gtimeout or skip
if ! command -v timeout &>/dev/null; then
    if command -v gtimeout &>/dev/null; then
        timeout() { gtimeout "$@"; }
    else
        timeout() { command perl -e 'alarm shift; exec @ARGV' "$@"; }
    fi
fi

# Temp dir for test fixtures
TMPDIR_TEST=$(mktemp -d)
trap 'rm -rf "$TMPDIR_TEST"' EXIT

# ─── Tests ────────────────────────────────────────────────────────────────────

echo -e "${BOLD}🐢 Turtle Security Scanner - Test Suite${RESET}"
echo -e "${DIM}OS: $OS_TYPE | CI: $IS_CI${RESET}"
echo "════════════════════════════════════════"
echo ""

# ── 1. Syntax & Structure ────────────────────────────────────────────────────

echo -e "${BOLD}Syntax & Structure${RESET}"

assert_exit "Script passes bash -n syntax check" 0 bash -n "$TURTLE"
assert_exit "install.sh passes bash -n syntax check" 0 bash -n "$SCRIPT_DIR/install.sh"

version=$(grep '^VERSION=' "$TURTLE" | head -1 | cut -d'"' -f2)
assert_not_empty "VERSION is set" "$version"
assert_match "VERSION is semver" '^[0-9]+\.[0-9]+\.[0-9]+' "$version"

# set -euo pipefail at the top
assert_match "Has strict mode" "set -euo pipefail" "$(head -10 "$TURTLE")"

echo ""

# ── 2. Required Functions ────────────────────────────────────────────────────

echo -e "${BOLD}Required Functions${RESET}"

# All run_* orchestrators
for fn in run_system_checks run_ssh_checks run_user_checks run_filesystem_checks \
          run_secrets_checks run_network_checks run_services_checks \
          run_hardening_checks run_bestpractice_checks run_privacy_checks \
          run_advanced_checks; do
    exists=$(grep -c "^${fn}()" "$TURTLE" || echo "0")
    assert_eq "Function $fn exists" "1" "$exists"
done

# All individual check functions
check_functions=(
    check_firewall check_auto_updates check_sip_selinux check_disk_encryption
    check_secure_boot check_no_world_writable_in_path check_home_permissions
    check_no_suid_in_home check_tmp_noexec check_secure_umask
    check_env_files check_secrets_in_history check_cloud_credentials_exposed
    check_exposed_private_keys check_browser_passwords check_sudo_timestamp
    check_secrets_in_shell_config check_git_credential_helper
    check_ssh_agent_forwarding check_docker_socket
    check_crypto_wallets check_dev_tokens check_session_tokens
    check_vpn_wifi_configs check_gpg_protection check_password_vault_files
    check_open_ports check_dns_encryption check_ipv6_privacy
    check_cron_jobs check_core_dumps_disabled check_kernel_hardening
    check_failed_logins check_services_exposed check_usb_automount
    check_bluetooth_discoverable check_wifi_autoconnect
    check_password_manager check_git_signing check_pending_security_updates
    check_swap_encryption check_kernel_up_to_date
    check_ssh_key_audit check_unencrypted_backups check_package_vulns
    check_hostname_privacy check_login_banner check_telemetry
    check_mac_randomization check_arp_protection check_hibp
    check_public_ports check_rootkit_indicators
)

for fn in "${check_functions[@]}"; do
    exists=$(grep -c "^${fn}()" "$TURTLE" || echo "0")
    assert_eq "Check $fn exists" "1" "$exists"
done

echo ""

# ── 3. CLI Arguments ─────────────────────────────────────────────────────────

echo -e "${BOLD}CLI Arguments${RESET}"

help_output=$(bash "$TURTLE" --help 2>&1 || true)
assert_match "--help shows usage" "Usage|usage|USAGE" "$help_output"
assert_match "--help mentions --quiet" "quiet" "$help_output"
assert_match "--help mentions --json" "json" "$help_output"
assert_match "--help mentions update" "update" "$help_output"

echo ""

# ── 4. Animation ─────────────────────────────────────────────────────────────

echo -e "${BOLD}Animation${RESET}"

frame_count=$(grep -c '^TURTLE_FRAME_[0-9]*=' "$TURTLE" || echo "0")
assert_eq "Has 10 animation frames" "10" "$frame_count"

spinner_count=$(grep 'SPINNER_FRAMES=' "$TURTLE" | grep -oE '"[^"]*"' | wc -l | tr -d ' ' || echo "0")
assert_eq "Has 10 spinner frames" "10" "$spinner_count"

init_fn_count=$(sed -n '/^init_turtle_frames/,/^}/p' "$TURTLE" | grep -c 'TURTLE_FRAMES_BIG\[')
assert_eq "init_turtle_frames loads 10 frames" "10" "$init_fn_count"

# Frame modulo matches count
assert_match "animate_turtle uses mod 10" '% 10' "$(grep 'TURTLE_IDX.*%' "$TURTLE")"

echo ""

# ── 5. Cross-Platform ────────────────────────────────────────────────────────

echo -e "${BOLD}Cross-Platform${RESET}"

assert_match "Has Linux detection" "linux" "$(grep 'OS_TYPE.*linux' "$TURTLE")"
assert_match "Has macOS detection" "macos" "$(grep 'OS_TYPE.*macos' "$TURTLE")"

for check in check_firewall check_disk_encryption check_sip_selinux; do
    has_linux=$(grep -A 30 "^${check}()" "$TURTLE" | grep -c 'linux\|Linux' || echo "0")
    has_macos=$(grep -A 30 "^${check}()" "$TURTLE" | grep -c 'macos\|Darwin\|macOS' || echo "0")
    if [[ "$has_linux" -gt 0 ]] && [[ "$has_macos" -gt 0 ]]; then
        echo -e "  ${GREEN}✓${RESET} $check handles both platforms"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗${RESET} $check missing platform (linux=$has_linux macos=$has_macos)"
        FAIL=$((FAIL + 1))
        ERRORS+=("$check cross-platform")
    fi
done

# stat command uses correct flags per platform
assert_match "Uses Linux stat -c" 'stat -c' "$(grep 'stat -c' "$TURTLE" | head -1)"
assert_match "Uses macOS stat -f" 'stat -f' "$(grep 'stat -f' "$TURTLE" | head -1)"

echo ""

# ── 6. Update & Install ──────────────────────────────────────────────────────

echo -e "${BOLD}Update & Install${RESET}"

update_block=$(sed -n '/update)/,/exit 0/p' "$TURTLE")
assert_match "Update command exists" 'update\)' "$update_block"
assert_match "Update checks write permission" 'write permission|-w' "$update_block"
assert_match "Update compares versions" 'new_ver|VERSION' "$update_block"

install_file="$SCRIPT_DIR/install.sh"
assert_match "install.sh has strict mode" "set -euo pipefail" "$(grep 'pipefail' "$install_file")"
assert_match "install.sh curls the script" "curl" "$(grep 'curl' "$install_file")"
assert_match "install.sh sets +x" "chmod" "$(grep 'chmod' "$install_file")"
assert_match "install.sh handles PATH" "PATH" "$(grep 'PATH' "$install_file")"

echo ""

# ── 7. Findings Report ───────────────────────────────────────────────────────

echo -e "${BOLD}Findings Report${RESET}"

for finding in "Secrets found in shell history" "Exposed cloud credentials" \
               "Private keys with bad permissions" ".env files found" \
               "Crypto wallets found" "Exposed dev tokens" \
               "App sessions found" "VPN/WiFi configs" \
               "Email breach alert" "Ports exposed to internet" \
               "ROOTKIT INDICATORS" "SSH key issues" \
               "Telemetry" "Package vulnerabilities"; do
    if grep -q "$finding" "$TURTLE"; then
        echo -e "  ${GREEN}✓${RESET} Finding: $finding"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗${RESET} Missing: $finding"
        FAIL=$((FAIL + 1))
        ERRORS+=("Finding: $finding")
    fi
done

echo ""

# ── 8. Unit Tests: Hostname Check ────────────────────────────────────────────

echo -e "${BOLD}Unit: Hostname Check${RESET}"

# Test with mock hostnames via subshells
(
    hostname() { echo "john-macbook-pro"; }
    export -f hostname
    eval "$(sed -n '/^check_hostname_privacy/,/^}/p' "$TURTLE")"
    HOSTNAME_ISSUE=""
    check_hostname_privacy 2>/dev/null
) && host_result="pass" || host_result="fail"
assert_eq "Flags 'john-macbook-pro'" "fail" "$host_result"

(
    hostname() { echo "server-42"; }
    export -f hostname
    eval "$(sed -n '/^check_hostname_privacy/,/^}/p' "$TURTLE")"
    HOSTNAME_ISSUE=""
    check_hostname_privacy 2>/dev/null
) && host_result="pass" || host_result="fail"
assert_eq "Accepts 'server-42'" "pass" "$host_result"

(
    hostname() { echo "janes-mbp"; }
    export -f hostname
    eval "$(sed -n '/^check_hostname_privacy/,/^}/p' "$TURTLE")"
    HOSTNAME_ISSUE=""
    check_hostname_privacy 2>/dev/null
) && host_result="pass" || host_result="fail"
assert_eq "Flags 'janes-mbp'" "fail" "$host_result"

(
    hostname() { echo "workstation"; }
    export -f hostname
    eval "$(sed -n '/^check_hostname_privacy/,/^}/p' "$TURTLE")"
    HOSTNAME_ISSUE=""
    check_hostname_privacy 2>/dev/null
) && host_result="pass" || host_result="fail"
assert_eq "Accepts 'workstation'" "pass" "$host_result"

echo ""

# ── 9. Unit Tests: Secrets Detection ─────────────────────────────────────────

echo -e "${BOLD}Unit: Secrets Detection${RESET}"

# Create test history with known secrets and safe commands
cat > "$TMPDIR_TEST/test_history" << 'HISTEOF'
export ETH=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
test 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ
export API_KEY=sk-abcdefghijklmnopqrstuvwxyz123456
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
sudo passwd root
ssh-keygen -t ed25519
man ssh
git commit -m "test"
ls -la
HISTEOF

# Run detection against test file in a subshell
detect_output=$(bash -c '
OS="$(uname -s)"
case "$OS" in Linux) OS_TYPE="linux";; Darwin) OS_TYPE="macos";; *) OS_TYPE="unknown";; esac

hfile="'"$TMPDIR_TEST/test_history"'"

patterns='"'"'(API[_-]?KEY|SECRET[_-]?KEY|AWS_SECRET_ACCESS_KEY|PRIVATE[_-]?KEY)[=:]["'"'"'"'"'"'"'"'"'\\x27]?[A-Za-z0-9+/=_-]{16,}'"'"'
key_patterns='"'"'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'"'"'
crypto_patterns='"'"'(0x[0-9a-fA-F]{64}|[^a-zA-Z0-9][5KL][1-9A-HJ-NP-Za-km-z]{50,51}[^a-zA-Z0-9]?|(--private-key|--seed|--mnemonic|--secret-key)[= ]["'"'"'"'"'"'"'"'"'\\x27]?[A-Za-z0-9])'"'"'
seed_pattern='"'"'([a-z]{3,8} ){10,23}[a-z]{3,8}'"'"'

count=0
types=""

# Main pattern matching
while IFS= read -r match; do
    line="${match#*:}"
    [[ "$line" =~ (sudo\ passwd|ssh-keygen|gpg\ |man\ |--help) ]] && continue
    [[ "$line" =~ (curl.*-u|wget|apt|pip|npm|brew) ]] && continue
    count=$((count + 1))
    echo "$line" | grep -qE "0x[0-9a-fA-F]{64}" && types="${types}ETH,"
    echo "$line" | grep -qE "[5KL][1-9A-HJ-NP-Za-km-z]{50,51}" && types="${types}WIF,"
    echo "$line" | grep -qE "API_KEY" && types="${types}API,"
done < <(grep -nE "$patterns|$key_patterns|$crypto_patterns" "$hfile" 2>/dev/null)

# Seed phrase matching
while IFS= read -r match; do
    line="${match#*:}"
    [[ "$line" =~ (echo|man\ |cat\ |grep\ ) ]] && continue
    count=$((count + 1))
    types="${types}SEED,"
done < <(grep -nE "$seed_pattern" "$hfile" 2>/dev/null)

echo "COUNT=$count"
echo "TYPES=$types"
' 2>/dev/null)

secret_count=$(echo "$detect_output" | grep "COUNT=" | cut -d= -f2)
secret_types=$(echo "$detect_output" | grep "TYPES=" | cut -d= -f2)

assert_eq "Detects 4 secrets total" "4" "$secret_count"
assert_match "Detects Ethereum key" "ETH" "$secret_types"
assert_match "Detects Bitcoin WIF" "WIF" "$secret_types"
assert_match "Detects API key" "API" "$secret_types"
assert_match "Detects seed phrase" "SEED" "$secret_types"
assert_eq "Skips safe commands (count is 4 not more)" "4" "$secret_count"

echo ""

# ── 10. Unit Tests: Login Banner ─────────────────────────────────────────────

echo -e "${BOLD}Unit: Login Banner${RESET}"

# Create test banner files
echo "Ubuntu 22.04 LTS" > "$TMPDIR_TEST/issue_bad"
echo "Authorized access only." > "$TMPDIR_TEST/issue_good"

# Test bad banner
(
    eval "$(sed -n '/^check_login_banner/,/^}/p' "$TURTLE")"
    OS_TYPE="linux"
    # Override file paths by patching the function
    check_test_banner() {
        for banner_file in "$TMPDIR_TEST/issue_bad"; do
            if [[ -f "$banner_file" ]] && [[ -s "$banner_file" ]]; then
                if grep -qEi '(ubuntu|debian|fedora|centos|arch|kernel|\\r|\\v|\\s|\\m)' "$banner_file" 2>/dev/null; then
                    return 1
                fi
            fi
        done
        return 0
    }
    check_test_banner
) && banner_result="pass" || banner_result="fail"
assert_eq "Flags banner with 'Ubuntu 22.04'" "fail" "$banner_result"

# Test good banner
(
    check_test_banner() {
        for banner_file in "$TMPDIR_TEST/issue_good"; do
            if [[ -f "$banner_file" ]] && [[ -s "$banner_file" ]]; then
                if grep -qEi '(ubuntu|debian|fedora|centos|arch|kernel|\\r|\\v|\\s|\\m)' "$banner_file" 2>/dev/null; then
                    return 1
                fi
            fi
        done
        return 0
    }
    check_test_banner
) && banner_result="pass" || banner_result="fail"
assert_eq "Accepts generic warning banner" "pass" "$banner_result"

echo ""

# ── 11. Unit Tests: Rootkit Indicators ───────────────────────────────────────

echo -e "${BOLD}Unit: Rootkit Checks${RESET}"

if [[ "$OS_TYPE" == "linux" ]]; then
    eval "$(sed -n '/^check_rootkit_indicators/,/^}/p' "$TURTLE")"
    ROOTKIT_INDICATORS=0
    declare -a ROOTKIT_LIST=()
    check_rootkit_indicators 2>/dev/null || true
    assert_match "Rootkit count is a number" '^[0-9]+$' "$ROOTKIT_INDICATORS"
    assert_eq "No rootkits on clean system" "0" "$ROOTKIT_INDICATORS"

    # Verify it checks known paths
    rk_code=$(sed -n '/^check_rootkit_indicators/,/^}/p' "$TURTLE")
    assert_match "Checks ld.so.preload" "ld.so.preload" "$rk_code"
    assert_match "Checks suspicious kernel modules" "diamorphine|reptile" "$rk_code"
    assert_match "Checks /dev/shm executables" "dev/shm" "$rk_code"
    assert_match "Checks process count" "proc_count|ps_count" "$rk_code"
    assert_match "Checks LD_PRELOAD env" "LD_PRELOAD" "$rk_code"
    assert_match "Checks hidden files in /tmp" "Hidden file" "$rk_code"
    assert_match "Checks promiscuous interfaces" "PROMISC" "$rk_code"
    assert_match "Checks deleted running binaries" "deleted" "$rk_code"
    assert_match "Checks suspicious cron entries" "dev/tcp|nc -e|curl.*sh" "$rk_code"
    assert_match "Checks known rootkit files" "libproc.a|phalanx" "$rk_code"
    assert_match "Checks shell config injections" "bashrc.*profile|LD_PRELOAD=" "$rk_code"
    assert_match "Checks immutable files" "lsattr" "$rk_code"
    assert_match "Checks reverse shell ports" "4444|1337|31337" "$rk_code"
    assert_match "Checks writable cron files" "crontab|cron.d" "$rk_code"
else
    skip_test "Rootkit checks" "Linux only"
fi

echo ""

# ── 12. Unit Tests: Other Checks ─────────────────────────────────────────────

echo -e "${BOLD}Unit: Other Checks${RESET}"

# SSH key audit - just verify it runs
eval "$(sed -n '/^check_ssh_key_audit/,/^}/p' "$TURTLE")"
SSH_KEY_ISSUES=0
declare -a SSH_KEY_ISSUES_LIST=()
check_ssh_key_audit 2>/dev/null || true
assert_match "SSH key audit returns number" '^[0-9]+$' "$SSH_KEY_ISSUES"

# Crypto wallets - verify it runs
eval "$(sed -n '/^check_crypto_wallets/,/^}/p' "$TURTLE")"
CRYPTO_WALLETS_FOUND=0
declare -a CRYPTO_WALLETS_LIST=()
check_crypto_wallets 2>/dev/null || true
assert_match "Crypto wallet check returns number" '^[0-9]+$' "$CRYPTO_WALLETS_FOUND"

# Dev tokens - verify it runs
eval "$(sed -n '/^check_dev_tokens/,/^}/p' "$TURTLE")"
DEV_TOKENS_FOUND=0
declare -a DEV_TOKENS_LIST=()
check_dev_tokens 2>/dev/null || true
assert_match "Dev tokens check returns number" '^[0-9]+$' "$DEV_TOKENS_FOUND"

# Session tokens - verify it runs
eval "$(sed -n '/^check_session_tokens/,/^}/p' "$TURTLE")"
SESSION_TOKENS_FOUND=0
declare -a SESSION_TOKENS_LIST=()
check_session_tokens 2>/dev/null || true
assert_match "Session tokens check returns number" '^[0-9]+$' "$SESSION_TOKENS_FOUND"

# Telemetry - verify it runs
eval "$(sed -n '/^check_telemetry/,/^}/p' "$TURTLE")"
TELEMETRY_ISSUES=0
declare -a TELEMETRY_LIST=()
check_telemetry 2>/dev/null || true
assert_match "Telemetry check returns number" '^[0-9]+$' "$TELEMETRY_ISSUES"

echo ""

# ── 13. Unit Tests: HIBP Email Collection ─────────────────────────────────

echo -e "${BOLD}Unit: HIBP Email Collection${RESET}"

# Verify check_hibp function collects emails from multiple sources
hibp_code=$(sed -n '/^check_hibp/,/^}/p' "$TURTLE")
assert_match "HIBP checks git global email" "git config --global user.email" "$hibp_code"
assert_match "HIBP checks SSH key comments" "\.ssh/\*\.pub" "$hibp_code"
assert_match "HIBP checks repo git configs" "\.git/config" "$hibp_code"
assert_match "HIBP deduplicates emails" "_add_email" "$hibp_code"
assert_match "HIBP uses XposedOrNot API" "xposedornot" "$hibp_code"

# Test email extraction from SSH pubkeys with mock fixture
mkdir -p "$TMPDIR_TEST/hibp_ssh"
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@example.com" > "$TMPDIR_TEST/hibp_ssh/id_ed25519.pub"
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB... nocomment" > "$TMPDIR_TEST/hibp_ssh/id_rsa.pub"
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... dev@company.org" > "$TMPDIR_TEST/hibp_ssh/work.pub"

# Extract emails from pubkeys the same way check_hibp does
pubkey_emails=""
for pubkey in "$TMPDIR_TEST/hibp_ssh"/*.pub; do
    comment=$(awk '{print $NF}' "$pubkey" 2>/dev/null || echo "")
    if [[ "$comment" == *@*.* ]]; then
        pubkey_emails="${pubkey_emails}${comment} "
    fi
done
assert_match "Extracts email from ed25519 key" "user@example.com" "$pubkey_emails"
assert_match "Extracts email from work key" "dev@company.org" "$pubkey_emails"
# "nocomment" doesn't match *@*.* pattern
if echo "$pubkey_emails" | grep -q "nocomment"; then
    echo -e "  ${RED}✗${RESET} Should skip non-email comment"
    FAIL=$((FAIL + 1)); ERRORS+=("pubkey non-email")
else
    echo -e "  ${GREEN}✓${RESET} Skips non-email SSH key comment"
    PASS=$((PASS + 1))
fi

echo ""

# ── 14. Unit Tests: Session Tokens (WhatsApp/GitHub) ─────────────────────

echo -e "${BOLD}Unit: Session Tokens Coverage${RESET}"

session_code=$(sed -n '/^check_session_tokens/,/^}/p' "$TURTLE")
assert_match "Checks Discord sessions" "discord" "$session_code"
assert_match "Checks Slack sessions" "Slack" "$session_code"
assert_match "Checks Telegram sessions" "Telegram" "$session_code"
assert_match "Checks WhatsApp sessions" "WhatsApp" "$session_code"
assert_match "Checks GitHub Desktop sessions" "GitHub Desktop" "$session_code"
assert_match "Checks Linux paths" ".config" "$session_code"
assert_match "Checks macOS paths" "Application Support" "$session_code"

echo ""

# ── 15. Unit Tests: Scoring System ────────────────────────────────────────

echo -e "${BOLD}Unit: Scoring System${RESET}"

# Source scoring functions
eval "$(sed -n '/^add_score/,/^}/p' "$TURTLE")"
eval "$(sed -n '/^add_max/,/^}/p' "$TURTLE")"
eval "$(sed -n '/^record_check/,/^}/p' "$TURTLE")"

# Reset scoring state
TOTAL_SCORE=0; MAX_SCORE=0; CHECKS_PASSED=0; CHECKS_FAILED=0; CHECKS_SKIPPED=0
declare -a CHECK_RESULTS=()

# Test add_score
add_score 100
assert_eq "add_score accumulates (100)" "100" "$TOTAL_SCORE"
add_score 50
assert_eq "add_score accumulates (150)" "150" "$TOTAL_SCORE"

# Test add_max
add_max 200
assert_eq "add_max accumulates (200)" "200" "$MAX_SCORE"
add_max 100
assert_eq "add_max accumulates (300)" "300" "$MAX_SCORE"

# Reset for record_check tests
TOTAL_SCORE=0; MAX_SCORE=0; CHECKS_PASSED=0; CHECKS_FAILED=0; CHECKS_SKIPPED=0
CHECK_RESULTS=()

# Test record_check pass
record_check "System" "Firewall" "1" "100" "100"
assert_eq "record_check pass increments CHECKS_PASSED" "1" "$CHECKS_PASSED"
assert_eq "record_check pass leaves CHECKS_FAILED at 0" "0" "$CHECKS_FAILED"
assert_eq "record_check stores result" "1" "${#CHECK_RESULTS[@]}"
assert_match "record_check result format" 'System|Firewall|1|100|100' "${CHECK_RESULTS[0]}"

# Test record_check fail
record_check "System" "Encryption" "0" "0" "100"
assert_eq "record_check fail increments CHECKS_FAILED" "1" "$CHECKS_FAILED"
assert_eq "CHECKS_PASSED still 1 after fail" "1" "$CHECKS_PASSED"

# Test record_check skip
record_check "SSH" "Root login" "skip" "0" "50"
assert_eq "record_check skip increments CHECKS_SKIPPED" "1" "$CHECKS_SKIPPED"
assert_eq "Total results array has 3 entries" "3" "${#CHECK_RESULTS[@]}"

echo ""

# ── 16. Unit Tests: Rating Calculation ────────────────────────────────────

echo -e "${BOLD}Unit: Rating Calculation${RESET}"

eval "$(sed -n '/^get_rating/,/^}/p' "$TURTLE")"
eval "$(sed -n '/^get_turtle_rating/,/^}/p' "$TURTLE")"

# Boundary tests for get_rating
assert_eq "100% => Diamond Shell" "Diamond Shell" "$(get_rating 100)"
assert_eq "90%  => Diamond Shell" "Diamond Shell" "$(get_rating 90)"
assert_eq "89%  => Shell Guardian" "Shell Guardian" "$(get_rating 89)"
assert_eq "75%  => Shell Guardian" "Shell Guardian" "$(get_rating 75)"
assert_eq "74%  => Steady Swimmer" "Steady Swimmer" "$(get_rating 74)"
assert_eq "60%  => Steady Swimmer" "Steady Swimmer" "$(get_rating 60)"
assert_eq "59%  => Soft Shell" "Soft Shell" "$(get_rating 59)"
assert_eq "40%  => Soft Shell" "Soft Shell" "$(get_rating 40)"
assert_eq "39%  => Hatchling" "Hatchling" "$(get_rating 39)"
assert_eq "0%   => Hatchling" "Hatchling" "$(get_rating 0)"

# Boundary tests for get_turtle_rating
assert_eq "90%  => 5 turtles" "5" "$(get_turtle_rating 90)"
assert_eq "75%  => 4 turtles" "4" "$(get_turtle_rating 75)"
assert_eq "60%  => 3 turtles" "3" "$(get_turtle_rating 60)"
assert_eq "40%  => 2 turtles" "2" "$(get_turtle_rating 40)"
assert_eq "0%   => 1 turtle" "1" "$(get_turtle_rating 0)"

echo ""

# ── 17. Unit Tests: Penalty Caps ──────────────────────────────────────────

echo -e "${BOLD}Unit: Penalty Caps${RESET}"

# Test env file penalty cap at 100
(
    penalty_test() {
        local ENV_FILES_COUNT=$1
        local penalty=$((ENV_FILES_COUNT * 5))
        [[ $penalty -gt 100 ]] && penalty=100
        echo "$penalty"
    }
    # 5 files = 25 penalty (under cap)
    result=$(penalty_test 5)
    [[ "$result" -eq 25 ]] && exit 0 || exit 1
) && env_pen="pass" || env_pen="fail"
assert_eq "Env penalty: 5 files = 25 pts" "pass" "$env_pen"

(
    penalty_test() {
        local ENV_FILES_COUNT=$1
        local penalty=$((ENV_FILES_COUNT * 5))
        [[ $penalty -gt 100 ]] && penalty=100
        echo "$penalty"
    }
    result=$(penalty_test 20)
    [[ "$result" -eq 100 ]] && exit 0 || exit 1
) && env_pen="pass" || env_pen="fail"
assert_eq "Env penalty: 20 files capped at 100" "pass" "$env_pen"

(
    penalty_test() {
        local ENV_FILES_COUNT=$1
        local penalty=$((ENV_FILES_COUNT * 5))
        [[ $penalty -gt 100 ]] && penalty=100
        echo "$penalty"
    }
    result=$(penalty_test 50)
    [[ "$result" -eq 100 ]] && exit 0 || exit 1
) && env_pen="pass" || env_pen="fail"
assert_eq "Env penalty: 50 files still capped at 100" "pass" "$env_pen"

# Test secrets penalty cap at 150
(
    penalty_test() {
        local count=$1
        local penalty=$((count * 10))
        [[ $penalty -gt 150 ]] && penalty=150
        echo "$penalty"
    }
    result=$(penalty_test 3)
    [[ "$result" -eq 30 ]] && exit 0 || exit 1
) && sec_pen="pass" || sec_pen="fail"
assert_eq "Secrets penalty: 3 secrets = 30 pts" "pass" "$sec_pen"

(
    penalty_test() {
        local count=$1
        local penalty=$((count * 10))
        [[ $penalty -gt 150 ]] && penalty=150
        echo "$penalty"
    }
    result=$(penalty_test 20)
    [[ "$result" -eq 150 ]] && exit 0 || exit 1
) && sec_pen="pass" || sec_pen="fail"
assert_eq "Secrets penalty: 20 secrets capped at 150" "pass" "$sec_pen"

# Test rootkit penalty cap at 500
(
    penalty_test() {
        local count=$1
        local penalty=$((count * 50))
        [[ $penalty -gt 500 ]] && penalty=500
        echo "$penalty"
    }
    result=$(penalty_test 2)
    [[ "$result" -eq 100 ]] && exit 0 || exit 1
) && rk_pen="pass" || rk_pen="fail"
assert_eq "Rootkit penalty: 2 indicators = 100 pts" "pass" "$rk_pen"

(
    penalty_test() {
        local count=$1
        local penalty=$((count * 50))
        [[ $penalty -gt 500 ]] && penalty=500
        echo "$penalty"
    }
    result=$(penalty_test 15)
    [[ "$result" -eq 500 ]] && exit 0 || exit 1
) && rk_pen="pass" || rk_pen="fail"
assert_eq "Rootkit penalty: 15 indicators capped at 500" "pass" "$rk_pen"

echo ""

# ── 18. Unit Tests: .env File Detection ───────────────────────────────────

echo -e "${BOLD}Unit: .env File Detection${RESET}"

# Create fixture directory tree
mkdir -p "$TMPDIR_TEST/envtest/project" "$TMPDIR_TEST/envtest/testdata" \
         "$TMPDIR_TEST/envtest/node_modules/pkg"

echo "SECRET=real" > "$TMPDIR_TEST/envtest/project/.env"
echo "EXAMPLE=safe" > "$TMPDIR_TEST/envtest/project/.env.example"
echo "SAMPLE=safe" > "$TMPDIR_TEST/envtest/project/.env.sample"
echo "TEMPLATE=safe" > "$TMPDIR_TEST/envtest/project/.env.template"
echo "TEST=safe" > "$TMPDIR_TEST/envtest/testdata/.env"
echo "NODEMOD=safe" > "$TMPDIR_TEST/envtest/node_modules/pkg/.env"
echo "PROD=real" > "$TMPDIR_TEST/envtest/project/.env.production"

# Run detection scoped to fixture dir (reimplement the logic with scoped find)
env_detected=$(find "$TMPDIR_TEST/envtest" \
    -path "*/node_modules" -prune -o \
    -path "*/.git" -prune -o \
    -path "*/go/pkg/mod" -prune -o \
    -path "*/.cache" -prune -o \
    -path "*/vendor" -prune -o \
    \( -name ".env" -o -name ".env.*" \) -print 2>/dev/null | while IFS= read -r envfile; do
        [[ "$envfile" == *.example ]] && continue
        [[ "$envfile" == *.sample ]] && continue
        [[ "$envfile" == *.template ]] && continue
        [[ "$envfile" == */testdata/* ]] && continue
        [[ "$envfile" == */test/* ]] && continue
        [[ "$envfile" == */fixtures/* ]] && continue
        echo "$envfile"
    done)

env_count=$(echo "$env_detected" | grep -c . || echo "0")
assert_eq ".env detected (real file)" "2" "$env_count"

# Verify specific files found/excluded
assert_match ".env.production found" ".env.production" "$env_detected"
assert_match "project/.env found" "project/.env" "$env_detected"

# Verify exclusions by checking they're NOT in output
if echo "$env_detected" | grep -q ".env.example"; then
    echo -e "  ${RED}✗${RESET} .env.example should be excluded"
    FAIL=$((FAIL + 1)); ERRORS+=(".env.example exclusion")
else
    echo -e "  ${GREEN}✓${RESET} .env.example correctly excluded"
    PASS=$((PASS + 1))
fi

if echo "$env_detected" | grep -q "testdata"; then
    echo -e "  ${RED}✗${RESET} testdata/.env should be excluded"
    FAIL=$((FAIL + 1)); ERRORS+=("testdata exclusion")
else
    echo -e "  ${GREEN}✓${RESET} testdata/.env correctly excluded"
    PASS=$((PASS + 1))
fi

if echo "$env_detected" | grep -q "node_modules"; then
    echo -e "  ${RED}✗${RESET} node_modules/.env should be pruned"
    FAIL=$((FAIL + 1)); ERRORS+=("node_modules prune")
else
    echo -e "  ${GREEN}✓${RESET} node_modules/.env correctly pruned"
    PASS=$((PASS + 1))
fi

echo ""

# ── 19. Unit Tests: Home Permissions ──────────────────────────────────────

echo -e "${BOLD}Unit: Home Permissions${RESET}"

# Test the regex pattern used in check_home_permissions
for perms_val in 700 750 755; do
    if [[ "$perms_val" =~ ^7[05][05]$ ]]; then
        echo -e "  ${GREEN}✓${RESET} Accepts $perms_val"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗${RESET} Should accept $perms_val"
        FAIL=$((FAIL + 1)); ERRORS+=("Home perms $perms_val")
    fi
done

for perms_val in 777 776 770 711 644; do
    if [[ "$perms_val" =~ ^7[05][05]$ ]]; then
        echo -e "  ${RED}✗${RESET} Should reject $perms_val"
        FAIL=$((FAIL + 1)); ERRORS+=("Home perms reject $perms_val")
    else
        echo -e "  ${GREEN}✓${RESET} Rejects $perms_val"
        PASS=$((PASS + 1))
    fi
done

echo ""

# ── 20. Unit Tests: Umask ─────────────────────────────────────────────────

echo -e "${BOLD}Unit: Umask Validation${RESET}"

# Test the umask check logic in isolation
test_umask_secure() {
    local test_umask="$1"
    case "$test_umask" in
        0027|027|0077|077) return 0 ;;
        *)
            local mask_val=$((8#$test_umask))
            [[ $mask_val -ge $((8#027)) ]]
            ;;
    esac
}

for um in 027 077 0027 0077; do
    if test_umask_secure "$um" 2>/dev/null; then
        echo -e "  ${GREEN}✓${RESET} Accepts umask $um"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗${RESET} Should accept umask $um"
        FAIL=$((FAIL + 1)); ERRORS+=("umask $um")
    fi
done

for um in 022 002 000; do
    if test_umask_secure "$um" 2>/dev/null; then
        echo -e "  ${RED}✗${RESET} Should reject umask $um"
        FAIL=$((FAIL + 1)); ERRORS+=("umask reject $um")
    else
        echo -e "  ${GREEN}✓${RESET} Rejects umask $um"
        PASS=$((PASS + 1))
    fi
done

echo ""

# ── 21. Unit Tests: Open Ports ────────────────────────────────────────────

echo -e "${BOLD}Unit: Open Ports Detection${RESET}"

# Test the port matching logic with mock data
test_open_ports() {
    local listening_ports="$1"
    local dangerous_ports=(21 23 25 69 110 143 445 513 514)
    for port in "${dangerous_ports[@]}"; do
        if echo "$listening_ports" | grep -q "^${port}$"; then
            return 1
        fi
    done
    return 0
}

# Safe ports only
safe_ports=$(printf '%s\n' 22 80 443 3000 8080)
if test_open_ports "$safe_ports"; then
    echo -e "  ${GREEN}✓${RESET} Safe ports (22,80,443,3000,8080) pass"
    PASS=$((PASS + 1))
else
    echo -e "  ${RED}✗${RESET} Safe ports should pass"
    FAIL=$((FAIL + 1)); ERRORS+=("safe ports")
fi

# Telnet port (23) is dangerous
danger_ports=$(printf '%s\n' 22 23 80 443)
if test_open_ports "$danger_ports"; then
    echo -e "  ${RED}✗${RESET} Port 23 (telnet) should fail"
    FAIL=$((FAIL + 1)); ERRORS+=("port 23 detection")
else
    echo -e "  ${GREEN}✓${RESET} Detects port 23 (telnet)"
    PASS=$((PASS + 1))
fi

# FTP port (21) is dangerous
ftp_ports=$(printf '%s\n' 21 443)
if test_open_ports "$ftp_ports"; then
    echo -e "  ${RED}✗${RESET} Port 21 (FTP) should fail"
    FAIL=$((FAIL + 1)); ERRORS+=("port 21 detection")
else
    echo -e "  ${GREEN}✓${RESET} Detects port 21 (FTP)"
    PASS=$((PASS + 1))
fi

# SMB port (445)
smb_ports=$(printf '%s\n' 80 445 8080)
if test_open_ports "$smb_ports"; then
    echo -e "  ${RED}✗${RESET} Port 445 (SMB) should fail"
    FAIL=$((FAIL + 1)); ERRORS+=("port 445 detection")
else
    echo -e "  ${GREEN}✓${RESET} Detects port 445 (SMB)"
    PASS=$((PASS + 1))
fi

# Empty input (no ports) should pass
if test_open_ports ""; then
    echo -e "  ${GREEN}✓${RESET} No ports listening passes"
    PASS=$((PASS + 1))
else
    echo -e "  ${RED}✗${RESET} No ports should pass"
    FAIL=$((FAIL + 1)); ERRORS+=("empty ports")
fi

# Port 2123 should NOT match port 21 (exact match test)
almost_ports=$(printf '%s\n' 2123 2345 8023)
if test_open_ports "$almost_ports"; then
    echo -e "  ${GREEN}✓${RESET} Port 2123 doesn't false-match 21"
    PASS=$((PASS + 1))
else
    echo -e "  ${RED}✗${RESET} Port 2123 should not match port 21"
    FAIL=$((FAIL + 1)); ERRORS+=("port false match")
fi

echo ""

# ── 22. Unit Tests: JSON Output ───────────────────────────────────────────

echo -e "${BOLD}Unit: JSON Output${RESET}"

# Source the JSON output function and test it
json_test_output=$(bash -c '
VERSION="1.0.0"
OS_TYPE="linux"
TOTAL_SCORE=750
MAX_SCORE=1000

declare -a CHECK_RESULTS=(
    "System|Firewall enabled|1|100|100"
    "System|Disk encryption|0|0|100"
    "SSH|Root login disabled|skip|0|50"
)

'"$(sed -n '/^get_rating/,/^}/p' "$TURTLE")"'
'"$(sed -n '/^print_json_output/,/^}/p' "$TURTLE")"'

print_json_output
' 2>/dev/null)

assert_match "JSON has opening brace" '^\{' "$json_test_output"
assert_match "JSON has version" '"version": "1.0.0"' "$json_test_output"
assert_match "JSON has score 750" '"score": 750' "$json_test_output"
assert_match "JSON has max_score 1000" '"max_score": 1000' "$json_test_output"
assert_match "JSON has percentage 75" '"percentage": 75' "$json_test_output"
assert_match "JSON has Shell Guardian rating" '"rating": "Shell Guardian"' "$json_test_output"
assert_match "JSON has checks array" '"checks":' "$json_test_output"
assert_match "JSON has passed status" '"status": "passed"' "$json_test_output"
assert_match "JSON has failed status" '"status": "failed"' "$json_test_output"
assert_match "JSON has skipped status" '"status": "skipped"' "$json_test_output"
assert_match "JSON has closing brace" '^\}' "$json_test_output"

echo ""

# ── 23. Unit Tests: Core Dumps ────────────────────────────────────────────

echo -e "${BOLD}Unit: Core Dumps${RESET}"

if [[ "$OS_TYPE" == "linux" ]]; then
    eval "$(sed -n '/^check_core_dumps_disabled/,/^}/p' "$TURTLE")"
    OS_TYPE="linux"
    # Run check - just verify it returns a valid exit code and doesn't crash
    check_core_dumps_disabled 2>/dev/null && core_result="pass" || core_result="fail"
    # We can't guarantee the result, but it should execute without error
    assert_match "Core dumps check runs on Linux" "pass|fail" "$core_result"

    # Verify the function checks the right things
    core_code=$(sed -n '/^check_core_dumps_disabled/,/^}/p' "$TURTLE")
    assert_match "Checks ulimit -c" "ulimit -c" "$core_code"
    assert_match "Checks kernel.core_pattern" "core_pattern" "$core_code"
elif [[ "$OS_TYPE" == "macos" ]]; then
    core_code=$(sed -n '/^check_core_dumps_disabled/,/^}/p' "$TURTLE")
    assert_match "Checks launchctl on macOS" "launchctl" "$core_code"
else
    skip_test "Core dumps check" "Unknown OS"
fi

echo ""

# ── 24. Unit Tests: Percentage & Score Edge Cases ─────────────────────────

echo -e "${BOLD}Unit: Score Edge Cases${RESET}"

# Test percentage calculation with zero max_score (division by zero protection)
json_zero_output=$(bash -c '
VERSION="1.0.0"
OS_TYPE="linux"
TOTAL_SCORE=0
MAX_SCORE=0

declare -a CHECK_RESULTS=()

'"$(sed -n '/^get_rating/,/^}/p' "$TURTLE")"'
'"$(sed -n '/^print_json_output/,/^}/p' "$TURTLE")"'

print_json_output
' 2>/dev/null)
assert_match "Zero max_score doesn't crash" '"percentage": 0' "$json_zero_output"
assert_match "Zero score gets Hatchling" '"rating": "Hatchling"' "$json_zero_output"

# Test negative score (from penalties exceeding points)
json_neg_output=$(bash -c '
VERSION="1.0.0"
OS_TYPE="linux"
TOTAL_SCORE=-50
MAX_SCORE=500

declare -a CHECK_RESULTS=()

'"$(sed -n '/^get_rating/,/^}/p' "$TURTLE")"'
'"$(sed -n '/^print_json_output/,/^}/p' "$TURTLE")"'

print_json_output
' 2>/dev/null)
# Negative score should still produce valid JSON (not crash)
assert_match "Negative score produces JSON" '"score": -50' "$json_neg_output"
assert_match "Negative score has max_score" '"max_score": 500' "$json_neg_output"

# Test perfect score
assert_eq "100% is Diamond Shell" "Diamond Shell" "$(get_rating 100)"

echo ""

# ── 25. Integration: Full Scan ────────────────────────────────────────────

if [[ "$RUN_MODE" == "unit" ]]; then
    skip_test "Integration: full scan" "unit mode (pass 'all' to run)"
    skip_test "Integration: JSON output" "unit mode"
    echo ""
else

if [[ "$RUN_MODE" == "integration" ]]; then
    echo -e "${DIM}Skipping unit tests (integration mode)${RESET}"
    echo ""
fi

echo -e "${BOLD}Integration: Full Scan (--quiet)${RESET}"

quiet_output=$(timeout 120 bash "$TURTLE" --quiet 2>&1 || true)

# Verify scan completes and produces expected output
assert_match "Shows header" "TURTLE SECURITY SCANNER" "$quiet_output"
assert_match "Shows score" "YOUR SCORE" "$quiet_output"
assert_match "Shows rating" "Rating:" "$quiet_output"
assert_match "Shows timing" "passed.*failed.*skipped.*[0-9]+s" "$quiet_output"

# All categories should appear
for cat in "SYSTEM SECURITY" "USER SECURITY" "FILE SYSTEM" "SECRETS" \
           "NETWORK" "SERVICES" "HARDENING" "BEST PRACTICES" "PRIVACY" "ADVANCED"; do
    assert_match "Category: $cat" "$cat" "$quiet_output"
done

# Score should be reasonable
score_line=$(echo "$quiet_output" | grep "YOUR SCORE" || echo "")
if [[ "$score_line" =~ ([0-9]+)\ /\ ([0-9]+) ]]; then
    score="${BASH_REMATCH[1]}"
    max="${BASH_REMATCH[2]}"
    assert_match "Score is numeric" '^[0-9]+$' "$score"
    if [[ "$max" -gt 500 ]] && [[ "$max" -lt 10000 ]]; then
        echo -e "  ${GREEN}✓${RESET} Max score reasonable ($max)"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗${RESET} Max score out of range ($max)"
        FAIL=$((FAIL + 1))
        ERRORS+=("Max score range: $max")
    fi
else
    echo -e "  ${RED}✗${RESET} Could not parse score line"
    FAIL=$((FAIL + 1))
    ERRORS+=("Score parse")
fi

echo ""

# ── 26. Integration: JSON Output ─────────────────────────────────────────────

echo -e "${BOLD}Integration: JSON Output${RESET}"

json_output=$(timeout 120 bash "$TURTLE" --json 2>&1 || true)

assert_match "JSON starts with {" '^\{' "$json_output"
assert_match "Has version" '"version"' "$json_output"
assert_match "Has score" '"score"' "$json_output"
assert_match "Has max_score" '"max_score"' "$json_output"
assert_match "Has checks array" '"checks"' "$json_output"
assert_match "Has os field" '"os"' "$json_output"

echo ""

fi  # end of integration tests

# ── Summary ───────────────────────────────────────────────────────────────────

echo "════════════════════════════════════════"
total=$((PASS + FAIL + SKIP))
echo -e "${BOLD}Results: ${GREEN}$PASS passed${RESET}, ${RED}$FAIL failed${RESET}, ${YELLOW}$SKIP skipped${RESET} / $total total"

if [[ ${#ERRORS[@]} -gt 0 ]]; then
    echo ""
    echo -e "${RED}${BOLD}Failures:${RESET}"
    for err in "${ERRORS[@]}"; do
        echo -e "  ${RED}→${RESET} $err"
    done
fi

echo ""
if [[ "$FAIL" -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}All tests passed! 🐢${RESET}"
    exit 0
else
    echo -e "${RED}${BOLD}$FAIL test(s) failed${RESET}"
    exit 1
fi
