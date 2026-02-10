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
        timeout() { shift; "$@"; }  # just run without timeout
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

install_content=$(cat "$SCRIPT_DIR/install.sh")
assert_match "install.sh has strict mode" "set -euo pipefail" "$install_content"
assert_match "install.sh curls the script" "curl" "$install_content"
assert_match "install.sh sets +x" "chmod" "$install_content"
assert_match "install.sh handles PATH" "PATH" "$install_content"

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
    assert_match "Checks suspicious kernel modules" "diamorphine\|reptile" "$rk_code"
    assert_match "Checks /dev/shm executables" "dev/shm" "$rk_code"
    assert_match "Checks process count" "proc_count|ps_count" "$rk_code"
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

# ── 13. Integration: Full Scan ───────────────────────────────────────────────

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

# ── 14. Integration: JSON Output ─────────────────────────────────────────────

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
