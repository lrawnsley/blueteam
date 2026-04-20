#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# 🔵 System Audit — Comprehensive Security Audit of the Local Machine
# Runs all security checks and produces a scored report.
# USAGE: ./system-audit.sh [--json] [--output <dir>]
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[AUDIT]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; }

OUTPUT_DIR="./scan-results/audit-$(date +%Y%m%d_%H%M%S)"
JSON_OUTPUT=0
SCORE=0
TOTAL=0
FINDINGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --json)   JSON_OUTPUT=1; shift ;;
        --output) OUTPUT_DIR="$2"; shift 2 ;;
        -h|--help) echo "Usage: $0 [--json] [--output <dir>]"; exit 0 ;;
        *)        fail "Unknown: $1"; exit 1 ;;
    esac
done

mkdir -p "$OUTPUT_DIR"
OS="$(uname -s)"
KERNEL="$(uname -r)"
HOSTNAME="$(hostname -s 2>/dev/null || hostname)"

pass() { TOTAL=$((TOTAL+1)); SCORE=$((SCORE+1)); FINDINGS+=("PASS:$1"); ok "$1"; }
fail_check() { TOTAL=$((TOTAL+1)); FINDINGS+=("FAIL:$1"); fail "$1"; }
warn_check() { TOTAL=$((TOTAL+1)); FINDINGS+=("WARN:$1"); warn "$1"; }

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║     🔵 System Security Audit                     ║"
echo "║     Host: $HOSTNAME | OS: $OS $Kernel"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# ── OS & Patch Level ────────────────────────────────────────────
info "═══ OS & Patch Level ═══"
if [[ "$OS" == "Darwin" ]]; then
    pass "macOS $(sw_vers -productVersion 2>/dev/null || echo 'unknown')"
    LAST_UPDATE=$(softwareupdate --history 2>/dev/null | head -1 || echo "unknown")
    info "Last update: $LAST_UPDATE"
else
    pass "$(lsb_release -ds 2>/dev/null || cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 || echo 'Linux')"
fi

# Check for available updates
if [[ "$OS" == "Darwin" ]]; then
    UPDATES=$(softwareupdate --list 2>&1 | grep -c "Title" || echo "0")
    [[ "$UPDATES" -eq 0 ]] && pass "No pending system updates" || fail_check "$UPDATES pending system updates — apply immediately"
else
    UPDATES=$(apt list --upgradable 2>/dev/null | grep -c "upgradable" || echo "0")
    [[ "$UPDATES" -le 1 ]] && pass "No pending package updates" || fail_check "$UPDATES pending package updates"
fi

# ── Network Security ────────────────────────────────────────────
info "═══ Network Security ═══"
if [[ "$OS" == "Darwin" ]]; then
    FIREWALL=$(defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null || echo "0")
    [[ "$FIREWALL" -ge 1 ]] && pass "Firewall enabled" || fail_check "Firewall DISABLED — enable immediately"
    
    STEALTH=$(defaults read /Library/Preferences/com.apple.alf stealthenabled 2>/dev/null || echo "0")
    [[ "$STEALTH" -eq 1 ]] && pass "Stealth mode enabled" || warn_check "Stealth mode not enabled — reduces scan visibility"
else
    UFW=$(ufw status 2>/dev/null | grep "Status:" | awk '{print $2}' || echo "inactive")
    [[ "$UFW" == "active" ]] && pass "UFW firewall active" || fail_check "UFW firewall inactive"
fi

# Listening services
LISTENING=$(lsof -i -P -n 2>/dev/null | grep LISTEN | wc -l | tr -d ' ')
info "$LISTENING services listening on network ports"
lsof -i -P -n 2>/dev/null | grep LISTEN | awk '{print $1, $9}' | sort -u > "$OUTPUT_DIR/listening-services.txt"

# ── SSH Security ────────────────────────────────────────────────
info "═══ SSH Security ═══"
SSH_CONFIG="/etc/ssh/sshd_config"
if [[ -f "$SSH_CONFIG" ]]; then
    grep -qi "PermitRootLogin no" "$SSH_CONFIG" && pass "SSH root login disabled" || fail_check "SSH root login permitted"
    grep -qi "PasswordAuthentication no" "$SSH_CONFIG" && pass "SSH password auth disabled" || warn_check "SSH password auth enabled — use keys only"
    grep -qi "X11Forwarding no" "$SSH_CONFIG" && pass "SSH X11 forwarding disabled" || warn_check "SSH X11 forwarding enabled"
fi

# ── Filesystem Security ─────────────────────────────────────────
info "═══ Filesystem Security ═══"
if [[ -d ~/.ssh ]]; then
    SSH_DIR_MODE=$(stat -f '%Lp' ~/.ssh 2>/dev/null || stat -c '%a' ~/.ssh 2>/dev/null || echo "???")
    [[ "$SSH_DIR_MODE" == "700" ]] && pass "~/.ssh permissions correct (700)" || fail_check "~/.ssh permissions wrong ($SSH_DIR_MODE — should be 700)"
    
    for key in ~/.ssh/id_rsa ~/.ssh/id_ed25519 ~/.ssh/id_ecdsa; do
        if [[ -f "$key" ]]; then
            KEY_MODE=$(stat -f '%Lp' "$key" 2>/dev/null || stat -c '%a' "$key" 2>/dev/null || echo "???")
            [[ "$KEY_MODE" == "600" ]] && pass "$(basename $key) permissions correct (600)" || fail_check "$(basename $key) permissions wrong ($KEY_MODE — should be 600)"
        fi
    done
fi

# SUID files
SUID_COUNT=$(find /usr /bin /sbin /Library -perm -4000 -type f 2>/dev/null | wc -l | tr -d ' ')
info "$SUID_COUNT SUID files found (standard binaries expected)"
UNUSUAL_SUID=$(find /usr/local /opt /tmp -perm -4000 -type f 2>/dev/null || true)
[[ -z "$UNUSUAL_SUID" ]] && pass "No unusual SUID files" || fail_check "Unusual SUID files found: $UNUSUAL_SUID"

# ── Encryption ──────────────────────────────────────────────────
info "═══ Encryption ═══"
if [[ "$OS" == "Darwin" ]]; then
    FDE=$(fdesetup status 2>/dev/null | head -1 || echo "Off")
    echo "$FDE" | grep -qi "On\|FileVault" && pass "FileVault encryption enabled" || fail_check "FileVault NOT enabled — data at risk"
else
    [[ -e /etc/crypttab ]] && pass "Disk encryption configured" || warn_check "No /etc/crypttab — verify LUKS encryption"
fi

# ── User Security ────────────────────────────────────────────────
info "═══ User Security ═══"
CURRENT_USER=$(whoami)
PASS_AGE=$(chage -l "$CURRENT_USER" 2>/dev/null | grep "Last password change" | cut -d: -f2 | xargs || echo "N/A")
info "Current user: $CURRENT_USER | Password last changed: $PASS_AGE"

# Empty password check
if [[ "$OS" == "Linux" ]]; then
    EMPTY_PASS=$(sudo awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null || echo "check_skipped")
    [[ "$EMPTY_PASS" == "check_skipped" || -z "$EMPTY_PASS" ]] && pass "No accounts with empty passwords" || fail_check "Accounts with empty/locked passwords: $EMPTY_PASS"
fi

# ── Software Vulnerabilities ─────────────────────────────────────
info "═══ Software Vulnerabilities ═══"
if command -v trivy &>/dev/null; then
    info "Running trivy filesystem scan..."
    trivy fs --severity LOW,MEDIUM,HIGH,CRITICAL --output "$OUTPUT_DIR/trivy-audit.json" / 2>/dev/null || true
    ok "Trivy scan complete"
elif command -v grype &>/dev/null; then
    info "Running grype vulnerability scan..."
    grype "dir:/" -o json > "$OUTPUT_DIR/grype-audit.json" 2>/dev/null || true
    ok "Grype scan complete"
else
    warn "No vulnerability scanner installed — run ./scripts/install.sh"
fi

# ── Lynis Audit ─────────────────────────────────────────────────
info "═══ Lynis Audit ═══"
if command -v lynis &>/dev/null; then
    info "Running lynis system audit..."
    sudo lynis audit system --report "$OUTPUT_DIR/lynis-report.dat" --quick 2>/dev/null | tail -30
    LYNIS_SCORE=$(grep "hardening_index" "$OUTPUT_DIR/lynis-report.dat" 2>/dev/null | cut -d= -f2 || echo "N/A")
    info "Lynis hardening index: $LYNIS_SCORE/100"
else
    warn "lynis not installed — run ./scripts/install.sh"
fi

# ── Summary ────────────────────────────────────────────────────
PCT=$((TOTAL > 0 ? SCORE * 100 / TOTAL : 0))
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║     🔵 Audit Score: ${SCORE}/${TOTAL} (${PCT}%)                   ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

if [[ "$JSON_OUTPUT" -eq 1 ]]; then
    cat > "$OUTPUT_DIR/audit-report.json" <<EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "host": "$HOSTNAME",
  "os": "$OS",
  "kernel": "$KERNEL",
  "score": $SCORE,
  "total": $TOTAL,
  "percentage": $PCT,
  "findings": [$(IFS=,; echo "${FINDINGS[*]}" | sed 's/,/","/g; s/^/"/; s/$/"/')]
}
EOF
    info "JSON report: $OUTPUT_DIR/audit-report.json"
fi

if [[ "$PCT" -lt 60 ]]; then
    fail "⚠️  Score below 60% — critical hardening needed"
elif [[ "$PCT" -lt 80 ]]; then
    warn "Score between 60-80% — improvements needed"
else
    ok "Score above 80% — good security posture"
fi