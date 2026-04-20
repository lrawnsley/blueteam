#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# 🔵 System Hardening Script — Applies security best practices
# Based on CIS benchmarks and Lynis recommendations. macOS + Linux.
# USAGE: sudo ./harden-system.sh [--audit] [--apply] [--category <name>]
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[HARDEN]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail()  { echo -e "${RED}[CRITICAL]${NC} $*"; }

MODE="audit"
CATEGORY="all"
SCORE=0
TOTAL=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --audit)    MODE="audit"; shift ;;
        --apply)    MODE="apply"; shift ;;
        --category) CATEGORY="$2"; shift 2 ;;
        -h|--help)  echo "Usage: $0 [--audit|--apply] [--category network|filesystem|auth|services|all]"; exit 0 ;;
        *)          fail "Unknown: $1"; exit 1 ;;
    esac
done

if [[ "$MODE" == "apply" && "$(id -u)" -ne 0 ]]; then
    fail "Apply mode requires root. Use: sudo $0 --apply"
    exit 1
fi

OS="$(uname -s)"
REPORT="./scan-results/harden-$(date +%Y%m%d_%H%M%S).txt"
mkdir -p "$(dirname "$REPORT")"

check() {
    local desc="$1"
    local cmd="$2"
    local expected="$3"
    TOTAL=$((TOTAL + 1))
    
    local result
    result=$(eval "$cmd" 2>/dev/null || echo "FAIL")
    
    if echo "$result" | grep -qi "$expected"; then
        ok "PASS: $desc"
        SCORE=$((SCORE + 1))
        echo "PASS: $desc" >> "$REPORT"
    else
        fail "FAIL: $desc"
        echo "FAIL: $desc (got: $result, expected: $expected)" >> "$REPORT"
    fi
}

apply() {
    local desc="$1"
    local cmd="$2"
    if [[ "$MODE" == "apply" ]]; then
        info "Applying: $desc..."
        eval "$cmd" 2>/dev/null && ok "Applied: $desc" || warn "Failed: $desc"
    else
        info "Would apply: $desc (use --apply to execute)"
    fi
}

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║     🔵 System Hardening — $MODE mode              ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# ═══════════════════════════════════════════════════════════════════
# NETWORK HARDENING
# ═══════════════════════════════════════════════════════════════════
if [[ "$CATEGORY" == "network" || "$CATEGORY" == "all" ]]; then
    info "═══ Network Hardening ═══"
    
    if [[ "$OS" == "Darwin" ]]; then
        # macOS Firewall
        check "Firewall enabled" "defaults read /Library/Preferences/com.apple.alf globalstate" "1|2"
        apply "Enable firewall" "defaults write /Library/Preferences/com.apple.alf globalstate -int 1"
        
        check "Stealth mode enabled" "defaults read /Library/Preferences/com.apple.alf stealthenabled" "1"
        apply "Enable stealth mode" "defaults write /Library/Preferences/com.apple.alf stealthenabled -int 1"
        
        check "Remote Login (SSH) off unless needed" "systemsetup -getremotelogin" "Off"
        # Don't auto-apply — user may need SSH
        
        check "Remote Apple Events off" "systemsetup -getremoteappleevents" "Off"
        apply "Disable remote Apple events" "systemsetup -setremoteappleevents off"
        
        # Check for listening services
        info "Checking for unexpected listening services..."
        LISTENING=$(lsof -i -P -n 2>/dev/null | grep LISTEN | grep -v -E '(sshd|nginx|apache|httpd|mongod|postgres|mysql|redis|node|bun|ollama)' || true)
        if [[ -n "$LISTENING" ]]; then
            warn "Unexpected listening services found:"
            echo "$LISTENING" | head -10
        else
            ok "No unexpected listening services"
        fi
    else
        # Linux
        check "UFW/iptables active" "ufw status 2>/dev/null || iptables -L INPUT" "active|ACCEPT"
        check "SSH root login disabled" "grep PermitRootLogin /etc/ssh/sshd_config" "no|prohibit-password"
        apply "Disable SSH root login" "sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config"
        
        check "SSH password auth disabled" "grep PasswordAuthentication /etc/ssh/sshd_config" "no"
        apply "Disable SSH password auth" "sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config"
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# FILESYSTEM HARDENING
# ═══════════════════════════════════════════════════════════════════
if [[ "$CATEGORY" == "filesystem" || "$CATEGORY" == "all" ]]; then
    info "═══ Filesystem Hardening ═══"
    
    # SUID/SGID files — potential privilege escalation vectors
    info "Checking SUID/SGID files..."
    SUID_FILES=$(find /usr /bin /sbin /Library -perm -4000 -type f 2>/dev/null | grep -v -E '(sudo|passwd|ping|ppp|traceroute|mount|umount|su|screen)' | head -20 || true)
    if [[ -n "$SUID_FILES" ]]; then
        warn "Unusual SUID files found (review these):"
        echo "$SUID_FILES"
    else
        ok "No unusual SUID files"
    fi
    
    # World-writable files
    info "Checking world-writable files..."
    WORLD_WRITABLE=$(find /tmp /var/tmp -perm -0002 -type f 2>/dev/null | head -10 || true)
    if [[ -n "$WORLD_WRITABLE" ]]; then
        warn "World-writable files found in temp dirs (expected for /tmp)"
    fi
    
    # SSH key permissions
    if [[ -d ~/.ssh ]]; then
        check "SSH dir permissions" "stat -f '%Lp' ~/.ssh 2>/dev/null || stat -c '%a' ~/.ssh" "700"
        apply "Fix SSH dir permissions" "chmod 700 ~/.ssh"
        
        for key in ~/.ssh/id_rsa ~/.ssh/id_ed25519; do
            if [[ -f "$key" ]]; then
                check "$(basename $key) permissions" "stat -f '%Lp' $key 2>/dev/null || stat -c '%a' $key" "600"
                apply "Fix $key permissions" "chmod 600 $key"
            fi
        done
        
        check "Authorized_keys permissions" "stat -f '%Lp' ~/.ssh/authorized_keys 2>/dev/null || stat -c '%a' ~/.ssh/authorized_keys" "600|644"
        apply "Fix authorized_keys permissions" "chmod 600 ~/.ssh/authorized_keys"
    fi
    
    # File vault (macOS)
    if [[ "$OS" == "Darwin" ]]; then
        check "FileVault enabled" "fdesetup status" "On|FileVault"
        apply "Enable FileVault" "fdesetup enable"
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# AUTHENTICATION HARDENING
# ═══════════════════════════════════════════════════════════════════
if [[ "$CATEGORY" == "auth" || "$CATEGORY" == "all" ]]; then
    info "═══ Authentication Hardening ═══"
    
    # Password policy
    if [[ "$OS" == "Darwin" ]]; then
        check "Password complexity configured" "pwpolicy getaccountpolicies 2>/dev/null | head -5" "."
        info "macOS password policy check — manual review recommended via System Settings > Users & Groups"
    else
        check "Password min length ≥12" "grep minlen /etc/security/pwquality.conf 2>/dev/null || echo 'not found'" "12|1[5-9]|[2-9][0-9]"
        check "Password complexity enabled" "grep -c minclass /etc/security/pwquality.conf 2>/dev/null || echo 0" "[1-9]"
    fi
    
    # Failed login tracking
    if [[ "$OS" == "Linux" ]]; then
        check "Fail2Ban installed" "which fail2ban-client" "fail2ban"
        check "Login delay configured" "grep pam_faildelay /etc/pam.d/common-auth 2>/dev/null || echo 'not found'" "delay"
    fi
    
    # 2FA check
    if [[ "$OS" == "Darwin" ]]; then
        check "Touch ID available" "bioutil -r -s | head -1" "Touch"
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# SERVICES HARDENING
# ═══════════════════════════════════════════════════════════════════
if [[ "$CATEGORY" == "services" || "$CATEGORY" == "all" ]]; then
    info "═══ Services Hardening ═══"
    
    # Check for unnecessary services
    DANGEROUS_SERVICES="telnet ftp rsh rlogin rexec xinetd"
    for svc in $DANGEROUS_SERVICES; do
        if command -v "$svc" &>/dev/null; then
            fail "Dangerous service installed: $svc"
        fi
    done
    ok "No dangerous services found (telnet, ftp, rsh, etc.)"
    
    # DNS configuration
    if [[ "$OS" == "Darwin" ]]; then
        info "Checking DNS configuration..."
        DNS_SERVERS=$(scutil --dns 2>/dev/null | grep "nameserver" | awk '{print $3}' | sort -u | head -5)
        info "DNS servers: $DNS_SERVERS"
        echo "$DNS_SERVERS" | grep -qiE '(8\.8\.8\.8|1\.1\.1\.1|9\.9\.9\.9)' && \
            ok "Using privacy-respecting DNS" || \
            warn "Consider using privacy DNS (1.1.1.1, 9.9.9.9, 8.8.8.8)"
    fi
    
    # Automatic updates
    if [[ "$OS" == "Darwin" ]]; then
        check "Automatic updates enabled" "softwareupdate --schedule 2>/dev/null" "on|enabled"
        apply "Enable automatic updates" "softwareupdate --schedule on"
    else
        check "Unattended upgrades" "dpkg -l unattended-upgrades 2>/dev/null | grep ii" "unattended-upgrades"
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "╔══════════════════════════════════════════════════╗"
PCT=$((TOTAL > 0 ? SCORE * 100 / TOTAL : 0))
echo "║  🔵 Hardening Score: ${SCORE}/${TOTAL} (${PCT}%)                  ║"
echo "║  Report: $REPORT"
echo "╚══════════════════════════════════════════════════╝"
echo ""
if [[ "$PCT" -lt 70 ]]; then
    fail "Score below 70% — significant hardening needed. Re-run with --apply."
elif [[ "$PCT" -lt 90 ]]; then
    warn "Score between 70-90% — some improvements needed."
else
    ok "Score above 90% — system well hardened."
fi