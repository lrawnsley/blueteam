#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# 🔵 BlueTeam Toolkit — Install Script
# Installs all required security tools via brew, pip, and go install.
# Zero-cost, open-source tools only. macOS (brew) + Linux (apt) support.
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; }

OS="$(uname -s)"
PKG_MGR=""
INSTALL_CMD=""

detect_pkg_mgr() {
    if command -v brew &>/dev/null; then
        PKG_MGR="brew"
        INSTALL_CMD="brew install"
    elif command -v apt-get &>/dev/null; then
        PKG_MGR="apt"
        INSTALL_CMD="sudo apt-get install -y"
    elif command -v dnf &>/dev/null; then
        PKG_MGR="dnf"
        INSTALL_CMD="sudo dnf install -y"
    elif command -v pacman &>/dev/null; then
        PKG_MGR="pacman"
        INSTALL_CMD="sudo pacman -S --noconfirm"
    else
        fail "No supported package manager found (brew/apt/dnf/pacman)"
        exit 1
    fi
    info "Package manager: $PKG_MGR"
}

check_or_install() {
    local name="$1"
    local cmd="${2:-$1}"
    local pkg="${3:-$1}"
    
    if command -v "$cmd" &>/dev/null; then
        ok "$name already installed"
        return 0
    fi
    
    info "Installing $name..."
    case "$PKG_MGR" in
        brew) brew install "$pkg" 2>/dev/null && ok "$name installed" || warn "$name install failed" ;;
        apt)  $INSTALL_CMD "$pkg" 2>/dev/null && ok "$name installed" || warn "$name install failed" ;;
        dnf)  $INSTALL_CMD "$pkg" 2>/dev/null && ok "$name installed" || warn "$name install failed" ;;
        pacman) $INSTALL_CMD "$pkg" 2>/dev/null && ok "$name installed" || warn "$name install failed" ;;
    esac
}

install_pip() {
    local name="$1"
    local pkg="${2:-$1}"
    if python3 -c "import $pkg" &>/dev/null 2>&1 || pip3 show "$pkg" &>/dev/null; then
        ok "$name (pip) already installed"
    else
        info "Installing $name via pip..."
        pip3 install --user "$pkg" 2>/dev/null && ok "$name installed" || warn "$name pip install failed"
    fi
}

install_go_bin() {
    local name="$1"
    local repo="$2"
    if command -v "$name" &>/dev/null; then
        ok "$name already installed"
    elif command -v go &>/dev/null; then
        info "Installing $name via go install..."
        go install "$repo@latest" 2>/dev/null && ok "$name installed" || warn "$name go install failed"
    else
        warn "$name requires Go — skipping (install Go: https://go.dev/dl/)"
    fi
}

# ═══════════════════════════════════════════════════════════════════
# Install categories
# ═══════════════════════════════════════════════════════════════════

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║     🔵 BlueTeam Toolkit — Installer             ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

detect_pkg_mgr

# ── Core Networking ──────────────────────────────────────────────
echo ""
info "Installing core networking tools..."
check_or_install "nmap" "nmap"
check_or_install "curl" "curl"
check_or_install "whois" "whois"
check_or_install "netcat" "nc" "netcat" 2>/dev/null || check_or_install "netcat" "nc" "nmap-ncat"
check_or_install "socat" "socat"
check_or_install "jq" "jq"

# ── Vulnerability Scanners ───────────────────────────────────────
echo ""
info "Installing vulnerability scanners..."
check_or_install "nuclei" "nuclei"
check_or_install "trivy" "trivy"
check_or_install "nikto" "nikto"

# ── SSL/TLS ──────────────────────────────────────────────────────
echo ""
info "Installing SSL/TLS tools..."
check_or_install "testssl.sh" "testssl" "testssl"
check_or_install "sslscan" "sslscan"

# ── Hardening & Audit ───────────────────────────────────────────
echo ""
info "Installing hardening & audit tools..."
check_or_install "lynis" "lynis"

# ── Password Auditing ────────────────────────────────────────────
echo ""
info "Installing password auditing tools..."
check_or_install "hashcat" "hashcat"
check_or_install "john" "john" "john-the-ripper"

# ── Web App Security ────────────────────────────────────────────
echo ""
info "Installing web application security tools..."
check_or_install "whatweb" "whatweb"

# ── Go-based Tools (need Go) ────────────────────────────────────
echo ""
info "Installing Go-based tools..."
check_or_install "go" "go"
install_go_bin "naabu" "github.com/projectdiscovery/naabu/v2/cmd/naabu"
install_go_bin "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
install_go_bin "httpx" "github.com/projectdiscovery/httpx/cmd/httpx"
install_go_bin "grype" "github.com/anchore/grype/cmd/grype"
install_go_bin "syft" "github.com/anchore/syft/cmd/syft"

# ── Python Security Packages ────────────────────────────────────
echo ""
info "Installing Python security packages..."
install_pip "scapy" "scapy"
install_pip "paramiko" "paramiko"
install_pip "python-nmap" "python-nmap"
install_pip "cryptography" "cryptography"
install_pip "PyOpenSSL" "pyOpenSSL"
install_pip "beautifulsoup4" "bs4"
install_pip "requests" "requests"
install_pip "dnspython" "dnspython"
install_pip "ipaddress" "ipaddress"

# ── testssl.sh (manual install if brew fails) ──────────────────
echo ""
if ! command -v testssl &>/dev/null; then
    info "Attempting manual testssl.sh install..."
    git clone --depth 1 https://github.com/drwetter/testssl.sh.git /tmp/testssl 2>/dev/null
    if [ -f /tmp/testssl/testssl.sh ]; then
        chmod +x /tmp/testssl/testssl.sh
        sudo cp /tmp/testssl/testssl.sh /usr/local/bin/testssl 2>/dev/null && ok "testssl installed" || warn "testssl manual install failed (try: add /tmp/testssl to PATH)"
        rm -rf /tmp/testssl
    fi
fi

# ── Summary ─────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║     🔵 Installation Complete                    ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "Installed tools:"
for tool in nmap nuclei trivy nikto testssl sslscan lynis hashcat john whatweb naabu subfinder httpx grype syft; do
    if command -v "$tool" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $tool"
    else
        echo -e "  ${RED}✗${NC} $tool (not found)"
    fi
done
echo ""
echo "Run './scripts/audit/system-audit.sh' to verify your setup."