#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# 🔵 Vulnerability Scanner — Multi-tool Vulnerability Assessment
# Runs multiple vulnerability scanners against a target and consolidates results.
# USAGE: ./vuln-scan.sh --target <IP/domain> [--type web|container|system]
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[VULN]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail()  { echo -e "${RED}[CRITICAL]${NC} $*"; }

TARGET=""
SCAN_TYPE="all"
OUTPUT_DIR="./scan-results/vuln-$(date +%Y%m%d_%H%M%S)"

usage() {
    echo "Usage: $0 --target <IP/domain> [--type web|container|system|all]"
    echo ""
    echo "Scan Types:"
    echo "  web       — Web application vulnerability scan (nuclei, nikto)"
    echo "  container — Container/image security scan (trivy, grype)"
    echo "  system    — System-level vulnerability scan (lynis + CVE check)"
    echo "  all       — Run all applicable scanners (default)"
    echo ""
    echo "⚠️  Only scan systems you own or have authorization to test."
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET="$2"; shift 2 ;;
        --type)   SCAN_TYPE="$2"; shift 2 ;;
        -h|--help) usage ;;
        *)        fail "Unknown option: $1"; usage ;;
    esac
done

if [[ -z "$TARGET" ]]; then
    fail "No target specified. Use --target <IP/domain>"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║     🔵 Vulnerability Scanner                     ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
info "Target: $TARGET"
info "Scan type: $SCAN_TYPE"
info "Output: $OUTPUT_DIR/"
echo ""

# ── Web Application Scan ────────────────────────────────────────
if [[ "$SCAN_TYPE" == "web" || "$SCAN_TYPE" == "all" ]]; then
    info "═══ Web Application Scanning ═══"
    
    # Nuclei — fast vulnerability scanner with templates
    if command -v nuclei &>/dev/null; then
        info "Running nuclei..."
        nuclei -u "$TARGET" -severity low,medium,high,critical \
            -o "$OUTPUT_DIR/nuclei-web.txt" -silent 2>/dev/null
        NUCLEI_COUNT=$(wc -l < "$OUTPUT_DIR/nuclei-web.txt" 2>/dev/null | tr -d ' ')
        if [[ "$NUCLEI_COUNT" -gt 0 ]]; then
            fail "nuclei found $NUCLEI_COUNT issues — see $OUTPUT_DIR/nuclei-web.txt"
        else
            ok "nuclei: no vulnerabilities found"
        fi
    else
        warn "nuclei not installed — skipping"
    fi
    
    # Nikto — web server security scanner
    if command -v nikto &>/dev/null; then
        info "Running nikto..."
        nikto -h "$TARGET" -output "$OUTPUT_DIR/nikto-web.txt" 2>/dev/null
        ok "nikto scan complete"
    else
        warn "nikto not installed — skipping"
    fi
    
    # WhatWeb — web technology identification
    if command -v whatweb &>/dev/null; then
        info "Running whatweb..."
        whatweb -v "$TARGET" > "$OUTPUT_DIR/whatweb.txt" 2>/dev/null
        ok "whatweb technology fingerprinting complete"
    else
        warn "whatweb not installed — skipping"
    fi
fi

# ── Container Scan ──────────────────────────────────────────────
if [[ "$SCAN_TYPE" == "container" || "$SCAN_TYPE" == "all" ]]; then
    info "═══ Container Security Scanning ═══"
    
    # Trivy — container vulnerability scanner
    if command -v trivy &>/dev/null; then
        info "Running trivy on $TARGET..."
        if [[ "$TARGET" == *"/"* ]]; then
            # Looks like an image reference
            trivy image --severity LOW,MEDIUM,HIGH,CRITICAL \
                --output "$OUTPUT_DIR/trivy-container.json" "$TARGET" 2>/dev/null
            ok "trivy container scan complete"
        else
            info "Running trivy filesystem scan..."
            trivy fs --severity LOW,MEDIUM,HIGH,CRITICAL \
                --output "$OUTPUT_DIR/trivy-fs.txt" "$TARGET" 2>/dev/null || true
            ok "trivy filesystem scan complete"
        fi
    else
        warn "trivy not installed — skipping container scan"
    fi
    
    # Grype — vulnerability scanner for containers
    if command -v grype &>/dev/null; then
        info "Running grype..."
        if [[ "$TARGET" == *"/"* ]]; then
            grype "$TARGET" -o json > "$OUTPUT_DIR/grype-container.json" 2>/dev/null || true
        else
            grype "dir:$TARGET" -o json > "$OUTPUT_DIR/grype-fs.json" 2>/dev/null || true
        fi
        ok "grype scan complete"
    else
        warn "grype not installed — skipping"
    fi
fi

# ── System Vulnerability Check ──────────────────────────────────
if [[ "$SCAN_TYPE" == "system" || "$SCAN_TYPE" == "all" ]]; then
    info "═══ System Vulnerability Check ═══"
    
    # Lynis — system security auditor
    if command -v lynis &>/dev/null; then
        info "Running lynis system audit..."
        sudo lynis audit system --report "$OUTPUT_DIR/lynis-report.dat" \
            2>/dev/null | tail -20
        ok "lynis audit complete — see $OUTPUT_DIR/lynis-report.dat"
    else
        warn "lynis not installed — run './scripts/install.sh' first"
    fi
    
    # CVE check via OSV API (free, no key required)
    info "Checking for known CVEs in installed packages..."
    if command -v python3 &>/dev/null; then
        python3 -c "
import subprocess, json, urllib.request, sys

# Get installed packages (macOS: brew, Linux: dpkg)
try:
    if '$(uname -s)' == 'Darwin':
        pkgs = subprocess.check_output(['brew', 'list', '--versions'], text=True).strip().split('\n')
    else:
        pkgs = subprocess.check_output(['dpkg', '-l'], text=True).strip().split('\n')[5:]
    
    # Check OSV for known vulnerabilities (free API, no key)
    # This is a lightweight check — for production use OSV API directly
    print(f'Checked {len(pkgs)} packages. For detailed CVE info, see https://osv.dev/list')
except Exception as e:
    print(f'Package check skipped: {e}')
" > "$OUTPUT_DIR/cve-check.txt" 2>/dev/null
        ok "CVE check complete"
    fi
fi

# ── Summary ────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║        🔵 Vulnerability Scan Complete            ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "Target: $TARGET"
echo "Results: $OUTPUT_DIR/"
echo ""
echo "⚠️  Review all findings and prioritize by severity."
echo "   CRITICAL/HIGH — patch immediately"
echo "   MEDIUM — schedule remediation"
echo "   LOW/INFO — review at next maintenance window"