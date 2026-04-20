#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# 🔵 Network Reconnaissance Scanner — Blue Team Defensive Scanning
# Scans your own network for open ports, services, and potential exposures.
# USAGE: ./network-scan.sh --local | --target <IP/CIDR> | --target-file <file>
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[RECON]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail()  { echo -e "${RED}[ALERT]${NC} $*"; }

OUTPUT_DIR="./scan-results/$(date +%Y%m%d_%H%M%S)"
TARGET=""
MODE=""
VERBOSE=0
PORTS=""

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --local              Scan local network (auto-detect LAN)"
    echo "  --target <IP/CIDR>   Scan specific target"
    echo "  --target-file <file> Read targets from file"
    echo "  --ports <port-list>  Specific ports (default: top 1000)"
    echo "  -v, --verbose        Verbose output"
    echo "  -h, --help            Show this help"
    echo ""
    echo "⚠️  Only scan networks you own or have authorization to test."
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --local)      MODE="local"; shift ;;
        --target)     MODE="target"; TARGET="$2"; shift 2 ;;
        --target-file) MODE="file"; TARGET_FILE="$2"; shift 2 ;;
        --ports)      PORTS="$2"; shift 2 ;;
        -v|--verbose) VERBOSE=1; shift ;;
        -h|--help)    usage ;;
        *)            fail "Unknown option: $1"; usage ;;
    esac
done

mkdir -p "$OUTPUT_DIR"

# ── Detect local network ────────────────────────────────────────
detect_local_network() {
    if [[ "$(uname -s)" == "Darwin" ]]; then
        # macOS: get default interface and subnet
        local iface=$(route -n get default 2>/dev/null | grep interface | awk '{print $2}')
        local ip=$(ifconfig "$iface" 2>/dev/null | grep 'inet ' | awk '{print $2}')
        local mask=$(ifconfig "$iface" 2>/dev/null | grep 'inet ' | awk '{print $4}')
        if [[ -n "$ip" && -n "$mask" ]]; then
            echo "${ip}/24"
        else
            # Fallback: parse all interfaces
            ifconfig | grep 'inet ' | grep -v 127.0.0.1 | awk '{print $2}' | head -1 | sed 's/$/\/24/'
        fi
    else
        # Linux: parse ip route
        ip route | grep default | awk '{print $3}' | sed 's/$/\/24/' | head -1
    fi
}

# ── Determine target ─────────────────────────────────────────────
if [[ "$MODE" == "local" ]]; then
    TARGET=$(detect_local_network)
    info "Auto-detected local network: $TARGET"
elif [[ "$MODE" == "file" ]]; then
    TARGET="$(cat "$TARGET_FILE")"
    info "Loaded targets from $TARGET_FILE"
elif [[ -z "$TARGET" ]]; then
    fail "No target specified. Use --local or --target <IP/CIDR>"
    exit 1
fi

info "Target: $TARGET"
info "Results: $OUTPUT_DIR/"

# ── Phase 1: Host Discovery ────────────────────────────────────
echo ""
info "═══ Phase 1: Host Discovery ═══"
if command -v nmap &>/dev/null; then
    info "Running nmap host discovery on $TARGET..."
    nmap -sn -oG "$OUTPUT_DIR/hosts.gnmap" "$TARGET" 2>/dev/null
    # Extract live hosts
    grep "Status: Up" "$OUTPUT_DIR/hosts.gnmap" | awk '{print $2}' > "$OUTPUT_DIR/live-hosts.txt"
    LIVE_COUNT=$(wc -l < "$OUTPUT_DIR/live-hosts.txt" | tr -d ' ')
    ok "Found $LIVE_COUNT live hosts"
    if [[ "$VERBOSE" -eq 1 ]]; then
        cat "$OUTPUT_DIR/live-hosts.txt"
    fi
else
    # Fallback: use ping sweep
    warn "nmap not installed, using ping sweep..."
    for ip in $(echo "$TARGET" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.' | head -1 | sed 's/.$//'); do
        for i in $(seq 1 254); do
            ping -c1 -W1 "${ip%.*}.$i" &>/dev/null && echo "${ip%.*}.$i" >> "$OUTPUT_DIR/live-hosts.txt" &
        done
    done
    wait
    LIVE_COUNT=$(wc -l < "$OUTPUT_DIR/live-hosts.txt" | tr -d ' ')
    ok "Found $LIVE_COUNT live hosts (ping sweep)"
fi

# ── Phase 2: Port Scanning ──────────────────────────────────────
echo ""
info "═══ Phase 2: Port Scanning ═══"
NMAP_OPTS="-sV --version-intensity 5 -T4"
if [[ -n "$PORTS" ]]; then
    NMAP_OPTS="$NMAP_OPTS -p $PORTS"
fi

if command -v nmap &>/dev/null; then
    info "Running nmap service scan..."
    nmap $NMAP_OPTS -oA "$OUTPUT_DIR/scan" -iL "$OUTPUT_DIR/live-hosts.txt" 2>/dev/null
    ok "Port scan complete — results in $OUTPUT_DIR/scan.nmap"
else
    warn "nmap not installed — skipping port scan"
fi

# ── Phase 3: Service Analysis ──────────────────────────────────
echo ""
info "═══ Phase 3: Service Analysis ═══"
if [[ -f "$OUTPUT_DIR/scan.nmap" ]]; then
    info "Checking for dangerous services..."
    
    # Common dangerous services to flag
    DANGEROUS_PORTS="21:FTP 23:Telnet 445:SMB 3389:RDP 5900:VNC 5432:PostgreSQL 3306:MySQL 6379:Redis 27017:MongoDB 9200:Elasticsearch"
    
    for entry in $DANGEROUS_PORTS; do
        PORT="${entry%%:*}"
        SVC="${entry##*:}"
        if grep -q " ${PORT}/open" "$OUTPUT_DIR/scan.nmap" 2>/dev/null; then
            fail "⚠️  $SVC (port ${PORT}) is EXPOSED — should be firewalled or disabled"
        fi
    done
    
    # Count open ports per host
    info "Open ports per host:"
    grep "open" "$OUTPUT_DIR/scan.nmap" | awk '{print $2}' | sort | uniq -c | sort -rn | head -20
    
    ok "Service analysis complete"
fi

# ── Phase 4: Quick Vulnerability Check ─────────────────────────
echo ""
info "═══ Phase 4: Quick Vulnerability Check ═══"
if command -v nuclei &>/dev/null; then
    info "Running nuclei with default templates on live hosts..."
    nuclei -iL "$OUTPUT_DIR/live-hosts.txt" -severity low,medium,high,critical \
        -o "$OUTPUT_DIR/nuclei-results.txt" -silent 2>/dev/null
    VULN_COUNT=$(wc -l < "$OUTPUT_DIR/nuclei-results.txt" 2>/dev/null | tr -d ' ')
    if [[ "$VULN_COUNT" -gt 0 ]]; then
        fail "Found $VULN_COUNT potential vulnerabilities — see $OUTPUT_DIR/nuclei-results.txt"
    else
        ok "No vulnerabilities found by nuclei"
    fi
else
    warn "nuclei not installed — skipping vulnerability scan"
fi

# ── Summary ────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║          🔵 Network Scan Complete               ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "Target: $TARGET"
echo "Live hosts: ${LIVE_COUNT:-?}"
echo "Results directory: $OUTPUT_DIR/"
echo ""
echo "Files:"
for f in "$OUTPUT_DIR"/*; do
    [[ -f "$f" ]] && echo "  $(basename "$f") ($(wc -l < "$f" | tr -d ' ') lines)"
done
echo ""
echo "⚠️  Review exposed services and apply hardening recommendations."