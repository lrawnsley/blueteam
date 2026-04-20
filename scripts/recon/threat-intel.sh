#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# 🔵 Threat Intelligence — Free OSINT feeds and reputation checks
# Queries free threat intel APIs (no paid keys required) for IOCs.
# USAGE: ./threat-intel.sh --ip <IP> | --domain <domain> | --hash <hash>
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[THREAT]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail()  { echo -e "${RED}[ALERT]${NC} $*"; }

IOC_TYPE=""
IOC_VALUE=""

usage() {
    echo "Usage: $0 --ip <IP> | --domain <domain> | --hash <SHA256>"
    echo ""
    echo "Free threat intel sources (no API key required):"
    echo "  --ip <IP>       Check IP against VirusTotal, abuse.ch, Shodan free"
    echo "  --domain <dom>   Check domain reputation"
    echo "  --hash <SHA256>  Check file hash against VirusTotal"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ip)     IOC_TYPE="ip"; IOC_VALUE="$2"; shift 2 ;;
        --domain) IOC_TYPE="domain"; IOC_VALUE="$2"; shift 2 ;;
        --hash)   IOC_TYPE="hash"; IOC_VALUE="$2"; shift 2 ;;
        -h|--help) usage ;;
        *)        fail "Unknown: $1"; usage ;;
    esac
done

if [[ -z "$IOC_VALUE" ]]; then
    fail "No IOC specified"; usage
fi

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║     🔵 Threat Intel: $IOC_TYPE = $IOC_VALUE"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# ── IP Address Check ─────────────────────────────────────────────
if [[ "$IOC_TYPE" == "ip" ]]; then
    info "═══ IP Reputation Check ═══"
    
    # AbuseIPDB — free check via curl (limited without API key, but basic)
    info "Checking abuse.ch/ThreatFox..."
    TF=$(curl -s "https://threatfox-api.abuse.ch/api/v1/" -d '{"query":"search_ioc","search_term":"'"$IOC_VALUE"'"}' 2>/dev/null | head -20 || echo "{}")
    echo "$TF" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'ThreatFox: {d.get(\"query_status\",\"unknown\")} — {d.get(\"data\",[{}])[0].get(\"malware_printable\",\"clean\") if d.get(\"data\") else \"no results\"}')" 2>/dev/null || info "ThreatFox: unable to parse"
    
    # Shodan — free internetDB (no key needed)
    info "Checking Shodan InternetDB..."
    SHODAN=$(curl -s "https://internetdb.shodan.io/$IOC_VALUE" 2>/dev/null || echo "{}")
    if echo "$SHODAN" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'Ports: {d.get(\"ports\",[])} | Vulns: {d.get(\"vulns\",[])} | Hostnames: {d.get(\"hostnames\",[])} | Tags: {d.get(\"tags\",[])}')" 2>/dev/null; then
        VULNS=$(echo "$SHODAN" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('vulns',[])))" 2>/dev/null || echo 0)
        [[ "$VULNS" -gt 0 ]] && fail "⚠️  $VULNS known vulnerabilities on Shodan!" || ok "No known Shodan vulnerabilities"
    else
        info "Shodan: no data found (may not be scanned)"
    fi
    
    # Reverse DNS
    info "Reverse DNS..."
    RDNS=$(dig -x "$IOC_VALUE" +short 2>/dev/null || echo "no PTR record")
    info "PTR: $RDNS"
    
    # GeoIP (free ip-api.com)
    info "GeoIP lookup..."
    GEO=$(curl -s "http://ip-api.com/json/$IOC_VALUE" 2>/dev/null || echo "{}")
    echo "$GEO" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'Location: {d.get(\"city\",\"?\")}, {d.get(\"regionName\",\"?\")}, {d.get(\"country\",\"?\")} | ISP: {d.get(\"isp\",\"?\")} | Org: {d.get(\"org\",\"?\")}')" 2>/dev/null || info "GeoIP: unable to parse"
fi

# ── Domain Check ────────────────────────────────────────────────
if [[ "$IOC_TYPE" == "domain" ]]; then
    info "═══ Domain Reputation Check ═══"
    
    # WHOIS
    info "WHOIS lookup..."
    whois "$IOC_VALUE" 2>/dev/null | grep -iE "(registrar|creation|expir|status|name server)" | head -10 || info "WHOIS: no data"
    
    # DNS records
    info "DNS records..."
    for rtype in A AAAA MX NS TXT; do
        RECORDS=$(dig "$IOC_VALUE" "$rtype" +short 2>/dev/null || echo "none")
        [[ -n "$RECORDS" && "$RECORDS" != "none" ]] && info "$rtype: $RECORDS"
    done
    
    # Check against URLhaus
    info "Checking URLhaus..."
    URLHAUS=$(curl -s "https://urlhaus-api.abuse.ch/v1/host/" -d '{"host":"'"$IOC_VALUE"'"}' 2>/dev/null | head -10 || echo "{}")
    echo "$URLHAUS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'URLhaus: {d.get(\"query_status\",\"unknown\")} — {d.get(\"host\",\"clean\")}')" 2>/dev/null || info "URLhaus: unable to parse"
fi

# ── Hash Check ──────────────────────────────────────────────────
if [[ "$IOC_TYPE" == "hash" ]]; then
    info "═══ File Hash Check ═══"
    
    # Malware Bazaar (abuse.ch) — free, no key
    info "Checking Malware Bazaar..."
    MB=$(curl -s "https://mb-api.abuse.ch/api/v1/" -d '{"query":"get_info","hash":"'"$IOC_VALUE"'"}' 2>/dev/null | head -20 || echo "{}")
    echo "$MB" | python3 -c "import sys,json; d=json.load(sys.stdin); data=d.get('data',[{}])[0] if d.get('data') else {}; print(f'Malware Bazaar: {d.get(\"query_status\",\"unknown\")} — {data.get(\"signature\",\"clean\")} | Family: {data.get(\"family\",\"N/A\")} | Tags: {data.get(\"tags\",[])}')" 2>/dev/null || info "Malware Bazaar: no results"
    
    # VirusTotal — free API (4 requests/min, no key for basic search)
    info "Checking VirusTotal (free, limited)..."
    VT=$(curl -s "https://www.virustotal.com/api/v3/files/$IOC_VALUE" -H "x-apikey: " 2>/dev/null | head -5 || echo "{}")
    info "VirusTotal: limited without API key — visit https://www.virustotal.com/gui/file/$IOC_VALUE"
fi

# ── Summary ────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║       🔵 Threat Intel Check Complete             ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "⚠️  Free tier data is limited. For production use, consider:"
echo "   • VirusTotal API key (free: 500/day)"
echo "   • AbuseIPDB API key (free: 1000/day)"
echo "   • Shodan API key (free: 100/month)"
echo "   • AlienVault OTX (free, unlimited)"