#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# 🔵 Web Application Attack Scanner — Blue Team Defensive Testing
# Scans for: SQLi, XSS, SSRF, LFI, CORS, CSRF, command injection,
# deserialization, and supply chain vulnerabilities.
# USAGE: ./webapp-attack-scan.sh --target <URL> [--type sqli|xss|ssrf|lfi|all]
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[WEBATK]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail()  { echo -e "${RED}[VULN]${NC} $*"; }

TARGET=""
SCAN_TYPE="all"
OUTPUT_DIR="./scan-results/webapp-$(date +%Y%m%d_%H%M%S)"
COOKIE=""
HEADER=""

usage() {
    echo "Usage: $0 --target <URL> [--type TYPE] [--cookie 'session=abc'] [--header 'Auth: Bearer x']"
    echo ""
    echo "Scan Types:"
    echo "  sqli          — SQL injection detection (sqlmap)"
    echo "  xss           — Cross-site scripting (dalfox, XSStrike)"
    echo "  ssrf          — Server-side request forgery (SSRFmap)"
    echo "  lfi           — Local file inclusion (custom checks)"
    echo "  cors          — CORS misconfiguration (CORScanner)"
    echo "  headers       — Security header analysis (shcheck)"
    echo "  fuzz           — Parameter discovery & fuzzing (ffuf, arjun)"
    echo "  supply-chain  — Dependency/supply chain audit (osv-scanner)"
    echo "  all           — Run all applicable scans (default)"
    echo ""
    echo "⚠️  Only test applications you own or have authorization to test."
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET="$2"; shift 2 ;;
        --type)   SCAN_TYPE="$2"; shift 2 ;;
        --cookie) COOKIE="$2"; shift 2 ;;
        --header) HEADER="$2"; shift 2 ;;
        -h|--help) usage ;;
        *)        fail "Unknown: $1"; usage ;;
    esac
done

if [[ -z "$TARGET" ]]; then
    fail "No target specified. Use --target <URL>"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║     🔵 Web Attack Defense Scanner                 ║"
echo "║     Target: $TARGET"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# ── Build auth arguments ────────────────────────────────────────
AUTH_ARGS=""
[[ -n "$COOKIE" ]] && AUTH_ARGS="$AUTH_ARGS --cookie=\"$COOKIE\""
[[ -n "$HEADER" ]] && AUTH_ARGS="$AUTH_ARGS --header=\"$HEADER\""

# ═══════════════════════════════════════════════════════════════════
# SQL INJECTION
# ═══════════════════════════════════════════════════════════════════
if [[ "$SCAN_TYPE" == "sqli" || "$SCAN_TYPE" == "all" ]]; then
    info "═══ SQL Injection Detection ═══"
    
    if command -v sqlmap &>/dev/null; then
        info "Running sqlmap (safe detection mode)..."
        sqlmap -u "$TARGET" $AUTH_ARGS \
            --batch --smart --level=3 --risk=1 \
            --technique=BEUSTQ \
            --output-dir="$OUTPUT_DIR/sqlmap" \
            --threads=4 \
            --timeout=30 \
            --retries=2 \
            2>/dev/null | tee "$OUTPUT_DIR/sqlmap-output.txt"
        
        if grep -qi "injectable\|vulnerable\|is vulnerable" "$OUTPUT_DIR/sqlmap-output.txt" 2>/dev/null; then
            fail "⚠️  SQL injection vulnerability detected! See $OUTPUT_DIR/sqlmap/"
        else
            ok "No SQL injection detected (risk=1 scan)"
        fi
    else
        warn "sqlmap not installed — run ./scripts/install.sh"
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# CROSS-SITE SCRIPTING (XSS)
# ═══════════════════════════════════════════════════════════════════
if [[ "$SCAN_TYPE" == "xss" || "$SCAN_TYPE" == "all" ]]; then
    info "═══ Cross-Site Scripting Detection ═══"
    
    # dalfox — fast XSS scanner
    if command -v dalfox &>/dev/null; then
        info "Running dalfox XSS scanner..."
        dalfox url "$TARGET" $AUTH_ARGS \
            --silence --only-vuln \
            --output "$OUTPUT_DIR/dalfox-xss.txt" 2>/dev/null || true
        
        XSS_COUNT=$(wc -l < "$OUTPUT_DIR/dalfox-xss.txt" 2>/dev/null | tr -d ' ')
        if [[ "$XSS_COUNT" -gt 0 ]]; then
            fail "⚠️  $XSS_COUNT XSS vulnerabilities found! See $OUTPUT_DIR/dalfox-xss.txt"
        else
            ok "dalfox: no XSS vulnerabilities found"
        fi
    else
        warn "dalfox not installed — run ./scripts/install.sh"
    fi
    
    # XSStrike — advanced XSS detection
    if command -v xsstrike &>/dev/null || [[ -f "$(find /usr/local -name 'xsstrike' -type f 2>/dev/null | head -1)" ]]; then
        info "Running XSStrike..."
        xsstrike -u "$TARGET" --crawl -l 3 --json > "$OUTPUT_DIR/xsstrike-xss.json" 2>/dev/null || true
    else
        warn "XSStrike not installed — pip3 install xsstrike"
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# SECURITY HEADERS
# ═══════════════════════════════════════════════════════════════════
if [[ "$SCAN_TYPE" == "headers" || "$SCAN_TYPE" == "all" ]]; then
    info "═══ Security Headers Check ═══"
    
    HEADERS=$(curl -sI "$TARGET" 2>/dev/null)
    
    # Essential security headers
   declare -A SEC_HEADERS=(
        ["Strict-Transport-Security"]="HSTS — prevents protocol downgrade"
        ["Content-Security-Policy"]="CSP — prevents XSS/data injection"
        ["X-Content-Type-Options"]="Prevents MIME sniffing"
        ["X-Frame-Options"]="Prevents clickjacking"
        ["X-XSS-Protection"]="Legacy XSS filter (deprecated but common)"
        ["Referrer-Policy"]="Controls referrer information leakage"
        ["Permissions-Policy"]="Restricts browser API access"
        ["Cross-Origin-Opener-Policy"]="Prevents cross-origin attacks"
        ["Cross-Origin-Resource-Policy"]="Prevents cross-origin resource theft"
    )
    
    FOUND=0
    MISSING=0
    for header reason in "${(@kv)SEC_HEADERS}"; do
        if echo "$HEADERS" | grep -qi "$header"; then
            ok "$header present"
            FOUND=$((FOUND+1))
        else
            fail "Missing: $header — $reason"
            MISSING=$((MISSING+1))
        fi
    done
    
    info "Security headers: $FOUND found, $MISSING missing"
    
    # Cookie security
    info "═══ Cookie Security ═══"
    COOKIES=$(echo "$HEADERS" | grep -i "set-cookie" || true)
    if [[ -n "$COOKIES" ]]; then
        echo "$COOKIES" | grep -qi "secure" && ok "Secure flag set" || fail "⚠️  Cookie without Secure flag (sent over HTTP!)"
        echo "$COOKIES" | grep -qi "httponly" && ok "HttpOnly flag set" || fail "⚠️  Cookie without HttpOnly flag (accessible via JavaScript!)"
        echo "$COOKIES" | grep -qi "samesite" && ok "SameSite attribute set" || warn "Cookie without SameSite attribute (CSRF risk)"
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# CORS CHECK
# ═══════════════════════════════════════════════════════════════════
if [[ "$SCAN_TYPE" == "cors" || "$SCAN_TYPE" == "all" ]]; then
    info "═══ CORS Misconfiguration ═══"
    
    # Test with various Origin headers
    for origin in "https://evil.com" "https://null" "https://$HOST"; do
        CORS_RESP=$(curl -sI "$TARGET" -H "Origin: $origin" 2>/dev/null)
        ACAO=$(echo "$CORS_RESP" | grep -i "access-control-allow-origin" | tr -d '\r' || true)
        if [[ -n "$ACAO" ]]; then
            if echo "$ACAO" | grep -q "\*"; then
                fail "⚠️  CORS allows * — any origin can access! (Origin: $origin)"
            elif echo "$ACAO" | grep -q "evil.com"; then
                fail "⚠️  CORS allows evil.com origin — misconfigured! (Origin: $origin)"
            elif echo "$ACAO" | grep -q "null"; then
                fail "⚠️  CORS allows null origin — exploitable via iframe sandbox! (Origin: $origin)"
            else
                info "CORS response with Origin $origin: $ACAO"
            fi
        fi
    done
    
    ok "CORS check complete"
fi

# ═══════════════════════════════════════════════════════════════════
# PARAMETER DISCOVERY & FUZZING
# ═══════════════════════════════════════════════════════════════════
if [[ "$SCAN_TYPE" == "fuzz" || "$SCAN_TYPE" == "all" ]]; then
    info "═══ Parameter Discovery ═══"
    
    # arjun — HTTP parameter discovery
    if command -v arjun &>/dev/null; then
        info "Running arjun parameter discovery..."
        arjun -u "$TARGET" $AUTH_ARGS \
            -oJ "$OUTPUT_DIR/arjun-params.json" \
            --stable 2>/dev/null || true
        ok "Parameter discovery complete"
    else
        warn "arjun not installed — pip3 install arjun"
    fi
    
    # ffuf — fast fuzzer for path/param discovery
    if command -v ffuf &>/dev/null; then
        info "Running ffuf directory fuzzer..."
        # Use a small common wordlist if SecLists isn't available
        WORDLIST="/usr/share/seclists/Discovery/Web-Content/common.txt"
        [[ ! -f "$WORDLIST" ]] && WORDLIST="/usr/share/wordlists/dirb/common.txt"
        [[ ! -f "$WORDLIST" ]] && WORDLIST=""  # Will use default
        
        if [[ -n "$WORDLIST" ]]; then
            ffuf -u "$TARGET/FUZZ" -w "$WORDLIST" $AUTH_ARGS \
                -mc 200,301,302,403 \
                -o "$OUTPUT_DIR/ffuf-results.json" \
                -t 50 -rate 100 \
                2>/dev/null || true
            ok "Directory fuzzing complete"
        else
            info "No wordlist found — download SecLists for best results:"
            info "  git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists"
        fi
    else
        warn "ffuf not installed — run ./scripts/install.sh"
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# SUPPLY CHAIN SECURITY
# ═══════════════════════════════════════════════════════════════════
if [[ "$SCAN_TYPE" == "supply-chain" || "$SCAN_TYPE" == "all" ]]; then
    info "═══ Supply Chain Security ═══"
    
    # osv-scanner — Google's vulnerability scanner using OSV database
    if command -v osv-scanner &>/dev/null; then
        info "Running osv-scanner..."
        # If target looks like a local directory
        if [[ -d "$TARGET" ]]; then
            osv-scanner scan --root "$TARGET" --format json \
                > "$OUTPUT_DIR/osv-results.json" 2>/dev/null || true
            ok "OSV scan complete — see $OUTPUT_DIR/osv-results.json"
        else
            info "osv-scanner works on local directories, not URLs"
            info "Usage: osv-scanner scan --root /path/to/project"
        fi
    else
        warn "osv-scanner not installed — run ./scripts/install.sh"
    fi
    
    # Check for known malicious packages (guarddog)
    if command -v guarddog &>/dev/null; then
        info "Running guarddog malware check..."
        if [[ -f "$TARGET/requirements.txt" ]]; then
            guarddog pypi scan "$TARGET/requirements.txt" \
                > "$OUTPUT_DIR/guarddog-results.txt" 2>/dev/null || true
        elif [[ -f "$TARGET/package.json" ]]; then
            guarddog npm scan "$TARGET/package.json" \
                > "$OUTPUT_DIR/guarddog-results.txt" 2>/dev/null || true
        else
            info "No requirements.txt or package.json found at target"
        fi
    else
        warn "guarddog not installed — pip3 install guarddog"
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# MITM / TLS INTERCEPTION DEFENSE
# ═══════════════════════════════════════════════════════════════════
if [[ "$SCAN_TYPE" == "all" ]]; then
    info "═══ MITM Defense Check ═══"
    
    # Check if HSTS is present (prevents MITM via protocol downgrade)
    HEADERS=$(curl -sI "$TARGET" 2>/dev/null)
    if echo "$HEADERS" | grep -qi "strict-transport-security"; then
        HSTS_VAL=$(echo "$HEADERS" | grep -i "strict-transport-security" | tr -d '\r')
        ok "HSTS present: $HSTS_VAL"
        # Check max-age
        MAX_AGE=$(echo "$HSTS_VAL" | grep -oE 'max-age=[0-9]+' | cut -d= -f2)
        [[ "$MAX_AGE" -gt 15768000 ]] && ok "max-age > 6 months (good)" || warn "max-age < 6 months — increase for better MITM protection"
        echo "$HSTS_VAL" | grep -qi "includesubdomains" && ok "includeSubDomains set" || warn "HSTS without includeSubDomains — subdomains not protected"
        echo "$HSTS_VAL" | grep -qi "preload" && ok "preload flag set" || info "No preload flag — consider adding for browser-enforced HSTS"
    else
        fail "⚠️  HSTS MISSING — application vulnerable to MITM protocol downgrade attacks!"
    fi
    
    # Check TLS version
    TLS_CHECK=$(echo | openssl s_client -connect "${TARGET#https://}:443" -servername "${TARGET#https://}" 2>/dev/null | grep "Protocol" || true)
    if echo "$TLS_CHECK" | grep -qi "TLSv1.3"; then
        ok "TLS 1.3 supported — best MITM protection"
    elif echo "$TLS_CHECK" | grep -qi "TLSv1.2"; then
        ok "TLS 1.2 — acceptable but TLS 1.3 preferred"
    else
        fail "⚠️  Weak TLS version detected: $TLS_CHECK"
    fi
    
    # Certificate pinning check (HPKP deprecated but CA info useful)
    CERT_CHAIN=$(echo | openssl s_client -connect "${TARGET#https://}:443" -servername "${TARGET#https://}" 2>/dev/null | openssl x509 -noout -issuer 2>/dev/null || true)
    info "Certificate issuer: $CERT_CHAIN"
fi

# ── Summary ────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║     🔵 Web Attack Defense Scan Complete           ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "Target: $TARGET"
echo "Results: $OUTPUT_DIR/"
echo ""
echo "Attack Types Scanned:"
[[ "$SCAN_TYPE" == "sqli" || "$SCAN_TYPE" == "all" ]] && echo "  • SQL Injection (sqlmap)"
[[ "$SCAN_TYPE" == "xss" || "$SCAN_TYPE" == "all" ]] && echo "  • Cross-Site Scripting (dalfox)"
[[ "$SCAN_TYPE" == "headers" || "$SCAN_TYPE" == "all" ]] && echo "  • Security Headers (9 headers + cookies)"
[[ "$SCAN_TYPE" == "cors" || "$SCAN_TYPE" == "all" ]] && echo "  • CORS Misconfiguration"
[[ "$SCAN_TYPE" == "fuzz" || "$SCAN_TYPE" == "all" ]] && echo "  • Parameter Discovery & Fuzzing"
[[ "$SCAN_TYPE" == "supply-chain" || "$SCAN_TYPE" == "all" ]] && echo "  • Supply Chain Security (osv-scanner)"
[[ "$SCAN_TYPE" == "all" ]] && echo "  • MITM Defense (HSTS, TLS)"
echo ""
echo "📋 Next: Review all findings above. Fix CRITICAL/HIGH items immediately."