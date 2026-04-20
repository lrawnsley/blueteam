#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# 🔵 SSL/TLS Security Check — Analyze TLS configuration of a target
# Checks: protocol versions, cipher suites, certificates, HSTS
# USAGE: ./ssl-check.sh <host:port>
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[SSL]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; }

TARGET="${1:?Usage: $0 <host:port>}"
# Default to port 443 if not specified
[[ "$TARGET" != *":"* ]] && TARGET="${TARGET}:443"
HOST="${TARGET%%:*}"
PORT="${TARGET##*:}"
OUTPUT_DIR="./scan-results/ssl-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║     🔵 SSL/TLS Check: $HOST:$PORT"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# ── Certificate Information ─────────────────────────────────────
info "═══ Certificate Information ═══"
CERT_INFO=$(echo | openssl s_client -connect "$TARGET" -servername "$HOST" 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null || true)

if [[ -n "$CERT_INFO" ]]; then
    SUBJECT=$(echo "$CERT_INFO" | grep "subject=" | head -1)
    ISSUER=$(echo "$CERT_INFO" | grep "issuer=" | head -1)
    NOT_AFTER=$(echo "$CERT_INFO" | grep "notAfter=" | head -1)
    
    ok "Subject: $SUBJECT"
    ok "Issuer: $ISSUER"
    ok "Expiry: $NOT_AFTER"
    
    # Check expiry
    EXPIRY_EPOCH=$(echo | openssl s_client -connect "$TARGET" -servername "$HOST" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || true)
    if [[ -n "$EXPIRY_EPOCH" ]]; then
        EXPIRY_SECONDS=$(( $(date -j -f "%b %d %T %Y %Z" "$EXPIRY_EPOCH" +%s 2>/dev/null || date -d "$EXPIRY_EPOCH" +%s 2>/dev/null || echo 0) - $(date +%s) ))
        EXPIRY_DAYS=$(( EXPIRY_SECONDS / 86400 ))
        if [[ "$EXPIRY_DAYS" -lt 0 ]]; then
            fail "Certificate EXPIRED $(( -EXPIRY_DAYS )) days ago!"
        elif [[ "$EXPIRY_DAYS" -lt 30 ]]; then
            warn "Certificate expires in $EXPIRY_DAYS days — renew soon"
        elif [[ "$EXPIRY_DAYS" -lt 90 ]]; then
            info "Certificate expires in $EXPIRY_DAYS days"
        else
            ok "Certificate valid for $EXPIRY_DAYS days"
        fi
    fi
else
    fail "Could not retrieve certificate information"
fi

# ── Protocol Versions ──────────────────────────────────────────
info "═══ Protocol Versions ═══"
for proto in ssl3 tls1 tls1_1 tls1_2 tls1_3; do
    case "$proto" in
        ssl3)   PROTO_OPT="ssl3" ;;
        tls1)   PROTO_OPT="tls1" ;;
        tls1_1) PROTO_OPT="tls1_1" ;;
        tls1_2) PROTO_OPT="tls1_2" ;;
        tls1_3) PROTO_OPT="tls1_3" ;;
    esac
    
    RESULT=$(echo | openssl s_client -connect "$TARGET" -servername "$HOST" -"$PROTO_OPT" 2>&1 || true)
    if echo "$RESULT" | grep -q "Cipher is\|Cipher:"; then
        case "$proto" in
            ssl3|tls1|tls1_1) fail "$proto is SUPPORTED — should be DISABLED (insecure)" ;;
            tls1_2|tls1_3) ok "$proto is supported" ;;
        esac
    else
        case "$proto" in
            ssl3|tls1|tls1_1) ok "$proto disabled (expected)" ;;
            tls1_2|tls1_3) warn "$proto not supported" ;;
        esac
    fi
done

# ── Cipher Suites ──────────────────────────────────────────────
info "═══ Cipher Suites ═══"
CIPHERS=$(echo | openssl s_client -connect "$TARGET" -servername "$HOST" 2>/dev/null | grep "Cipher is\|Cipher:" | head -1 || true)
if [[ -n "$CIPHERS" ]]; then
    ok "Negotiated cipher: $CIPHERS"
else
    warn "Could not determine cipher suite"
fi

# ── HSTS Check ──────────────────────────────────────────────────
info "═══ HTTP Security Headers ═══"
HEADERS=$(curl -sI "https://$TARGET" 2>/dev/null || true)
if echo "$HEADERS" | grep -qi "strict-transport-security"; then
    HSTS=$(echo "$HEADERS" | grep -i "strict-transport-security" | tr -d '\r')
    ok "HSTS enabled: $HSTS"
else
    warn "HSTS not enabled — add Strict-Transport-Security header"
fi

if echo "$HEADERS" | grep -qi "content-security-policy"; then
    ok "Content-Security-Policy header present"
else
    warn "Content-Security-Policy header missing"
fi

if echo "$HEADERS" | grep -qi "x-frame-options"; then
    ok "X-Frame-Options header present"
else
    warn "X-Frame-Options header missing — clickjacking possible"
fi

# ── testssl.sh (if available) ──────────────────────────────────
if command -v testssl &>/dev/null || [[ -x ./testssl.sh ]]; then
    info "═══ Deep Analysis (testssl.sh) ═══"
    TESTSSL="testssl"
    command -v testssl &>/dev/null || TESTSSL="./testssl.sh"
    $TESTSSL --quiet --severity low "$TARGET" > "$OUTPUT_DIR/testssl-report.txt" 2>/dev/null || true
    ok "testssl.sh report saved to $OUTPUT_DIR/testssl-report.txt"
fi

# ── Summary ────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║       🔵 SSL/TLS Check Complete                 ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "Results: $OUTPUT_DIR/"
echo ""
echo "⚠️  Review any FAILED items above and remediate immediately."