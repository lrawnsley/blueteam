#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# 🔵 DNS Security Check — Validate DNS configuration and detect issues
# Checks: DNS hijacking, DNSSEC, zone transfer, SPF/DMARC/DKIM, CAA
# USAGE: ./dns-security-check.sh <domain>
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[DNS]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; }

DOMAIN="${1:?Usage: $0 <domain>}"
OUTPUT_DIR="./scan-results/dns-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║     🔵 DNS Security Check: $DOMAIN"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# ── DNS Resolution ───────────────────────────────────────────────
info "═══ DNS Resolution ═══"
dig "$DOMAIN" +short > "$OUTPUT_DIR/a-records.txt" 2>/dev/null
A_RECORDS=$(wc -l < "$OUTPUT_DIR/a-records.txt" | tr -d ' ')
if [[ "$A_RECORDS" -gt 0 ]]; then
    ok "A records found: $(cat "$OUTPUT_DIR/a-records.txt" | tr '\n' ', ' | sed 's/,$//')"
else
    fail "No A records found for $DOMAIN"
fi

dig "$DOMAIN" AAAA +short > "$OUTPUT_DIR/aaaa-records.txt" 2>/dev/null
AAAA_COUNT=$(wc -l < "$OUTPUT_DIR/aaaa-records.txt" | tr -d ' ')
[[ "$AAAA_COUNT" -gt 0 ]] && ok "IPv6 (AAAA) supported" || warn "No IPv6 (AAAA) records"

# ── DNSSEC Validation ───────────────────────────────────────────
info "═══ DNSSEC ═══"
DNSKEY=$(dig "$DOMAIN" DNSKEY +short 2>/dev/null)
if [[ -n "$DNSKEY" ]]; then
    ok "DNSKEY records found — DNSSEC may be configured"
    # Verify DNSSEC validation
    dig "$DOMAIN" +dnssec +short | grep -q "RRSIG" && ok "DNSSEC signatures present" || warn "DNSKEY found but no RRSIG — DNSSEC may not be fully configured"
else
    fail "No DNSKEY records — DNSSEC not configured. This domain is vulnerable to DNS spoofing."
fi

# ── Zone Transfer Test ───────────────────────────────────────────
info "═══ Zone Transfer ═══"
NS_SERVERS=$(dig "$DOMAIN" NS +short 2>/dev/null)
for ns in $NS_SERVERS; do
    info "Testing zone transfer on $ns..."
    AXFR=$(dig "@$ns" "$DOMAIN" AXFR +timeout=5 2>/dev/null | grep -c "XFR" || true)
    if [[ "$AXFR" -gt 0 ]]; then
        fail "⚠️  Zone transfer ALLOWED on $ns — this leaks all DNS records! Disable AXFR immediately."
    else
        ok "Zone transfer denied on $ns (expected)"
    fi
done

# ── Email Security (SPF, DMARC, DKIM) ───────────────────────────
info "═══ Email Security ═══"

# SPF
SPF=$(dig "$DOMAIN" TXT +short 2>/dev/null | grep -i "v=spf1" || true)
if [[ -n "$SPF" ]]; then
    ok "SPF record found: $SPF"
    echo "$SPF" | grep -q "\~all" && ok "SPF uses softfail (~all)" || \
    echo "$SPF" | grep -q "\-all" && ok "SPF uses hardfail (-all)" || \
    warn "SPF does not end with ~all or -all"
else
    fail "No SPF record — domain is vulnerable to email spoofing"
fi

# DMARC
DMARC=$(dig "_dmarc.$DOMAIN" TXT +short 2>/dev/null | grep -i "v=dmarc1" || true)
if [[ -n "$DMARC" ]]; then
    ok "DMARC record found: $DMARC"
else
    fail "No DMARC record — email authentication not enforced"
fi

# DKIM
DKIM=$(dig "default._domainkey.$DOMAIN" TXT +short 2>/dev/null | grep -i "v=dkim1" || true)
if [[ -n "$DKIM" ]]; then
    ok "DKIM record found"
else
    warn "No DKIM record found (may use different selector)"
fi

# ── CAA Records ─────────────────────────────────────────────────
info "═══ CAA (Certificate Authority Authorization) ═══"
CAA=$(dig "$DOMAIN" CAA +short 2>/dev/null || true)
if [[ -n "$CAA" ]]; then
    ok "CAA records found: $CAA"
else
    warn "No CAA records — any CA can issue certificates for this domain"
fi

# ── Subdomain Enumeration ───────────────────────────────────────
info "═══ Subdomain Check ═══"
COMMON_SUBS="www mail ftp vpn remote api dev staging test admin portal intranet git ci cd blog shop store app mobile m db redis es kafka rabbitmq mongo mysql pg phoenix"
FOUND_SUBS=""
for sub in $COMMON_SUBS; do
    IP=$(dig "${sub}.${DOMAIN}" +short 2>/dev/null | head -1)
    if [[ -n "$IP" && "$IP" != "0.0.0.0" && "$IP" != "NXDOMAIN" ]]; then
        FOUND_SUBS="$FOUND_SUBS ${sub}.${DOMAIN} (${IP})"
    fi
done
if [[ -n "$FOUND_SUBS" ]]; then
    warn "Public subdomains found:$FOUND_SUBS"
    warn "Ensure each subdomain is intentionally public and properly secured"
else
    ok "No common subdomains found (good for reducing attack surface)"
fi

# ── Summary ────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║       🔵 DNS Security Check Complete            ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "Results: $OUTPUT_DIR/"
echo ""
echo "Priority Actions:"
[[ -z "$DNSKEY" ]] && echo "  🔴 Enable DNSSEC to prevent DNS spoofing"
[[ -z "$SPF" ]] && echo "  🔴 Add SPF record to prevent email spoofing"
[[ -z "$DMARC" ]] && echo "  🔴 Add DMARC record to enforce email authentication"
[[ -z "$CAA" ]] && echo "  🟡 Add CAA record to restrict certificate issuance"
[[ -n "$FOUND_SUBS" ]] && echo "  🟡 Review public subdomains for unnecessary exposure"