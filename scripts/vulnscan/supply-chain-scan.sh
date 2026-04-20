#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# 🔵 Supply Chain Security Scanner — Blue Team
# Audits dependencies for known CVEs, malicious packages, and
# supply chain misconfigurations using osv-scanner, chain-bench,
# guarddog, and grype/syft SBOM analysis.
# USAGE: ./supply-chain-scan.sh --path /path/to/project [--mode quick|full]
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[SUPPLY]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail()  { echo -e "${RED}[VULN]${NC} $*"; }

SCAN_PATH="."
MODE="quick"
OUTPUT_DIR="./scan-results/supplychain-$(date +%Y%m%d_%H%M%S)"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --path)  SCAN_PATH="$2"; shift 2 ;;
        --mode)  MODE="$2"; shift 2 ;;
        -h|--help) echo "Usage: $0 --path /project [--mode quick|full]"; exit 0 ;;
        *)       fail "Unknown: $1"; exit 1 ;;
    esac
done

if [[ ! -d "$SCAN_PATH" ]]; then
    fail "Path does not exist: $SCAN_PATH"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║     🔵 Supply Chain Security Scanner             ║"
echo "║     Path: $SCAN_PATH  Mode: $MODE"
echo "╚══════════════════════════════════════════════════╝"
echo ""

VULN_COUNT=0

# ═══════════════════════════════════════════════════════════════════
# OSV-SCANNER — Google's OSV database CVE scanner
# ═══════════════════════════════════════════════════════════════════
if command -v osv-scanner &>/dev/null; then
    info "═══ OSV Vulnerability Scanner ═══"
    osv-scanner scan --root "$SCAN_PATH" \
        --format json \
        --output "$OUTPUT_DIR/osv-results.json" \
        2>/dev/null || true
    
    if [[ -f "$OUTPUT_DIR/osv-results.json" ]]; then
        VULNS=$(python3 -c "
import json,sys
try:
    d=json.load(open('$OUTPUT_DIR/osv-results.json'))
    count=sum(len(p.get('packages',[{}])[0].get('vulnerabilities',[])) for p in d.get('results',[]))
    print(count)
except: print(0)
" 2>/dev/null)
        if [[ "$VULNS" -gt 0 ]]; then
            fail "⚠️  $VULNS known vulnerabilities found via OSV database!"
            VULN_COUNT=$((VULN_COUNT + VULNS))
            # Show summary
            python3 -c "
import json
d=json.load(open('$OUTPUT_DIR/osv-results.json'))
for r in d.get('results',[]):
    for pkg in r.get('packages',[]):
        name=pkg.get('package',{}).get('name','?')
        ver=pkg.get('package',{}).get('version','?')
        for v in pkg.get('vulnerabilities',[]):
            sid=v.get('id','?')
            sev=v.get('database_specific',{}).get('severity','?')
            print(f'  • {name}@{ver} → {sid} [{sev}]')
" 2>/dev/null || true
        else
            ok "No known vulnerabilities in OSV database"
        fi
    fi
else
    warn "osv-scanner not installed — run ./scripts/install.sh"
fi

# ═══════════════════════════════════════════════════════════════════
# SBOM ANALYSIS — Generate Software Bill of Materials
# ═══════════════════════════════════════════════════════════════════
if [[ "$MODE" == "full" ]]; then
    info "═══ Software Bill of Materials (SBOM) ═══"
    
    if command -v syft &>/dev/null; then
        info "Generating SBOM with syft..."
        syft "$SCAN_PATH" -o json > "$OUTPUT_DIR/sbom.json" 2>/dev/null || true
        syft "$SCAN_PATH" -o spdx-json > "$OUTPUT_DIR/sbom.spdx.json" 2>/dev/null || true
        ok "SBOM generated — $(wc -l < "$OUTPUT_DIR/sbom.json" 2>/dev/null | tr -d ' ') entries"
    else
        warn "syft not installed — run ./scripts/install.sh"
    fi
    
    # Grype — scan SBOM for vulnerabilities
    if command -v grype &>/dev/null && [[ -f "$OUTPUT_DIR/sbom.json" ]]; then
        info "Scanning SBOM for vulnerabilities with grype..."
        grype "sbom:$OUTPUT_DIR/sbom.json" -o json \
            > "$OUTPUT_DIR/grype-results.json" 2>/dev/null || true
        
        if [[ -f "$OUTPUT_DIR/grype-results.json" ]]; then
            HIGH=$(python3 -c "
import json
d=json.load(open('$OUTPUT_DIR/grype-results.json'))
sev_count={}
for m in d.get('matches',[]):
    s=m.get('vulnerability',{}).get('severity','Unknown')
    sev_count[s]=sev_count.get(s,0)+1
for s in ['Critical','High','Medium','Low','Negligible','Unknown']:
    if s in sev_count: print(f'  {s}: {sev_count[s]}')
" 2>/dev/null || true)
            if [[ -n "$HIGH" ]]; then
                fail "Grype vulnerability breakdown:"
                echo "$HIGH"
            else
                ok "No vulnerabilities found by grype"
            fi
        fi
    else
        warn "grype not installed or no SBOM available"
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# MALICIOUS PACKAGE DETECTION
# ═══════════════════════════════════════════════════════════════════
if command -v guarddog &>/dev/null; then
    info "═══ Malicious Package Detection ═══"
    
    # Python packages
    if [[ -f "$SCAN_PATH/requirements.txt" ]]; then
        info "Scanning Python requirements.txt..."
        guarddog pypi scan "$SCAN_PATH/requirements.txt" \
            > "$OUTPUT_DIR/guarddog-pypi.txt" 2>&1 || true
        ok "Python package scan complete"
    fi
    
    # npm packages
    if [[ -f "$SCAN_PATH/package.json" ]]; then
        info "Scanning npm package.json..."
        guarddog npm scan "$SCAN_PATH/package.json" \
            > "$OUTPUT_DIR/guarddog-npm.txt" 2>&1 || true
        ok "npm package scan complete"
    fi
else
    warn "guarddog not installed — pip3 install guarddog"
fi

# ═══════════════════════════════════════════════════════════════════
# SUPPLY CHAIN BEST PRACTICES AUDIT
# ═══════════════════════════════════════════════════════════════════
info "═══ Supply Chain Best Practices ═══"

# Check for lockfiles
for lockfile in "package-lock.json" "yarn.lock" "pnpm-lock.yaml" "poetry.lock" "Pipfile.lock" "go.sum" "Cargo.lock"; do
    if find "$SCAN_PATH" -name "$lockfile" -type f -print -quit 2>/dev/null | grep -q .; then
        ok "Lockfile found: $lockfile"
    else
        warn "Missing lockfile: $lockfile — dependencies not pinned!"
    fi
done

# Check for .gitignore + sensitive files
if [[ -f "$SCAN_PATH/.gitignore" ]]; then
    ok ".gitignore present"
else
    fail "⚠️  No .gitignore — accidental commits of secrets/build artifacts possible"
fi

# Check for hardcoded secrets
info "Checking for potential hardcoded secrets..."
SECRET_PATTERNS=(
    "password\s*=\s*['\"][^'\"]+['\"]"
    "api_key\s*=\s*['\"][^'\"]+['\"]"
    "secret_key\s*=\s*['\"][^'\"]+['\"]"
    "token\s*=\s*['\"][^'\"]{20,}['\"]"
    "-----BEGIN (RSA |EC )?PRIVATE KEY-----"
    "ghp_[0-9a-zA-Z]{36}"
    "sk-[0-9a-zA-Z]{48}"
)
SECRETS_FOUND=0
for pattern in "${SECRET_PATTERNS[@]}"; do
    MATCHES=$(grep -rnE "$pattern" "$SCAN_PATH" --include='*.py' --include='*.js' --include='*.ts' --include='*.env' --include='*.yaml' --include='*.yml' --include='*.json' 2>/dev/null | head -5 || true)
    if [[ -n "$MATCHES" ]]; then
        fail "⚠️  Potential secret found matching: $pattern"
        echo "$MATCHES" | head -5
        SECRETS_FOUND=$((SECRETS_FOUND+1))
    fi
done
[[ "$SECRETS_FOUND" -eq 0 ]] && ok "No obvious hardcoded secrets found"

# Check for pinned versions vs ranges
if [[ -f "$SCAN_PATH/requirements.txt" ]]; then
    UNPINNED=$(grep -cE '^[a-zA-Z]' "$SCAN_PATH/requirements.txt" 2>/dev/null || echo 0)
    PINNED=$(grep -cE '^[a-zA-Z]+==' "$SCAN_PATH/requirements.txt" 2>/dev/null || echo 0)
    if [[ "$UNPINNED" -gt 0 ]]; then
        warn "$UNPINNED unpinned dependencies in requirements.txt (should use == for exact versions)"
    else
        ok "All Python dependencies pinned in requirements.txt"
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# CHAIN-BENCH — CIS Software Supply Chain Benchmark
# ═══════════════════════════════════════════════════════════════════
if [[ "$MODE" == "full" ]]; then
    if command -v chain-bench &>/dev/null; then
        info "═══ CIS Supply Chain Benchmark ═══"
        chain-bench check --repository "$SCAN_PATH" \
            --output-format json \
            > "$OUTPUT_DIR/chain-bench-results.json" 2>/dev/null || true
        ok "Supply chain benchmark complete"
    else
        warn "chain-bench not installed — run ./scripts/install.sh"
    fi
fi

# ── Summary ────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║     🔵 Supply Chain Scan Complete                ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "Project: $SCAN_PATH"
echo "Mode:    $MODE"
echo "Results: $OUTPUT_DIR/"
if [[ "$VULN_COUNT" -gt 0 ]]; then
    echo ""
    fail "🚨 $VULN_COUNT total vulnerabilities found — review results!"
else
    echo ""
    ok "No critical supply chain vulnerabilities detected"
fi
echo ""
echo "Tools used:"
echo "  • osv-scanner  — OSV database CVE scanning"
[[ "$MODE" == "full" ]] && echo "  • syft        — SBOM generation"
[[ "$MODE" == "full" ]] && echo "  • grype       — SBOM vulnerability scanning"
echo "  • guarddog    — Malicious package detection"
echo "  • Pattern scan — Hardcoded secrets check"
[[ "$MODE" == "full" ]] && echo "  • chain-bench — CIS supply chain benchmark"