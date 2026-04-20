# 🔵 BlueTeam Toolkit

Defensive cybersecurity toolkit for blue teaming — vulnerability awareness, resolution, patching, network scanning, and all things defensive security. Zero-cost, CLI-first, works on macOS and Linux.

## Philosophy

- **Blue team only** — every tool and script is for defensive purposes: detection, prevention, hardening, and response
- **Zero-cost** — all tools are free/open-source, no paid API keys required
- **CLI-first** — everything runs from the terminal, automatable via cron or Hermes agent
- **Local-first** — runs on your machine, no cloud dependency (except for threat intel feeds with free tiers)

## Quick Start

```bash
# Install all security tools
./scripts/install.sh

# Quick system audit
./scripts/audit/system-audit.sh

# Network reconnaissance (local LAN)
./scripts/recon/network-scan.sh --local

# Vulnerability scan a target (with authorization!)
./scripts/vulnscan/vuln-scan.sh --target 192.168.1.1

# Harden your system
./scripts/hardening/harden-system.sh

# Check DNS security
./scripts/dns/dns-security-check.sh example.com
```

## Tool Categories

| Category | Tools | Scripts |
|----------|-------|---------|
| **Reconnaissance** | nmap, rustscan, naabu, masscan | `recon/network-scan.sh`, `recon/port-sweep.sh` |
| **Vulnerability Scanning** | nuclei, trivy, grype, nikto | `vulnscan/vuln-scan.sh`, `vulnscan/cve-check.sh` |
| **Web App Security** | OWASP ZAP (headless), nikto, whatweb | `vulnscan/webapp-scan.sh` |
| **SSL/TLS Analysis** | testssl.sh, sslscan | `crypto/ssl-check.sh` |
| **DNS Security** | dig, whois, dnstwist | `dns/dns-security-check.sh` |
| **Hardening** | lynis, CIS benchmarks | `hardening/harden-system.sh`, `hardening/cis-audit.sh` |
| **Password Auditing** | hashcat, john the ripper | `audit/password-audit.sh` |
| **Container Security** | trivy, grype, dockle | `vulnscan/container-scan.sh` |
| **Threat Intelligence** | curl + free APIs | `recon/threat-intel.sh` |
| **Incident Response** | custom scripts | `incident/ir-toolkit.sh` |
| **System Audit** | lynis, custom checks | `audit/system-audit.sh` |

## Directory Structure

```
blueteam/
├── README.md
├── scripts/
│   ├── install.sh              # Install all security tools
│   ├── recon/
│   │   ├── network-scan.sh      # Full network reconnaissance
│   │   ├── port-sweep.sh        # Quick port discovery
│   │   └── threat-intel.sh      # Free threat intelligence feeds
│   ├── vulnscan/
│   │   ├── vuln-scan.sh         # Multi-scanner vulnerability assessment
│   │   ├── cve-check.sh         # Check software versions against CVEs
│   │   ├── webapp-scan.sh       # Web application security scanner
│   │   └── container-scan.sh   # Docker/container security
│   ├── hardening/
│   │   ├── harden-system.sh     # OS hardening script
│   │   └── cis-audit.sh         # CIS benchmark audit
│   ├── dns/
│   │   └── dns-security-check.sh # DNS hijacking/SEC/zone checks
│   ├── crypto/
│   │   └── ssl-check.sh         # SSL/TLS configuration analysis
│   ├── audit/
│   │   ├── system-audit.sh      # Full system security audit
│   │   └── password-audit.sh    # Password strength auditing
│   └── incident/
│       └── ir-toolkit.sh         # Incident response toolkit
└── docs/
    ├── tool-reference.md        # Detailed tool command reference
    └── methodology.md           # Blue team methodology guide
```

## ⚠️ Legal Notice

**Only scan systems you own or have explicit written authorization to test.** Unauthorized scanning is illegal. All tools in this toolkit are designed for **defensive security** — hardening your own systems, detecting vulnerabilities before attackers do, and responding to incidents.

## License

MIT