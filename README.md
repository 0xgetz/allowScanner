<div align="center">

![AllowScanner Logo](https://img.shields.io/badge/🛡️-AllowScanner-blue?style=for-the-badge)

# AllowScanner

### Advanced Web Vulnerability Scanner

[![CI](https://github.com/0xgetz/allowScanner/actions/workflows/ci.yml/badge.svg)](https://github.com/0xgetz/allowScanner/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker&logoColor=white)](Dockerfile)

Fast, async web security scanner for vulnerability detection, security header analysis, SSL/TLS auditing, DNS security checks, and more.

</div>

---

## ✨ Features

| Module | Description |
|---|---|
| 🔍 **Vulnerability Scanner** | SQLi, XSS, SSRF, SSTI, Command Injection, XXE, Open Redirect, Directory Traversal |
| 🛡️ **Security Headers** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| 🔐 **SSL/TLS Audit** | Certificate validation, expiry checks, weak ciphers, protocol version |
| 🌐 **DNS Security** | DNSSEC, SPF, DMARC, DKIM, CAA records |
| 🛠️ **Technology Detection** | 30+ frameworks/servers: WordPress, React, Laravel, Nginx, Cloudflare, etc. |
| 🔎 **Subdomain Enum** | DNS-based subdomain discovery (500+ common prefixes) |
| 🍪 **Cookie Security** | Secure, HttpOnly, SameSite attribute checks |
| 🔗 **CORS Analysis** | Wildcard, reflected origin, null origin, credentials misconfiguration |
| 📂 **Sensitive Files** | `.env`, `.git`, `phpinfo.php`, Spring Actuator, Swagger, etc. |
| 🔑 **Admin Panels** | Discover exposed admin/login interfaces |
| 📊 **Security Score** | 0–100 score based on findings |

## 🚀 Quick Start

### Install from source

```bash
git clone https://github.com/0xgetz/allowScanner.git
cd allowScanner
pip install -e .
```

### Run a scan

```bash
# Basic scan
allowscanner https://example.com

# JSON output
allowscanner https://example.com -o report.json -f json

# High concurrency
allowscanner https://example.com -c 100

# Only specific modules
allowscanner https://example.com --only ssl,dns,headers

# Skip subdomain enumeration
allowscanner https://example.com --no-subdomains
```

### Docker

```bash
docker build -t allowscanner .
docker run --rm allowscanner https://example.com
```

## 📖 Usage

```
allowscanner [OPTIONS] URL

Positional:
  url                     Target URL to scan

Options:
  -o, --output FILE       Save report to file
  -f, --format FORMAT     Output format: terminal | json | markdown
  -c, --concurrency N     Max concurrent requests (default: 50)
  -t, --timeout N         Request timeout in seconds (default: 15)
  -v, --verbose           Verbose output
  --no-color              Disable colored output

Module toggles:
  --no-ssl                Skip SSL/TLS checks
  --no-dns                Skip DNS security checks
  --no-headers            Skip security header checks
  --no-vulns              Skip vulnerability scans
  --no-admin              Skip admin panel discovery
  --no-sensitive          Skip sensitive file checks
  --no-tech               Skip technology detection
  --no-subdomains         Skip subdomain enumeration
  --no-cors               Skip CORS checks
  --no-cookies            Skip cookie security checks
  --only MODULES          Only run specific modules (comma-separated)
                          Modules: ssl,dns,headers,vulns,tech,subdomains,cors,cookies,admin,sensitive
```

## 📊 Example Output

```
╭──── 📊 Scan Summary ─────────────────────────────────╮
│  Target: https://example.com                          │
│  Domain: example.com                                  │
│  Duration: 4.2s                                       │
│  Score: 72/100                                        │
╰──────────────────────────────────────────────────────╯

╭──── ⚠️ Vulnerability Summary ────────────────────────╮
│  Critical: 1  High: 2  Medium: 4  Low: 3             │
╰──────────────────────────────────────────────────────╯

┌─── 🔍 Detailed Findings ─────────────────────────────┐
│ #  │ Severity │ Finding              │ CWE    │      │
│────┼──────────┼──────────────────────┼────────│      │
│ 1  │ CRITICAL │ SQL Injection        │ CWE-89 │      │
│ 2  │ HIGH     │ Reflected XSS        │ CWE-79 │      │
│ 3  │ HIGH     │ Weak SSL Cipher      │ CWE-326│      │
│ ...│          │                      │        │      │
└──────────────────────────────────────────────────────┘
```

## 🏗️ Project Structure

```
allowScanner/
├── src/allowscanner/
│   ├── __init__.py          # Package exports
│   ├── cli.py               # CLI entry point
│   ├── scanner.py           # Main orchestrator
│   ├── output.py            # Rich terminal formatter
│   ├── core/
│   │   ├── models.py        # Data models (Vulnerability, ScanResult, etc.)
│   │   └── config.py        # Scan configuration
│   ├── scanners/
│   │   ├── http.py          # Async HTTP client
│   │   ├── vuln.py          # Vulnerability scanner
│   │   ├── ssl.py           # SSL/TLS auditor
│   │   ├── dns.py           # DNS security checker
│   │   ├── headers.py       # Security header analyzer
│   │   ├── tech.py          # Technology detector
│   │   ├── subdomain.py     # Subdomain enumerator
│   │   ├── cors.py          # CORS analyzer
│   │   └── cookies.py       # Cookie security checker
│   └── formatters/
│       └── __init__.py      # JSON formatter
├── tests/
│   └── test_models.py
├── pyproject.toml           # Project config
├── Dockerfile               # Container support
├── LICENSE                  # MIT License
└── README.md
```

## 🛡️ Security Checks

### Vulnerability Detection
- **SQL Injection** — Error-based detection with multiple payloads
- **Cross-Site Scripting (XSS)** — Reflected XSS with DOM-based payloads
- **Server-Side Template Injection** — Jinja2, Twig, ERB, Freemarker
- **SSRF** — Internal metadata endpoints (AWS, GCP, Azure)
- **Command Injection** — OS command injection via shell metacharacters
- **XXE** — XML External Entity injection
- **Directory Traversal** — Path traversal with encoding bypass
- **Open Redirect** — Unvalidated redirect detection
- **Log4Shell** — CVE-2021-44228 detection

### Infrastructure Security
- SSL/TLS certificate health and expiry
- Weak cipher suites and deprecated protocols
- DNSSEC, SPF, DMARC, DKIM, CAA records
- CORS misconfigurations
- Cookie security attributes
- Subdomain enumeration

## ⚠️ Disclaimer

> **This tool is for authorized security testing only.** Only scan targets you own or have explicit permission to test. Unauthorized scanning may violate laws and regulations. Always practice responsible disclosure.

## 📝 License

[MIT](LICENSE) © 2026 0xgetz
