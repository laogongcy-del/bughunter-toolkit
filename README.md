# 🛡️ BugBounty Toolkit

> White-hat bug bounty toolkit — Comprehensive methodology, automation scripts, and practical techniques from recon to vulnerability detection

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](.github/CONTRIBUTING.md)
[![Maintenance](https://img.shields.io/badge/maintained-yes-green.svg)](https://github.com/laogongcy-del/bughunter-toolkit)

[中文版](README_CN.md)

---

## 📋 Table of Contents

- [Why This Project](#why-this-project)
- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [Use Cases](#use-cases)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)

---

## 🎯 Why This Project

Real-world experience and lessons learned from bug bounty hunting, organized into a systematic knowledge base and toolset. Goals:

1. **Systematize Knowledge** — Turn scattered techniques into structured methodology
2. **Automate Tools** — One-click execution for repetitive tasks, focus on core vulnerabilities
3. **Pass Down Experience** — Newcomers can build on existing knowledge without repeating mistakes

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- Bash (Linux/macOS/WSL)

### One-Click Install

```bash
git clone https://github.com/laogongcy-del/bughunter-toolkit.git
cd bughunter-toolkit
pip install -r requirements.txt
```

### Quick Usage

```bash
# One-click recon
bash scripts/recon/full_recon.sh example.com

# Extract API endpoints from JavaScript
python scripts/js-tools/js_api_extractor.py -u https://example.com/app.js

# Mass IDOR detection
python scripts/scanners/mass_idor.py -l urls.txt -c cookies.txt

# WAF bypass testing
python scripts/utils/waf_bypass.py -u https://example.com/admin
```

### Docker

```bash
docker-compose up -d
docker exec -it bugbounty-toolkit bash
```

---

---

## 📂 Project Structure

```
bughunter-toolkit/
├── methodology/          # 📖 Hunting methodology
│   ├── 01-recon.md           — Reconnaissance workflow
│   ├── 02-js-analysis.md     — JS endpoint analysis
│   ├── 03-api-testing.md     — API security testing
│   ├── 04-chained-attacks.md — Attack chain thinking
│   └── 05-business-logic.md  — Business logic flaws
│
├── techniques/           # 🔓 Vulnerability techniques
│   ├── 01-waf-bypass.md      — WAF/403 bypass manual
│   ├── 02-idor.md            — IDOR detection
│   ├── 03-jwt-attacks.md     — JWT attack techniques
│   ├── 04-graphql.md         — GraphQL security testing
│   ├── 05-oauth.md           — OAuth 2.0 testing
│   └── 06-race-condition.md  — Race condition bugs
│
├── scripts/              # ⚡ Automation tools
│   ├── recon/                — Reconnaissance
│   ├── scanners/             — Vulnerability scanners
│   ├── js-tools/             — JavaScript analysis
│   └── utils/                — Utility functions
│
├── wordlists/            # 📚 Custom wordlists
├── templates/            # 📝 Report templates
├── case-studies/         # 🎯 Real-world case studies
├── cheatsheets/          # 📋 Quick reference guides
└── config/               # ⚙️ Tool configuration
```

---

## 🎬 Use Cases

| Scenario | Command | Est. Time |
|----------|---------|-----------|
| New target recon | `bash scripts/recon/full_recon.sh target.com` | 5-15min |
| JS API extraction | `python scripts/js-tools/js_api_extractor.py -u URL` | 1-2min |
| Mass IDOR testing | `python scripts/scanners/mass_idor.py -l urls.txt` | 3-10min |
| 403/WAF bypass | See `techniques/01-waf-bypass.md` | - |
| Write report | See `templates/HackerOne.md` | 10min |

---

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](.github/CONTRIBUTING.md)

---

## ⚠️ Disclaimer

This project is intended for **authorized security testing, CTF competitions, and security research ONLY**. Users must comply with all applicable local, state, and federal laws. The authors assume no liability for any misuse or damage caused by this software.

---

## 📜 Acknowledgments

- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — Payload reference
- [ProjectDiscovery](https://github.com/projectdiscovery) — Excellent open-source tools
- All bug bounty hunters who share their knowledge 🙏
