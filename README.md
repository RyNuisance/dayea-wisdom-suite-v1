# Dayea

### Open Source Security Testing Framework

---

> This is an ongoing project and still actively in development.
> Features are being added regularly. Feedback and contributions are welcome.

---

## What Is This?

Dayea is an open-source penetration testing framework built to help security professionals find and fix vulnerabilities before attackers do.

It was born from a simple idea and a military mindset — *do with what you have.* Built by a security professional, not a developer, leveraging AI to turn an idea into a working tool. This project is proof that domain expertise combined with modern AI tools can produce real, professional-grade results without an engineering team.

The tool runs entirely through a clean, browser-based dashboard and produces professional PDF reports suitable for sharing with clients and stakeholders.

---

## Legal Disclaimer

**READ THIS BEFORE USING.**

This tool is designed exclusively for **authorized security testing**. By downloading, installing, or using Dayea, you agree to the following:

- You will **only** run scans against systems you **own** or have **explicit written permission** to test
- You understand that unauthorized scanning, probing, or testing of systems you do not own is **illegal** in most countries, including under the Computer Fraud and Abuse Act (CFAA) in the United States, the Computer Misuse Act in the United Kingdom, and equivalent laws worldwide
- The author of this tool accepts **no liability** for misuse, damage, or legal consequences resulting from unauthorized or improper use
- This tool is intended for professional security assessments, CTF (Capture the Flag) competitions, home lab environments, and authorized penetration testing engagements only

**If you do not have written authorization — do not scan. Full stop.**

---

## No Support / No Warranty

This project is provided as-is with absolutely no guarantee of support, maintenance, or continued development.

All use is entirely at your own risk.

---

## Modules

| Module | Name | What It Does | Status |
|---|---|---|---|
| 1 | Recon | Network discovery, port scanning, service identification | Complete |
| 2 | Intel | CVE lookup via NVD, banner analysis, vulnerability assessment | Complete |
| 3 | Breach | OWASP Top 10 web application scanning | Complete |
| 4 | Debrief | Professional PDF report generation | Complete |

---

## Features

- **Browser-based dashboard** — clean, professional interface accessible from any device on the network
- **Real-time scan updates** — findings appear live as they are discovered
- **Three-gate authorization system** — scope lock, permission confirmation, and legal acknowledgment before any scan runs
- **NVD API integration** — queries the National Vulnerability Database for live CVE data
- **OWASP Top 10 testing** — SQL injection, XSS, path traversal, open redirect, CORS, sensitive file exposure, security headers, and more
- **Professional PDF reports** — executive summary, risk grade, prioritized remediation roadmap, and detailed findings
- **Full audit logging** — every action is timestamped and recorded
- **Cross-platform** — runs on Windows, macOS, and Linux

---

## Installation

### Step 1 — Install Python

Dayea requires Python 3.10 or newer.

```bash
python --version
```

If you see `Python 3.10` or higher — skip to Step 2. Otherwise download from https://www.python.org/downloads

### Step 2 — Download Dayea

```bash
git clone https://github.com/dayeagroup/dayea.git
cd dayea
```

Or click the green **Code** button and **Download ZIP**.

### Step 3 — Install Dependencies

```bash
pip install flask requests reportlab
```

### Step 4 — Run the Dashboard

```bash
python app.py
```

Open your browser to `http://localhost:5000`

---

## Usage

1. Enter the target IP address or domain
2. Complete the three-gate authorization process
3. Select your scan type (Recon, Intel, Breach, or Full)
4. Review findings in real-time on the dashboard
5. Generate a PDF report when finished

---

## Project Structure

```
dayea/
  app.py              — Web server (Flask)
  main.py             — CLI entry point
  config/
    settings.json     — Tool configuration
    vuln_db.json      — Local vulnerability database
    web_payloads.json — Web testing payloads
  core/
    authorization.py  — Three-gate auth system
    config_loader.py  — Settings manager
    logger.py         — Audit logging
    menu.py           — CLI menu interface
  modules/
    scout.py          — Network reconnaissance (Recon)
    nvd_client.py     — NVD/CVE lookup (Intel)
    inspector.py      — Vulnerability analysis (Intel)
    web_tester.py     — OWASP web testing (Breach)
    reporter.py       — PDF report generation (Debrief)
  templates/
    index.html        — Dashboard UI
  logs/               — Scan logs
  reports/            — Generated PDF reports
```

---

## License

AGPL-3.0. See LICENSE file.

---

## Author

Built by a veteran. For the security community.

https://github.com/dayeagroup
