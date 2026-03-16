# Dayea

### Open Source Security Testing Framework

---

> This is an ongoing project and still actively in development.
> Features are being added regularly. Feedback and contributions are welcome.

---

## What Is This?

Dayea is an open-source penetration testing framework built to help security professionals find and fix vulnerabilities before attackers do.

The tool runs entirely through a clean, browser-based dashboard and produces professional PDF reports suitable for sharing with clients and stakeholders.

---

## Legal Disclaimer

**READ THIS BEFORE USING.**

This tool is designed exclusively for **authorized security testing**. By downloading, installing, or using Dayea, you agree to the following:

- You will **only** run scans against systems you **own** or have **explicit written permission** to test
- Unauthorized scanning is **illegal** under the CFAA (US), Computer Misuse Act (UK), and equivalent laws worldwide
- The author accepts **no liability** for misuse, damage, or legal consequences

**If you do not have written authorization — do not scan.**

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

- **Browser-based dashboard** — clean interface accessible from any device on the network
- **Real-time scan updates** — findings appear live as they are discovered
- **Three-gate authorization system** — scope lock, permission confirmation, and legal acknowledgment
- **NVD API integration** — queries the National Vulnerability Database for live CVE data
- **OWASP Top 10 testing** — SQL injection, XSS, path traversal, and more
- **Professional PDF reports** — executive summary, risk grade, and remediation roadmap
- **Full audit logging** — every action is timestamped and recorded
- **Cross-platform** — Windows, macOS, and Linux

---

## Installation

```bash
git clone https://github.com/dayeagroup/dayea.git
cd dayea
pip install flask requests reportlab
python app.py
```

Open `http://localhost:5000` in your browser.

---

## Project Structure

```
dayea/
  app.py              — Web server (Flask)
  main.py             — CLI entry point
  config/             — Settings and payload databases
  core/               — Authorization, logging, config
  modules/            — Recon, Intel, Breach, Debrief
  templates/          — Dashboard UI
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
