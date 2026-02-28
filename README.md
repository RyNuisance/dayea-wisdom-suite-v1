# 🌟 Dayea Wisdom Suite
### Professional Security Testing Framework

*Named for Dayea, the Filipino goddess of wisdom.*
*Because real security takes more than tools - it takes understanding.*

---

> ⚠️ **This is an ongoing project and still actively in development.**
> Features are being added regularly. Feedback and contributions are welcome.

---

## 📌 What Is This?

Dayea Wisdom Suite is an open-source penetration testing framework built to help security professionals find and fix vulnerabilities before attackers do.

It was born from a simple idea and a military mindset - *do with what you have.* Built by a security professional, not a developer, leveraging AI to turn an idea into a working tool in under an hour. This project is proof that domain expertise combined with modern AI tools can produce real, professional-grade results without an engineering team.

The suite runs entirely through a clean, browser-based dashboard and produces professional PDF reports suitable for sharing with clients and stakeholders.

---

## ⚠️ Legal Disclaimer

**READ THIS BEFORE USING.**

This tool is designed exclusively for **authorized security testing**. By downloading, installing, or using Dayea Wisdom Suite, you agree to the following:

- You will **only** run scans against systems you **own** or have **explicit written permission** to test
- You understand that unauthorized scanning, probing, or testing of systems you do not own is **illegal** in most countries, including under the Computer Fraud and Abuse Act (CFAA) in the United States, the Computer Misuse Act in the United Kingdom, and equivalent laws worldwide
- The author of this tool accepts **no liability** for misuse, damage, or legal consequences resulting from unauthorized or improper use
- This tool is intended for professional security assessments, CTF (Capture the Flag) competitions, home lab environments, and authorized penetration testing engagements only

**If you do not have written authorization - do not scan. Full stop.**

---

## 🚫 No Support / No Warranty

This project is provided as-is with absolutely no guarantee of support,
maintenance, or continued development.

The author is under no obligation to:
- Fix bugs or resolve issues
- Respond to questions or feature requests
- Provide updates or security patches
- Ensure compatibility with future software versions

This is a personal project shared freely with the community. Use it,
learn from it, and build on it — but do not rely on it for production
security operations without independent validation and testing.

All use is entirely at your own risk.

---

## 📢 Personal Disclaimer

This is a personal project and does not represent the views, standards,
practices, or opinions of any employer, client, or organization — past,
present, or future. It is not affiliated with any company or institution.

---

## 🛡️ Modules

| Module | Name | What It Does | Status |
|---|---|---|---|
| 1 | 🗺️ Recon | Network discovery, port scanning, service identification | ✅ Complete |
| 2 | 🔍 Intel | CVE lookup via NVD, banner analysis, vulnerability assessment | ✅ Complete |
| 3 | 🌐 Breach | OWASP Top 10 web application scanning | ✅ Complete |
| 4 | 📄 Debrief | Professional PDF report generation | ✅ Complete |

> More modules are planned and in development. Watch this repo for updates.

---

## ✨ Features

- **Browser-based dashboard** - clean, professional interface accessible from any device on the network
- **Real-time scan updates** - findings appear live as they are discovered, no waiting for a scan to finish
- **Three-gate authorization system** - scope lock, permission confirmation, and legal acknowledgment before any scan runs
- **NVD API integration** - queries the US Government's National Vulnerability Database for live CVE data
- **OWASP Top 10 testing** - SQL injection, XSS, path traversal, open redirect, CORS, sensitive file exposure, security headers, admin panel discovery, and more
- **Professional PDF reports** - executive summary, risk grade, prioritised remediation roadmap, and detailed findings
- **Full audit logging** - every action is timestamped and recorded
- **Cross-platform** - runs on Windows, macOS, and Linux

---

## ⚡ Installation Guide

This guide walks you through everything from scratch. If you have never installed a Python tool before, follow every step in order.

---

### Step 1 — Install Python

Dayea Wisdom Suite is built in Python. You need Python 3.10 or newer.

**Check if you already have Python:**

Open a terminal (Command Prompt on Windows, Terminal on Mac/Linux) and type:

```bash
python --version
```

If you see `Python 3.10` or higher — skip to Step 2.

If you get an error or see Python 2.x — download Python from:
```
https://www.python.org/downloads
```

> **Windows users:** During installation, check the box that says **"Add Python to PATH"** — this is important.

---

### Step 2 — Download Dayea Wisdom Suite

**Option A — Download the ZIP (easiest):**
1. Click the green **Code** button at the top of this page
2. Click **Download ZIP**
3. Unzip the folder somewhere on your computer (e.g. your Desktop)

**Option B — Clone with Git (if you know Git):**
```bash
git clone https://github.com/YOUR-USERNAME/dayea-wisdom-suite.git
cd dayea-wisdom-suite
```

---

### Step 3 — Open a Terminal in the Project Folder

**Windows:**
1. Open the unzipped `DayeaWisdomSuite_FINAL` folder
2. Click the address bar at the top of the File Explorer window
3. Type `cmd` and press Enter — a terminal opens in that folder

**Mac:**
1. Open the unzipped folder in Finder
2. Right-click the folder
3. Select **New Terminal at Folder**

**Linux:**
```bash
cd /path/to/DayeaWisdomSuite_FINAL
```

---

### Step 4 — Install Dependencies

Dependencies are small Python libraries the tool needs to run. Install them with one command:

```bash
pip install flask requests reportlab
```

This takes about 30 seconds. You should see a success message at the end.

> **If pip is not found**, try: `pip3 install flask requests reportlab`

> **If you get a permissions error on Mac/Linux**, try: `pip install --user flask requests reportlab`

---

### Step 5 — Run the Dashboard

```bash
python app.py
```

You should see output like:
```
* Running on http://127.0.0.1:5000
```

Now open your browser and go to:
```
http://localhost:5000
```

The Dayea Wisdom Suite dashboard will load. ✅

> **If python is not found**, try: `python3 app.py`

---

### Step 6 (Optional) — Get a Free NVD API Key

The Intel module queries the US Government's vulnerability database (NVD).
It works without a key but is rate-limited to 5 requests per 30 seconds.

A free API key raises this to 50 requests per 30 seconds.

**To get a free key:**
1. Go to: `https://nvd.nist.gov/developers/request-an-api-key`
2. Enter your email and submit
3. Check your email for the key
4. Open `config/settings.json` and add your key:

```json
{
  "nvd_api_key": "YOUR-KEY-HERE"
}
```

---

### Requirements Summary

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.10+ | Free at python.org |
| flask | Latest | Installed via pip |
| requests | Latest | Installed via pip |
| reportlab | Latest | Installed via pip |

### Platform Support

| Platform | Status |
|---|---|
| Windows 10/11 | ✅ Fully supported |
| macOS 12+ | ✅ Fully supported |
| Linux (Ubuntu/Debian) | ✅ Fully supported |
| Linux (Other) | ✅ Should work |

---

### Run the CLI Version (Alternative)

If you prefer a command-line interface instead of the browser dashboard:

```bash
python main.py
```

---

### Troubleshooting

**Port 5000 already in use:**
Another application is using port 5000. Either close it, or edit `app.py` and change `port=5000` to `port=5001`, then go to `http://localhost:5001`.

**Module not found errors:**
Run the pip install command again from Step 4 and make sure you are in the correct folder.

**Permission denied errors on scan:**
Some network operations require elevated privileges. On Mac/Linux try:
```bash
sudo python app.py
```

**Cannot reach NVD API:**
Check your internet connection. The Intel module requires internet access to query the vulnerability database.

---

## 📁 Project Structure

```
dayea-wisdom-suite/
│
├── app.py                    - Flask web server and API
├── main.py                   - CLI entry point
│
├── modules/
│   ├── scout.py              - Network scanner
│   ├── inspector.py          - Vulnerability assessment engine
│   ├── nvd_client.py         - NVD API client
│   ├── web_tester.py         - OWASP Top 10 web scanner
│   └── reporter.py           - PDF report generator
│
├── core/
│   ├── authorization.py      - Authorization gate and audit trail
│   ├── logger.py             - Session logging
│   ├── config_loader.py      - Settings management
│   └── menu.py               - CLI menu system
│
├── config/
│   ├── settings.json         - User configuration
│   ├── vuln_db.json          - Local vulnerability database
│   └── web_payloads.json     - Web testing payload library
│
├── templates/
│   └── index.html            - Dashboard UI
│
├── reports/                  - Scan reports saved here
└── logs/                     - Activity logs saved here
```

---

## ⚙️ Configuration

Edit `config/settings.json` to customize behavior:

| Setting | What It Does | Default |
|---|---|---|
| scan_speed | How fast to scan: slow, normal, fast | normal |
| scan_timeout | Seconds to wait for responses | 30 |
| port_range | Which ports to scan | 1-1024 |
| max_threads | Parallel scan threads | 10 |
| web_test_depth | How deep to crawl websites | 2 |
| output_dir | Where to save reports | reports/ |

---

## 🌐 NVD API Key (Optional but Recommended)

Intel module queries the National Vulnerability Database (NVD) for live CVE data. This works without an API key but is rate-limited to 5 requests per 30 seconds.

For faster lookups, get a free API key at:
```
https://nvd.nist.gov/developers/request-an-api-key
```

Then add it to your settings:
```json
{
  "nvd_api_key": "your-key-here"
}
```

---

## 💻 Supported Platforms

| Platform | Versions | Notes |
|---|---|---|
| Windows | 10, 11, Server 2016+ | Full support |
| macOS | 10.15 Catalina and newer | Full support |
| Linux | Ubuntu, Kali, Debian, CentOS, etc. | Full support - Kali recommended |

---

## 🗺️ Roadmap

This is an active project with more features planned:

- [ ] Automated scheduled scanning
- [ ] Network topology visualization
- [ ] Email report delivery
- [ ] Docker container support
- [ ] Additional web application tests
- [ ] Custom plugin/module support
- [ ] Expanded vulnerability database
- [ ] API authentication testing

Have a feature idea? Open an issue and let's talk about it.

---

## 🤝 Contributing

Contributions are welcome. This is a community tool built for the security community.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

Please ensure any contributions follow the responsible disclosure principles this project is built on. No offensive payloads, no exploitation code.

---

## 📄 License

This project is licensed under the MIT License. See `LICENSE` for full details.

In plain English: You are free to use, copy, modify, and distribute this software. You must include the original license and copyright notice. The author provides no warranty and accepts no liability for misuse.

---

## 👤 Author

Built by a security professional and military veteran, with the belief that good tools should be accessible to everyone who needs them - not just large enterprises with big budgets.

AI-assisted development using Claude by Anthropic.

---

## ⭐ Support the Project

If this tool is useful to you, consider starring the repository. It helps others find it and keeps the project visible.

And always - test responsibly. 🌟
