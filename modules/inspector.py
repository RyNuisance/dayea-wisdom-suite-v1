"""
inspector.py — Intel: Vulnerability Assessment

This is Module 2. Intel takes everything Recon discovered
and asks the most important question:

 "Are any of these services actually VULNERABLE to known attacks?"

Think of Recon as a surveyor who maps a building.
Intel is the structural engineer who looks at that map
and says: "This wall has a crack. That window frame is rotted.
The foundation shows signs of subsidence."

Intel has THREE layers of intelligence:

 Layer 1 — LOCAL DATABASE (config/vuln_db.json)
 Offline checks that run instantly without internet.
 Things we KNOW are dangerous: Telnet, default passwords,
 SMB exposed to internet, Redis without auth, etc.

 Layer 2 — BANNER ANALYSIS
 Recon collected "banners" — what each service says about itself.
 We analyse those to extract version numbers, then check if those
 versions have known vulnerabilities.
 e.g. "Apache/2.2.15" → "Apache 2.2 is end-of-life with 50+ CVEs"

 Layer 3 — NVD API (National Vulnerability Database)
 For anything with a version number, we query the US Government's
 official vulnerability database for matching CVEs.
 This is the "live intelligence" layer — always up to date.
"""

import json
import os
import re
import socket
import time
from datetime import datetime
from modules.nvd_client import NVDClient


# ── Severity ranking (for sorting findings) ──────────────────────
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class VulnerabilityIntel:
 """
 Intel — vulnerability assessment engine.
 
 Designed to run AFTER Recon has collected scan data.
 Can also run standalone with just a scope and port list.
 """

 def __init__(self, settings: dict, logger,
 progress_callback=None, finding_callback=None):
 """
 Set up the Intel.
 
 Args:
 settings: Config dict (scope, timeouts, etc.)
 logger: Toolkit logger
 progress_callback: Called to update the progress bar
 finding_callback: Called when a new vulnerability is found
 """
 self.settings = settings
 self.logger = logger
 self.progress_cb = progress_callback or (lambda p, m: None)
 self.finding_cb = finding_callback or (lambda f: None)

 self.scope = settings.get('scope', [])
 self.timeout = settings.get('scan_timeout', 3)
 self._running = True
 self.findings = []

 # Load our local vulnerability database (works offline)
 self.local_db = self._load_local_db()

 # Set up the NVD API client (requires internet, gracefully optional)
 nvd_api_key = settings.get('nvd_api_key', None)
 self.nvd = NVDClient(logger, api_key=nvd_api_key)

 # ══════════════════════════════════════════════════════════════
 # MAIN RUN METHOD
 # ══════════════════════════════════════════════════════════════

 def run(self, scout_results: dict = None) -> dict:
 """
 Run the full vulnerability assessment.
 
 Args:
 scout_results: Results from Recon (if available).
 If None, Intel performs its own basic scan.
 
 Returns:
 dict: Full assessment report
 """
 self.logger.section("INTEL — VULNERABILITY ASSESSMENT STARTED")
 start_time = time.time()

 # ── Phase 1: Setup ───────────────────────────────────────
 self._update_progress(5, "Preparing vulnerability assessment...")

 # If Recon results were passed in, use them. Otherwise scan ourselves.
 if scout_results and scout_results.get('hosts'):
 hosts = scout_results['hosts']
 self.logger.info(f"Using Recon data: {len(hosts)} host(s) to assess")
 self._update_progress(10, f"Loaded Recon data — {len(hosts)} host(s) to assess")
 else:
 self.logger.info("No Recon data provided — running basic inspection")
 hosts = self._basic_host_discovery()

 if not hosts:
 self._update_progress(100, " No hosts to inspect")
 return {"findings": [], "note": "No hosts available to inspect"}

 total_hosts = len(hosts)

 # ── Phase 2: Layer 1 — Local database checks ─────────────
 self._update_progress(15, " Running local database checks (offline)...")
 self.logger.section("LAYER 1: Local Database Checks")

 for idx, (ip, host_data) in enumerate(hosts.items()):
 if not self._running: break
 self._check_dangerous_ports(ip, host_data)
 self._check_service_risks(ip, host_data)

 self._update_progress(35, f"✅ Local checks complete — {len(self.findings)} finding(s) so far")

 # ── Phase 3: Layer 2 — Banner / version analysis ─────────
 self._update_progress(40, "️ Analysing service banners for version info...")
 self.logger.section("LAYER 2: Banner & Version Analysis")

 for idx, (ip, host_data) in enumerate(hosts.items()):
 if not self._running: break
 self._analyse_banners(ip, host_data)

 self._update_progress(60, f"✅ Banner analysis complete — {len(self.findings)} finding(s) so far")

 # ── Phase 4: Layer 3 — NVD API lookups ───────────────────
 self._update_progress(65, "Querying NVD for CVEs (requires internet)...")
 self.logger.section("LAYER 3: NVD Live CVE Lookup")

 self._nvd_lookup_all(hosts)

 self._update_progress(88, f"✅ NVD lookup complete — {len(self.findings)} total finding(s)")

 # ── Phase 5: Additional targeted checks ──────────────────
 self._update_progress(90, "Running targeted service checks...")
 for ip, host_data in hosts.items():
 if not self._running: break
 self._check_anonymous_ftp(ip, host_data)
 self._check_http_security(ip, host_data)

 # ── Phase 6: Build & save report ─────────────────────────
 self._update_progress(95, " Building report...")
 report = self._build_report(start_time, hosts)
 self._save_report(report)

 elapsed = round(time.time() - start_time, 1)
 self._update_progress(100, f"✅ Inspection complete in {elapsed}s — {len(self.findings)} finding(s)")
 self.logger.info(f"Intel finished. Duration: {elapsed}s | Findings: {len(self.findings)}")

 return report

 # ══════════════════════════════════════════════════════════════
 # LAYER 1 — LOCAL DATABASE CHECKS
 # ══════════════════════════════════════════════════════════════

 def _check_dangerous_ports(self, ip: str, host_data: dict):
 """
 Checks if any open ports are in our "dangerous ports" database.
 
 This runs 100% offline — no internet needed.
 Our local database tells us which ports are inherently risky.
 """
 open_ports = host_data.get('open_ports', [])
 dangerous = self.local_db.get('dangerous_ports', {})

 for port in open_ports:
 port_str = str(port)
 if port_str in dangerous:
 vuln_info = dangerous[port_str]

 finding = {
 "severity": vuln_info['severity'],
 "title": vuln_info['name'],
 "detail": vuln_info['description'],
 "host": ip,
 "port": port,
 "service": self._get_service_name(host_data, port),
 "recommendation": vuln_info['recommendation'],
 "cve_refs": vuln_info.get('cve_examples', []),
 "source": "Local Database",
 "layer": 1
 }

 self._add_finding(finding)

 def _check_service_risks(self, ip: str, host_data: dict):
 """
 Checks each discovered service against our risk knowledge base.
 For example: "Is HTTP running? Flag that it's unencrypted."
 """
 port_details = host_data.get('port_details', [])
 service_checks = self.local_db.get('service_checks', {})

 for port_info in port_details:
 service = port_info.get('service', '')
 port = port_info.get('port', 0)

 if service in service_checks:
 checks = service_checks[service].get('checks', [])
 for check in checks:
 finding = {
 "severity": check['severity'],
 "title": f"[{check['id']}] {check['name']}",
 "detail": check['description'],
 "host": ip,
 "port": port,
 "service": service,
 "recommendation": f"See check {check['id']} in security baseline",
 "cve_refs": [],
 "source": "Service Check",
 "layer": 1
 }
 self._add_finding(finding)

 # ══════════════════════════════════════════════════════════════
 # LAYER 2 — BANNER ANALYSIS
 # ══════════════════════════════════════════════════════════════

 def _analyse_banners(self, ip: str, host_data: dict):
 """
 Examines service banners collected by Recon.
 
 A banner is the message a service sends when you first connect.
 For example, Apache might say: "Apache/2.2.15 (CentOS)"
 
 We extract version numbers from banners and check:
 1. Is the version known to be outdated?
 2. Are there known CVEs for this exact version?
 """
 port_details = host_data.get('port_details', [])
 banner_sigs = self.local_db.get('banner_signatures', {})

 for port_info in port_details:
 banner = port_info.get('banner', '')
 version = port_info.get('version', '')
 port = port_info.get('port', 0)

 if not banner:
 continue

 # Check each known software signature against this banner
 for software, sig_data in banner_sigs.items():
 pattern = sig_data.get('pattern', '')

 # Does this banner mention the software? (e.g. "Apache" in banner)
 if pattern.lower() not in banner.lower():
 continue

 # Extract version number from banner using regex
 # Regex = a pattern-matching language for text
 detected_version = self._extract_version(
 banner,
 sig_data.get('version_pattern', '')
 )

 if not detected_version:
 continue

 # Check if this version is known to be bad
 known_bad = sig_data.get('known_bad_versions', [])
 is_bad = any(detected_version.startswith(bad)
 for bad in known_bad)

 if is_bad:
 severity = "critical" if software == "vsftpd" else "high"
 finding = {
 "severity": severity,
 "title": f"Outdated/Vulnerable {software} Version Detected",
 "detail": f"Version {detected_version} identified from banner. {sig_data['recommendation']}",
 "host": ip,
 "port": port,
 "service": software,
 "version": detected_version,
 "banner": banner[:200],
 "recommendation": sig_data['recommendation'],
 "cve_refs": [],
 "source": "Banner Analysis",
 "layer": 2,
 # Flag for NVD lookup — this version should be checked further
 "_nvd_query": f"{software} {detected_version}"
 }
 self._add_finding(finding)
 else:
 # Even if not in bad list, log the version for NVD lookup
 # Store it on the host_data so _nvd_lookup_all can find it
 if '_detected_software' not in host_data:
 host_data['_detected_software'] = []
 host_data['_detected_software'].append({
 "software": software,
 "version": detected_version,
 "port": port
 })

 def _extract_version(self, text: str, pattern: str) -> str | None:
 """
 Uses regex (pattern matching) to pull version numbers from text.
 
 Example:
 text: "Apache/2.4.51 (Ubuntu)"
 pattern: "Apache[/\\s]([\\d.]+)"
 result: "2.4.51"
 """
 if not pattern or not text:
 return None
 try:
 match = re.search(pattern, text, re.IGNORECASE)
 if match:
 return match.group(1)
 except re.error:
 pass
 return None

 # ══════════════════════════════════════════════════════════════
 # LAYER 3 — NVD API LOOKUPS
 # ══════════════════════════════════════════════════════════════

 def _nvd_lookup_all(self, hosts: dict):
 """
 Queries NVD for CVEs matching all detected software versions.
 
 Collects all the software versions discovered across all hosts,
 deduplicates them, then queries NVD once per unique version.
 This is efficient — if Apache 2.4.51 is on 10 servers,
 we query NVD once, not 10 times.
 """
 # Collect all unique software queries
 queries_to_run = set()

 for ip, host_data in hosts.items():
 # From banner analysis stage
 for sw in host_data.get('_detected_software', []):
 query = f"{sw['software']} {sw['version']}"
 queries_to_run.add(query)

 # From findings with _nvd_query flag
 for finding in self.findings:
 if finding.get('host') == ip and finding.get('_nvd_query'):
 queries_to_run.add(finding['_nvd_query'])

 # Also query based on open port services if version is in banner
 for port_info in host_data.get('port_details', []):
 version = port_info.get('version', '')
 service = port_info.get('service', '')
 if version and service and len(service) > 2:
 queries_to_run.add(f"{service} {version}")

 if not queries_to_run:
 self.logger.info("No software versions detected for NVD lookup")
 self._update_progress(85, "ℹ️ No version info found for CVE lookup (try grabbing more banners)")
 return

 total = len(queries_to_run)
 self.logger.info(f"Running {total} NVD CVE lookup(s)...")

 for idx, query in enumerate(queries_to_run):
 if not self._running:
 break

 progress = 65 + int((idx / total) * 20)
 self._update_progress(progress, f"NVD lookup {idx+1}/{total}: '{query}'")

 cves = self.nvd.search_by_keyword(query, max_results=5)

 for cve in cves:
 # Only report HIGH and CRITICAL CVEs to avoid noise
 if cve.get('cvss_score', 0) < 4.0:
 continue

 severity_map = {
 "CRITICAL": "critical",
 "HIGH": "high",
 "MEDIUM": "medium",
 "LOW": "low"
 }
 severity = severity_map.get(cve.get('severity', ''), 'medium')

 # Find which host(s) run this software
 affected_hosts = self._find_hosts_for_query(hosts, query)

 for ip in affected_hosts:
 finding = {
 "severity": severity,
 "title": f"{cve['id']} — {query}",
 "detail": cve['description'][:300],
 "host": ip,
 "port": None,
 "service": query.split()[0],
 "cvss_score": cve['cvss_score'],
 "cve_id": cve['id'],
 "cve_url": cve['url'],
 "published": cve['published'],
 "recommendation": f"Check {cve['url']} for patch information",
 "cve_refs": [cve['id']],
 "source": "NVD API",
 "layer": 3
 }
 self._add_finding(finding)

 def _find_hosts_for_query(self, hosts: dict, query: str) -> list:
 """
 Returns the list of IPs that are running the software in the query.
 If we can't determine which host, return all hosts (conservative).
 """
 matched = []
 software = query.split()[0].lower()

 for ip, host_data in hosts.items():
 for sw in host_data.get('_detected_software', []):
 if software in sw['software'].lower():
 matched.append(ip)
 break
 for pd in host_data.get('port_details', []):
 banner = (pd.get('banner') or '').lower()
 if software in banner and ip not in matched:
 matched.append(ip)

 return matched if matched else list(hosts.keys())

 # ══════════════════════════════════════════════════════════════
 # TARGETED SERVICE CHECKS
 # ══════════════════════════════════════════════════════════════

 def _check_anonymous_ftp(self, ip: str, host_data: dict):
 """
 Attempts anonymous FTP login to check if it's enabled.
 
 Anonymous FTP = anyone can connect without a password.
 This is occasionally intentional (public file servers) but
 often misconfigured and exposes sensitive files.
 
 We try to login as "anonymous" with email as password.
 This is completely passive — we don't download anything.
 """
 open_ports = host_data.get('open_ports', [])
 if 21 not in open_ports:
 return

 try:
 import ftplib
 ftp = ftplib.FTP()
 ftp.connect(ip, 21, timeout=self.timeout)
 ftp.login('anonymous', 'inspector@dayea-wisdom.local')
 # If we get here, anonymous login succeeded
 ftp.quit()

 self._add_finding({
 "severity": "high",
 "title": "Anonymous FTP Login Enabled",
 "detail": f"FTP server on {ip}:21 allows login without a password using the 'anonymous' username. Anyone can access files.",
 "host": ip,
 "port": 21,
 "service": "FTP",
 "recommendation": "Disable anonymous FTP access unless intentionally serving public files. Review what files are accessible.",
 "cve_refs": [],
 "source": "Active Check",
 "layer": 3
 })
 self.logger.warning(f" Anonymous FTP login SUCCEEDED on {ip}")

 except Exception:
 # Login failed = good! Anonymous access is properly disabled.
 self.logger.info(f" ✅ Anonymous FTP login correctly rejected on {ip}")

 def _check_http_security(self, ip: str, host_data: dict):
 """
 Checks HTTP/HTTPS services for basic security header presence.
 
 Security headers are instructions a web server sends to browsers
 telling them how to behave safely. Missing headers = risks.
 
 We check for:
 - Content-Security-Policy (prevents XSS attacks)
 - X-Frame-Options (prevents clickjacking)
 - X-Content-Type-Options (prevents MIME sniffing)
 - Strict-Transport-Security (forces HTTPS)
 """
 open_ports = host_data.get('open_ports', [])
 http_ports = [p for p in open_ports if p in [80, 8080, 8000, 8008]]

 if not http_ports:
 return

 for port in http_ports:
 try:
 # Make a real HTTP request and examine the response headers
 import urllib.request
 url = f"http://{ip}:{port}/"

 req = urllib.request.Request(
 url,
 headers={"User-Agent": "Dayea/1.0 Security Assessment"}
 )

 with urllib.request.urlopen(req, timeout=self.timeout) as response:
 headers = {k.lower(): v for k, v in response.headers.items()}

 # Check for missing security headers
 missing_headers = []

 security_headers = {
 "content-security-policy": "Content-Security-Policy (CSP) — prevents cross-site scripting (XSS)",
 "x-frame-options": "X-Frame-Options — prevents clickjacking attacks",
 "x-content-type-options": "X-Content-Type-Options — prevents MIME type confusion",
 "strict-transport-security": "Strict-Transport-Security (HSTS) — enforces HTTPS usage"
 }

 for header, description in security_headers.items():
 if header not in headers:
 missing_headers.append(description)

 if missing_headers:
 self._add_finding({
 "severity": "medium",
 "title": f"Missing HTTP Security Headers on {ip}:{port}",
 "detail": f"The web server is missing {len(missing_headers)} security header(s): " +
 "; ".join(missing_headers),
 "host": ip,
 "port": port,
 "service": "HTTP",
 "recommendation": "Add security headers to your web server configuration. See securityheaders.com for a free check.",
 "cve_refs": [],
 "source": "HTTP Header Check",
 "layer": 3
 })

 # Check if server version is disclosed in Server header
 server_header = headers.get('server', '')
 if server_header and any(c.isdigit() for c in server_header):
 self._add_finding({
 "severity": "low",
 "title": f"Web Server Version Disclosed: '{server_header}'",
 "detail": f"The Server header reveals software version: '{server_header}'. Attackers use this to find matching CVEs.",
 "host": ip,
 "port": port,
 "service": "HTTP",
 "recommendation": "Configure your web server to hide or change the Server header (ServerTokens Prod for Apache, server_tokens off for Nginx).",
 "cve_refs": [],
 "source": "HTTP Header Check",
 "layer": 3
 })

 except Exception as e:
 self.logger.debug(f"HTTP check failed on {ip}:{port}: {e}")

 # ══════════════════════════════════════════════════════════════
 # HELPERS
 # ══════════════════════════════════════════════════════════════

 def _load_local_db(self) -> dict:
 """Load the local vulnerability database from disk"""
 db_path = "config/vuln_db.json"
 try:
 with open(db_path, 'r') as f:
 db = json.load(f)
 self.logger.info(f"Local vuln DB loaded: {len(db.get('dangerous_ports', {}))} port rules, "
 f"{len(db.get('banner_signatures', {}))} banner signatures")
 return db
 except FileNotFoundError:
 self.logger.error(f"Local vuln DB not found at {db_path}")
 return {}
 except json.JSONDecodeError as e:
 self.logger.error(f"Local vuln DB is malformed: {e}")
 return {}

 def _get_service_name(self, host_data: dict, port: int) -> str:
 """Returns the service name for a given port from host data"""
 for pd in host_data.get('port_details', []):
 if pd.get('port') == port:
 return pd.get('service', str(port))
 return str(port)

 def _basic_host_discovery(self) -> dict:
 """
 Minimal host check when no Recon data is available.
 Just checks if the hosts in scope are reachable.
 """
 hosts = {}
 for target in self.scope:
 target = target.strip()
 if not target:
 continue
 try:
 ip = socket.gethostbyname(target)
 hosts[ip] = {
 "ip": ip,
 "open_ports": [],
 "port_details": [],
 "hostname": target
 }
 except Exception:
 pass
 return hosts

 def _add_finding(self, finding: dict):
 """Add a finding, avoid duplicates, and push to GUI"""
 # Deduplicate — don't add the same finding twice
 dedup_key = f"{finding['host']}:{finding.get('port')}:{finding['title'][:40]}"
 for existing in self.findings:
 existing_key = f"{existing['host']}:{existing.get('port')}:{existing['title'][:40]}"
 if existing_key == dedup_key:
 return # Already have this one

 self.findings.append(finding)
 self.finding_cb(finding)
 self.logger.info(f" Finding [{finding['severity'].upper()}]: {finding['title']} @ {finding['host']}")

 def _update_progress(self, percent: int, message: str):
 """Update progress bar and log"""
 self.logger.info(f"[{percent}%] {message}")
 self.progress_cb(percent, message)

 def stop(self):
 """Stop the scan gracefully"""
 self._running = False
 self.logger.warning("Intel scan stopped by user")

 # ══════════════════════════════════════════════════════════════
 # REPORT
 # ══════════════════════════════════════════════════════════════

 def _build_report(self, start_time: float, hosts: dict) -> dict:
 """Build the final assessment report"""
 elapsed = round(time.time() - start_time, 1)

 # Sort findings: critical first, then high, medium, low
 sorted_findings = sorted(
 self.findings,
 key=lambda f: SEVERITY_ORDER.get(f.get('severity', 'info'), 4)
 )

 severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
 for f in self.findings:
 sev = f.get("severity", "info")
 severity_counts[sev] = severity_counts.get(sev, 0) + 1

 return {
 "module": "inspector",
 "scan_type": "Vulnerability Assessment",
 "timestamp": datetime.now().isoformat(),
 "duration_seconds": elapsed,
 "scope": self.scope,
 "hosts_assessed": len(hosts),
 "total_findings": len(self.findings),
 "severity_summary": severity_counts,
 "findings": sorted_findings,
 "data_sources": ["Local Database", "Banner Analysis", "NVD API"]
 }

 def _save_report(self, report: dict):
 """Save report to disk"""
 os.makedirs("reports", exist_ok=True)
 timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
 filename = f"reports/inspector_{timestamp}.json"
 with open(filename, 'w') as f:
 json.dump(report, f, indent=2)
 self.logger.info(f"Intel report saved: {filename}")
