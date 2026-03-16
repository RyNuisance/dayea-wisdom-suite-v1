"""
web_tester.py — Breach: OWASP Top 10 Scanner

This is Module 3. Breach focuses specifically on web
applications — websites, APIs, web portals.

Think of a website like a shop.
 Recon found which shops exist on the street (IPs/ports).
 Intel checked if the shop's locks are out of date (CVEs).
 Breach walks INTO the shop and checks:
 - Can I get into the staff-only area? (Access Control)
 - Does the checkout form let me inject commands? (SQL Injection)
 - Can I make the shop display malicious content? (XSS)
 - Are there unlocked filing cabinets full of secrets? (Sensitive Files)
 - Is the shop sending data on postcards instead of sealed envelopes? (HTTPS)
 - Does the shop leak its internal layout to strangers? (Info Disclosure)

WHAT THIS IS:
 A DETECTION tool — it probes for vulnerability INDICATORS.
 It looks for error messages, unexpected responses, and
 missing protections. It does NOT extract real data.

WHAT THIS IS NOT:
 An exploitation tool. When we detect SQL injection, we stop
 at "this field appears vulnerable" — we do NOT run actual
 queries to dump databases.

HOW WEB TESTING WORKS (simple):
 1. CRAWL — visit the site and find all its pages and forms
 2. PROBE — send specially crafted inputs to each form/parameter
 3. OBSERVE — look at the responses for signs of vulnerability
 4. REPORT — document what was found with severity and fix guidance
"""

import urllib.request
import urllib.parse
import urllib.error
import json
import re
import time
import os
import ssl
from datetime import datetime
from html.parser import HTMLParser


class LinkParser(HTMLParser):
 """
 A simple HTML parser that extracts links and forms from a webpage.
 
 HTMLParser is Python's built-in tool for reading HTML.
 Think of it as a person who reads through a webpage's source code
 and writes down every link and form they find.
 """

 def __init__(self, base_url: str):
 super().__init__()
 self.base_url = base_url
 self.links = set() # All href links found
 self.forms = [] # All forms found
 self._current_form = None # Form being parsed right now

 def handle_starttag(self, tag: str, attrs: list):
 """Called every time an opening HTML tag is found"""
 attrs_dict = dict(attrs)

 # Found a link (<a href="...">)
 if tag == 'a' and 'href' in attrs_dict:
 href = attrs_dict['href']
 # Only keep links that belong to our target site
 if href and not href.startswith('#') and not href.startswith('mailto:'):
 full_url = self._resolve_url(href)
 if full_url and self._same_domain(full_url):
 self.links.add(full_url)

 # Found a form (<form action="..." method="...">)
 elif tag == 'form':
 self._current_form = {
 'action': self._resolve_url(attrs_dict.get('action', '')),
 'method': attrs_dict.get('method', 'get').upper(),
 'inputs': []
 }

 # Found an input inside a form
 elif tag == 'input' and self._current_form is not None:
 input_type = attrs_dict.get('type', 'text').lower()
 input_name = attrs_dict.get('name', '')
 if input_name and input_type not in ['submit', 'button', 'image', 'reset', 'hidden']:
 self._current_form['inputs'].append({
 'name': input_name,
 'type': input_type,
 'value': attrs_dict.get('value', '')
 })

 def handle_endtag(self, tag: str):
 """Called every time a closing HTML tag is found"""
 if tag == 'form' and self._current_form:
 # Only save forms that have at least one input
 if self._current_form['inputs'] or self._current_form.get('action'):
 self.forms.append(self._current_form)
 self._current_form = None

 def _resolve_url(self, href: str) -> str:
 """Convert a relative URL to absolute"""
 if not href:
 return self.base_url
 if href.startswith('http://') or href.startswith('https://'):
 return href
 if href.startswith('//'):
 scheme = self.base_url.split('://')[0]
 return f"{scheme}:{href}"
 if href.startswith('/'):
 parts = urllib.parse.urlparse(self.base_url)
 return f"{parts.scheme}://{parts.netloc}{href}"
 # Relative path
 base = self.base_url.rsplit('/', 1)[0]
 return f"{base}/{href}"

 def _same_domain(self, url: str) -> bool:
 """Check if a URL belongs to the same domain as our target"""
 try:
 target_domain = urllib.parse.urlparse(self.base_url).netloc
 url_domain = urllib.parse.urlparse(url).netloc
 return target_domain == url_domain
 except Exception:
 return False


class WebTester:
 """
 Breach — OWASP Top 10 Web Application Scanner.
 
 Tests web applications for the most common and dangerous
 categories of vulnerability, as defined by the Open Web
 Application Security Project (OWASP).
 """

 def __init__(self, settings: dict, logger,
 progress_callback=None, finding_callback=None):
 self.settings = settings
 self.logger = logger
 self.progress_cb = progress_callback or (lambda p, m: None)
 self.finding_cb = finding_callback or (lambda f: None)

 self.scope = settings.get('scope', [])
 self.timeout = settings.get('scan_timeout', 5)
 self.max_depth = settings.get('web_test_depth', 2)
 self._running = True
 self.findings = []

 # Load our web payload database
 self.payloads = self._load_payloads()

 # SSL context — allows testing HTTPS sites with self-signed certs
 # (common on internal/development servers)
 self.ssl_context = ssl.create_default_context()
 self.ssl_context.check_hostname = False
 self.ssl_context.verify_mode = ssl.CERT_NONE

 # Track visited URLs to avoid loops
 self.visited_urls = set()

 # All discovered pages, forms, and parameters
 self.discovered = {
 'pages': set(),
 'forms': [],
 'params': []
 }

 # ══════════════════════════════════════════════════════════════
 # MAIN RUN METHOD
 # ══════════════════════════════════════════════════════════════

 def run(self) -> dict:
 """
 Run the full web application test against all targets in scope.
 Tests each target that looks like a web server (port 80/443 or http/https URL).
 """
 self.logger.section("BREACH — OWASP TOP 10 SCAN STARTED")
 start_time = time.time()

 # Build the list of web targets from scope
 web_targets = self._build_web_targets()

 if not web_targets:
 self._update_progress(100, "No web targets found in scope")
 return {"findings": [], "note": "No HTTP/HTTPS targets found in scope. Add http:// targets."}

 self.logger.info(f"Web targets to test: {web_targets}")
 self._update_progress(5, f"Found {len(web_targets)} web target(s) to test")

 for target_idx, base_url in enumerate(web_targets):
 if not self._running:
 break

 self.logger.section(f"TESTING: {base_url}")
 self._update_progress(
 10 + int((target_idx / len(web_targets)) * 85),
 f"Testing: {base_url}"
 )
 self._test_target(base_url)

 # Build and save final report
 self._update_progress(96, " Saving web scan report...")
 report = self._build_report(start_time)
 self._save_report(report)

 elapsed = round(time.time() - start_time, 1)
 self._update_progress(100, f"✅ Web scan complete in {elapsed}s — {len(self.findings)} finding(s)")
 return report

 def _test_target(self, base_url: str):
 """
 Runs all tests against a single web target.
 This is the main test orchestrator for one URL.
 """
 host = urllib.parse.urlparse(base_url).netloc

 # ── Test 1: HTTPS & TLS ──────────────────────────────────
 self._update_progress_msg(f"Checking HTTPS configuration on {host}...")
 self._check_https(base_url)

 # ── Test 2: Security Headers ─────────────────────────────
 self._update_progress_msg(f"Checking security headers on {host}...")
 self._check_security_headers(base_url)

 # ── Test 3: Sensitive File Exposure ──────────────────────
 self._update_progress_msg(f" Scanning for exposed sensitive files on {host}...")
 self._check_sensitive_files(base_url)

 # ── Test 4: Crawl the site ───────────────────────────────
 self._update_progress_msg(f"️ Crawling {host} to discover pages and forms...")
 pages, forms = self._crawl(base_url, depth=self.max_depth)
 self.logger.info(f" Crawled {len(pages)} page(s), found {len(forms)} form(s)")

 # ── Test 5: SQL Injection ────────────────────────────────
 self._update_progress_msg(f" Testing for SQL Injection on {host}...")
 self._test_sql_injection(base_url, forms, pages)

 # ── Test 6: XSS ─────────────────────────────────────────
 self._update_progress_msg(f"Testing for Cross-Site Scripting (XSS) on {host}...")
 self._test_xss(base_url, forms, pages)

 # ── Test 7: Path Traversal ───────────────────────────────
 self._update_progress_msg(f" Testing for path traversal on {host}...")
 self._test_path_traversal(base_url, pages)

 # ── Test 8: Open Redirect ────────────────────────────────
 self._update_progress_msg(f"↗️ Testing for open redirects on {host}...")
 self._test_open_redirect(base_url, pages)

 # ── Test 9: CORS ─────────────────────────────────────────
 self._update_progress_msg(f" Testing CORS policy on {host}...")
 self._test_cors(base_url)

 # ── Test 10: Info Disclosure ─────────────────────────────
 self._update_progress_msg(f"Checking for information disclosure on {host}...")
 self._check_info_disclosure(base_url)

 # ── Test 11: Admin Panel Discovery ───────────────────────
 self._update_progress_msg(f" Scanning for exposed admin panels on {host}...")
 self._find_admin_panels(base_url)

 # ══════════════════════════════════════════════════════════════
 # TEST 1 — HTTPS & TLS CONFIGURATION
 # ══════════════════════════════════════════════════════════════

 def _check_https(self, base_url: str):
 """
 Checks if the site uses HTTPS and if HTTP properly redirects to HTTPS.
 
 HTTPS = your data is encrypted in transit (like a sealed envelope)
 HTTP = your data is sent in plain text (like a postcard anyone can read)
 """
 host = urllib.parse.urlparse(base_url).netloc
 is_https = base_url.startswith('https://')

 if not is_https:
 # Check if there IS an HTTPS version available
 https_url = f"https://{host}"
 try:
 self._fetch(https_url, follow_redirects=False)
 # If HTTPS exists but we're testing HTTP, that's a medium issue
 self._add_finding({
 "severity": "medium",
 "title": "HTTP Available — Should Redirect to HTTPS",
 "detail": f"The site is accessible over unencrypted HTTP at {base_url}. Data transmitted over HTTP can be intercepted by anyone on the network.",
 "host": host,
 "url": base_url,
 "owasp": "A02 — Cryptographic Failures",
 "recommendation": "Redirect all HTTP traffic to HTTPS. Add HSTS header to prevent future HTTP connections.",
 })
 except Exception:
 # Can't reach HTTPS at all
 self._add_finding({
 "severity": "high",
 "title": "No HTTPS Available",
 "detail": f"The site has no HTTPS version. All traffic including passwords is unencrypted.",
 "host": host,
 "url": base_url,
 "owasp": "A02 — Cryptographic Failures",
 "recommendation": "Install a TLS certificate and enable HTTPS. Free certificates available at letsencrypt.org",
 })
 else:
 self.logger.info(f" ✅ HTTPS in use on {host}")

 # ══════════════════════════════════════════════════════════════
 # TEST 2 — SECURITY HEADERS
 # ══════════════════════════════════════════════════════════════

 def _check_security_headers(self, base_url: str):
 """
 Checks for the presence of HTTP security headers.
 These are instructions the server sends to the browser
 telling it how to behave safely.
 """
 host = urllib.parse.urlparse(base_url).netloc
 result = self._fetch(base_url)
 if not result:
 return

 _, response_headers, _ = result
 headers_lower = {k.lower(): v for k, v in response_headers.items()}

 required = self.payloads.get('security_headers', {}).get('required_headers', [])

 for header_check in required:
 header_name = header_check['header'].lower()
 if header_name not in headers_lower:
 self._add_finding({
 "severity": header_check['severity'],
 "title": f"Missing Security Header: {header_check['header']}",
 "detail": header_check['description'],
 "host": host,
 "url": base_url,
 "owasp": "A05 — Security Misconfiguration",
 "recommendation": header_check['recommendation'],
 })
 else:
 self.logger.debug(f" ✅ {header_check['header']} present")

 # ══════════════════════════════════════════════════════════════
 # TEST 3 — SENSITIVE FILE EXPOSURE
 # ══════════════════════════════════════════════════════════════

 def _check_sensitive_files(self, base_url: str):
 """
 Tries to access commonly exposed sensitive files.
 
 Many servers accidentally leave configuration files,
 backups, and admin pages accessible to anyone.
 
 We check for files like:
 .env — environment variables (often contains passwords)
 .git/ — source code repository
 wp-config — WordPress database passwords
 phpinfo — PHP configuration details
 backup.sql — database dump
 """
 host = urllib.parse.urlparse(base_url).netloc
 sensitive_list = self.payloads.get('sensitive_files', {}).get('paths', [])
 severity_map = self.payloads.get('sensitive_files', {}).get('severity_map', {})

 for file_info in sensitive_list:
 if not self._running:
 break

 path = file_info['path']
 desc = file_info['desc']
 test_url = f"{base_url.rstrip('/')}{path}"

 try:
 result = self._fetch(test_url, follow_redirects=False)
 if not result:
 continue

 status_code, headers, body = result

 # 200 = Found! 403 = Exists but forbidden. Both are findings.
 if status_code in [200, 403]:
 # Determine severity based on file type
 severity = "medium"
 for keyword, sev in severity_map.items():
 if keyword in path.lower():
 severity = sev
 break

 # Bump to critical if we can actually READ the file (200)
 if status_code == 200 and severity == "high":
 severity = "critical"

 # Extra check: does the body look like it has real secrets?
 has_secrets = self._body_contains_secrets(body or "")
 if has_secrets:
 severity = "critical"

 self._add_finding({
 "severity": severity,
 "title": f"Sensitive File Accessible: {path}",
 "detail": f"{desc} — HTTP {status_code} at {test_url}. "
 + ("File contents appear to contain sensitive data." if has_secrets else ""),
 "host": host,
 "url": test_url,
 "owasp": "A05 — Security Misconfiguration",
 "recommendation": f"Restrict access to {path} via web server configuration. Move sensitive files outside the web root.",
 })
 self.logger.warning(f" Sensitive file found [{status_code}]: {test_url}")

 except Exception as e:
 self.logger.debug(f" Could not check {test_url}: {e}")
 continue

 def _body_contains_secrets(self, body: str) -> bool:
 """Check if a response body looks like it contains real credentials"""
 secret_patterns = [
 r'DB_PASSWORD\s*=\s*\S+',
 r'DATABASE_URL\s*=\s*\S+',
 r'SECRET_KEY\s*=\s*\S+',
 r'API_KEY\s*=\s*\S+',
 r'AWS_SECRET',
 r'password\s*=\s*["\'][^"\']+["\']',
 r'root:x:0:0', # /etc/passwd
 r'\[extensions\]', # win.ini
 ]
 body_lower = body.lower()
 for pattern in secret_patterns:
 if re.search(pattern, body, re.IGNORECASE):
 return True
 return False

 # ══════════════════════════════════════════════════════════════
 # CRAWLER — Discovers pages and forms
 # ══════════════════════════════════════════════════════════════

 def _crawl(self, base_url: str, depth: int = 2) -> tuple:
 """
 Crawls the website to discover pages and forms.
 
 Think of it like exploring a building:
 - Start at the front door (base_url)
 - Note every room you can see (links)
 - Walk into each room and look for more rooms
 - Keep going until you've been everywhere (or hit depth limit)
 
 Depth = how many "rooms deep" you go from the start.
 Depth 1 = just the homepage. Depth 2 = homepage + linked pages.
 """
 to_visit = {base_url}
 visited = set()
 forms = []

 for current_depth in range(depth):
 if not self._running or not to_visit:
 break

 next_batch = set()

 for url in list(to_visit)[:20]: # Max 20 pages per depth level
 if url in visited or not self._running:
 continue

 visited.add(url)

 result = self._fetch(url)
 if not result:
 continue

 status, headers, body = result
 if not body:
 continue

 # Parse the HTML to find links and forms
 parser = LinkParser(base_url)
 try:
 parser.feed(body)
 except Exception:
 pass

 # Add discovered links to next batch
 next_batch.update(parser.links - visited)

 # Save discovered forms
 for form in parser.forms:
 form['source_url'] = url
 forms.append(form)

 self.logger.debug(f" Crawled: {url} → {len(parser.links)} links, {len(parser.forms)} forms")

 to_visit = next_batch

 self.logger.info(f" Crawl complete: {len(visited)} pages, {len(forms)} forms")
 return visited, forms

 # ══════════════════════════════════════════════════════════════
 # TEST 5 — SQL INJECTION DETECTION
 # ══════════════════════════════════════════════════════════════

 def _test_sql_injection(self, base_url: str, forms: list, pages: set):
 """
 Tests for SQL Injection vulnerabilities.
 
 SQL Injection = tricking a website into running database
 commands it wasn't supposed to run.
 
 HOW WE DETECT IT (without exploiting):
 We send a single quote (') as input.
 If the site has a SQL error in its response, the input
 went directly into a SQL query without sanitisation.
 
 Real response if vulnerable:
 "You have an error in your SQL syntax near '''"
 
 We look for these error messages, NOT for actual data.
 
 IMPORTANT: We're looking for error MESSAGES, not running
 real SQL queries. This is detection, not exploitation.
 """
 host = urllib.parse.urlparse(base_url).netloc
 sqli_config = self.payloads.get('sql_injection', {})
 error_sigs = [s.lower() for s in sqli_config.get('error_signatures', [])]
 detection_payloads = sqli_config.get('detection_payloads', [])

 # Test URL parameters from crawled pages
 for page_url in list(pages)[:15]: # Limit to 15 pages
 parsed = urllib.parse.urlparse(page_url)
 params = urllib.parse.parse_qs(parsed.query)

 if not params:
 continue

 for param_name in params:
 if not self._running:
 return

 # Try just the single-quote payload first (most revealing)
 probe_payload = "'"
 test_params = dict(params)
 test_params[param_name] = [probe_payload]

 new_query = urllib.parse.urlencode(test_params, doseq=True)
 test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

 result = self._fetch(test_url)
 if not result:
 continue

 _, _, body = result
 if not body:
 continue

 body_lower = body.lower()

 # Look for SQL error signatures in the response
 for sig in error_sigs:
 if sig in body_lower:
 self._add_finding({
 "severity": "critical",
 "title": f"SQL Injection Detected — Parameter: '{param_name}'",
 "detail": f"The parameter '{param_name}' at {page_url} appears vulnerable to SQL injection. "
 f"SQL error message detected in response after sending: {probe_payload!r}",
 "host": host,
 "url": page_url,
 "parameter": param_name,
 "owasp": "A03 — Injection",
 "recommendation": sqli_config.get('recommendation', ''),
 })
 break # Don't double-report the same parameter

 # Test forms
 for form in forms[:10]: # Limit to 10 forms
 if not self._running:
 return

 action = form.get('action', base_url) or base_url
 method = form.get('method', 'GET')
 inputs = form.get('inputs', [])

 if not inputs:
 continue

 for input_field in inputs:
 probe = "'"
 form_data = {inp['name']: inp.get('value', 'test') for inp in inputs}
 form_data[input_field['name']] = probe

 result = self._submit_form(action, method, form_data)
 if not result:
 continue

 _, _, body = result
 if not body:
 continue

 body_lower = body.lower()
 for sig in error_sigs:
 if sig in body_lower:
 self._add_finding({
 "severity": "critical",
 "title": f"SQL Injection in Form Field: '{input_field['name']}'",
 "detail": f"Form at {action} — field '{input_field['name']}' returned a SQL error when tested.",
 "host": host,
 "url": action,
 "parameter": input_field['name'],
 "owasp": "A03 — Injection",
 "recommendation": sqli_config.get('recommendation', ''),
 })
 break

 # ══════════════════════════════════════════════════════════════
 # TEST 6 — CROSS-SITE SCRIPTING (XSS) DETECTION
 # ══════════════════════════════════════════════════════════════

 def _test_xss(self, base_url: str, forms: list, pages: set):
 """
 Tests for Cross-Site Scripting (XSS) vulnerabilities.
 
 XSS = attacker injects a script that runs in victims' browsers.
 Like putting a hidden camera inside a shop that records
 every customer who walks in.
 
 HOW WE DETECT IT:
 We send a harmless test string like:
 <script>alert(1)</script>
 
 If we find this EXACT unmodified string reflected back
 in the HTML response, it means the server put our input
 directly into the page without encoding it first.
 
 A safe server would convert < to &lt; and > to &gt;
 making it display as text rather than execute as code.
 
 NOTE: We check if the tag appears unencoded in the response.
 We do NOT check if it actually executes — that requires a browser.
 """
 host = urllib.parse.urlparse(base_url).netloc
 xss_config = self.payloads.get('xss', {})
 probes = xss_config.get('detection_payloads', [])

 # Use a unique marker to avoid false positives
 # If our exact probe appears in the response → reflected XSS likely
 xss_probe = "<script>alert('DAYEA_XSS_TEST')</script>"
 marker = "DAYEA_XSS_TEST"

 # Test URL parameters
 for page_url in list(pages)[:15]:
 parsed = urllib.parse.urlparse(page_url)
 params = urllib.parse.parse_qs(parsed.query)

 if not params:
 continue

 for param_name in params:
 if not self._running:
 return

 test_params = dict(params)
 test_params[param_name] = [xss_probe]
 new_query = urllib.parse.urlencode(test_params, doseq=True)
 test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

 result = self._fetch(test_url)
 if not result:
 continue

 _, _, body = result
 if not body:
 continue

 # Check if our probe appears UNENCODED in the response
 # Encoded would be &lt;script&gt; — safe
 # Unencoded would be <script> — vulnerable
 if xss_probe in body or marker in body:
 if '<script>' in body.lower() and marker in body:
 self._add_finding({
 "severity": "high",
 "title": f"Reflected XSS — Parameter: '{param_name}'",
 "detail": f"Parameter '{param_name}' at {page_url} reflects input unencoded in the HTML response. An attacker could inject malicious scripts that execute in victims' browsers.",
 "host": host,
 "url": page_url,
 "parameter": param_name,
 "owasp": "A03 — Injection (XSS)",
 "recommendation": xss_config.get('recommendation', ''),
 })

 # Test forms
 for form in forms[:10]:
 if not self._running:
 return

 action = form.get('action', base_url) or base_url
 inputs = form.get('inputs', [])
 method = form.get('method', 'GET')

 for input_field in inputs:
 form_data = {inp['name']: inp.get('value', 'test') for inp in inputs}
 form_data[input_field['name']] = xss_probe

 result = self._submit_form(action, method, form_data)
 if not result:
 continue

 _, _, body = result
 if not body:
 continue

 if xss_probe in body and '<script>' in body.lower():
 self._add_finding({
 "severity": "high",
 "title": f"Reflected XSS in Form Field: '{input_field['name']}'",
 "detail": f"Form at {action} — field '{input_field['name']}' reflects script tags unencoded in the response.",
 "host": host,
 "url": action,
 "parameter": input_field['name'],
 "owasp": "A03 — Injection (XSS)",
 "recommendation": xss_config.get('recommendation', ''),
 })
 break

 # ══════════════════════════════════════════════════════════════
 # TEST 7 — PATH TRAVERSAL
 # ══════════════════════════════════════════════════════════════

 def _test_path_traversal(self, base_url: str, pages: set):
 """
 Tests for path traversal vulnerabilities.
 
 Path traversal = using '../../../' sequences to escape the
 web root directory and access system files.
 
 Like a hotel guest navigating from their room to the
 manager's office by going up stairs and through staff doors.
 """
 host = urllib.parse.urlparse(base_url).netloc
 pt_data = self.payloads.get('path_traversal', {})
 test_paths = pt_data.get('test_paths', [])
 indicators = [i.lower() for i in pt_data.get('success_indicators', [])]

 # Look for file= or path= parameters in URLs
 file_params = ['file', 'path', 'page', 'include', 'doc', 'document', 'template', 'view']

 for page_url in list(pages)[:10]:
 parsed = urllib.parse.urlparse(page_url)
 params = urllib.parse.parse_qs(parsed.query)

 for param_name in params:
 if param_name.lower() not in file_params:
 continue

 if not self._running:
 return

 for traversal in test_paths[:5]: # Test top 5 payloads
 test_params = dict(params)
 test_params[param_name] = [traversal]
 new_query = urllib.parse.urlencode(test_params, doseq=True)
 test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

 result = self._fetch(test_url)
 if not result:
 continue

 _, _, body = result
 if not body:
 continue

 body_lower = body.lower()
 for indicator in indicators:
 if indicator in body_lower:
 self._add_finding({
 "severity": "critical",
 "title": f"Path Traversal Vulnerability — Parameter: '{param_name}'",
 "detail": f"Parameter '{param_name}' at {page_url} is vulnerable to path traversal. Using '{traversal}' returned system file contents.",
 "host": host,
 "url": page_url,
 "parameter": param_name,
 "owasp": "A01 — Broken Access Control",
 "recommendation": pt_data.get('recommendation', 'Validate and sanitise all file path inputs. Use a whitelist of allowed files.'),
 })
 break

 # ══════════════════════════════════════════════════════════════
 # TEST 8 — OPEN REDIRECT
 # ══════════════════════════════════════════════════════════════

 def _test_open_redirect(self, base_url: str, pages: set):
 """
 Tests for open redirect vulnerabilities.
 
 An open redirect is when a website redirects users to
 external URLs based on user input.
 
 Attackers use these to make phishing links look legitimate:
 yourbank.com/login?next=https://evil.com/fake-login
 
 HOW WE DETECT IT:
 We put our own test URL in redirect parameters.
 If the server redirects us there → vulnerable.
 """
 host = urllib.parse.urlparse(base_url).netloc
 or_config = self.payloads.get('open_redirect', {})
 red_params = or_config.get('redirect_params', [])
 test_vals = or_config.get('test_values', [])

 # We use a harmless test domain — we don't actually redirect to evil sites
 test_domain = "https://example.com"

 for page_url in list(pages)[:15]:
 parsed = urllib.parse.urlparse(page_url)
 params = urllib.parse.parse_qs(parsed.query)

 for param_name in params:
 if param_name.lower() not in [p.lower() for p in red_params]:
 continue

 if not self._running:
 return

 test_params = dict(params)
 test_params[param_name] = [test_domain]
 new_query = urllib.parse.urlencode(test_params, doseq=True)
 test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

 result = self._fetch(test_url, follow_redirects=False)
 if not result:
 continue

 status, headers, _ = result

 # A redirect (301/302/303/307/308) to our test domain = vulnerable
 if status in [301, 302, 303, 307, 308]:
 location = headers.get('Location') or headers.get('location', '')
 if 'example.com' in location:
 self._add_finding({
 "severity": "medium",
 "title": f"Open Redirect — Parameter: '{param_name}'",
 "detail": f"Parameter '{param_name}' at {page_url} redirected to our test URL ({test_domain}). Attackers can use this to redirect users to phishing sites.",
 "host": host,
 "url": page_url,
 "parameter": param_name,
 "owasp": "A01 — Broken Access Control",
 "recommendation": or_config.get('recommendation', ''),
 })

 # ══════════════════════════════════════════════════════════════
 # TEST 9 — CORS MISCONFIGURATION
 # ══════════════════════════════════════════════════════════════

 def _test_cors(self, base_url: str):
 """
 Tests for CORS (Cross-Origin Resource Sharing) misconfigurations.
 
 CORS controls which external websites can make requests to
 your API/site and read the responses.
 
 A misconfigured CORS policy is like a bank that answers
 questions about your account to anyone who calls,
 instead of just you.
 
 HOW WE DETECT IT:
 We send a request pretending to be from evil.example.com.
 If the server responds with:
 Access-Control-Allow-Origin: https://evil.example.com
 or
 Access-Control-Allow-Origin: *
 
 ...then any malicious website could make requests on behalf
 of your users and read the responses.
 """
 host = urllib.parse.urlparse(base_url).netloc
 evil_origin = "https://evil.dayea-wisdom-test.com"

 try:
 req = urllib.request.Request(base_url)
 req.add_header('Origin', evil_origin)
 req.add_header('User-Agent', 'Dayea/1.0 Security Assessment')

 with urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_context) as response:
 headers = {k.lower(): v for k, v in response.headers.items()}

 acao = headers.get('access-control-allow-origin', '')

 if acao == '*':
 self._add_finding({
 "severity": "medium",
 "title": "CORS Wildcard Policy — Any Origin Allowed",
 "detail": "The server responds with Access-Control-Allow-Origin: * meaning any website can make requests and read responses. This is dangerous for authenticated endpoints.",
 "host": host,
 "url": base_url,
 "owasp": "A01 — Broken Access Control",
 "recommendation": self.payloads.get('cors', {}).get('recommendation', ''),
 })

 elif evil_origin in acao or acao == evil_origin:
 self._add_finding({
 "severity": "high",
 "title": "CORS Reflects Arbitrary Origins",
 "detail": f"The server reflected our test origin ({evil_origin}) in the Access-Control-Allow-Origin header. This allows any origin to read authenticated responses.",
 "host": host,
 "url": base_url,
 "owasp": "A01 — Broken Access Control",
 "recommendation": self.payloads.get('cors', {}).get('recommendation', ''),
 })

 elif acao:
 self.logger.info(f" ℹ️ CORS policy present: {acao}")

 except Exception as e:
 self.logger.debug(f" CORS test failed on {base_url}: {e}")

 # ══════════════════════════════════════════════════════════════
 # TEST 10 — INFORMATION DISCLOSURE
 # ══════════════════════════════════════════════════════════════

 def _check_info_disclosure(self, base_url: str):
 """
 Checks for information the server reveals that it shouldn't.
 
 Information disclosure helps attackers — if they know your
 exact software version, they can look up matching exploits.
 
 We look for:
 - Server header revealing exact version numbers
 - Error pages revealing stack traces
 - Debug information in responses
 """
 host = urllib.parse.urlparse(base_url).netloc
 result = self._fetch(base_url)
 if not result:
 return

 _, headers, body = result
 headers_lower = {k.lower(): v for k, v in headers.items()}

 # Check Server header for version disclosure
 server_header = headers_lower.get('server', '')
 if server_header and re.search(r'\d+\.\d+', server_header):
 self._add_finding({
 "severity": "low",
 "title": f"Server Version Disclosed in Header: '{server_header}'",
 "detail": f"The Server response header reveals the exact software version: '{server_header}'. This helps attackers identify matching known vulnerabilities.",
 "host": host,
 "url": base_url,
 "owasp": "A05 — Security Misconfiguration",
 "recommendation": "Configure server to hide version: ServerTokens Prod (Apache) or server_tokens off (Nginx)",
 })

 # Check for X-Powered-By header (reveals backend technology)
 powered_by = headers_lower.get('x-powered-by', '')
 if powered_by:
 self._add_finding({
 "severity": "low",
 "title": f"Technology Stack Disclosed: X-Powered-By: {powered_by}",
 "detail": f"The X-Powered-By header reveals backend technology: '{powered_by}'. Attackers use this to target language/framework-specific vulnerabilities.",
 "host": host,
 "url": base_url,
 "owasp": "A05 — Security Misconfiguration",
 "recommendation": "Remove X-Powered-By header. In PHP: expose_php = Off. In Express.js: app.disable('x-powered-by')",
 })

 # Check for stack traces in response body (send a broken request)
 if body:
 body_lower = body.lower()
 stack_indicators = self.payloads.get('info_disclosure', {}).get('stack_trace_indicators', [])
 for indicator in stack_indicators:
 if indicator in body_lower:
 self._add_finding({
 "severity": "medium",
 "title": "Stack Trace / Error Detail Disclosed in Response",
 "detail": f"The response body contains what appears to be a stack trace or detailed error message. This reveals internal code structure to attackers.",
 "host": host,
 "url": base_url,
 "owasp": "A05 — Security Misconfiguration",
 "recommendation": "Disable detailed error messages in production. Catch exceptions and show generic error pages. Log errors server-side only.",
 })
 break

 # ══════════════════════════════════════════════════════════════
 # TEST 11 — ADMIN PANEL DISCOVERY
 # ══════════════════════════════════════════════════════════════

 def _find_admin_panels(self, base_url: str):
 """
 Checks common paths for exposed admin panels.
 
 Admin panels left publicly accessible are a major risk.
 They're prime targets for brute force attacks and
 sometimes have authentication bypasses.
 """
 host = urllib.parse.urlparse(base_url).netloc
 admin_paths = self.payloads.get('common_admin_paths', [])

 for path in admin_paths:
 if not self._running:
 return

 test_url = f"{base_url.rstrip('/')}{path}"
 result = self._fetch(test_url, follow_redirects=False)

 if not result:
 continue

 status, _, body = result

 # 200 = accessible, 401/403 = exists but protected, 302 to login = exists
 if status == 200:
 # Check it's not just a 404 styled as 200
 if body and len(body) > 200:
 self._add_finding({
 "severity": "high",
 "title": f"Admin Panel Accessible: {path}",
 "detail": f"An admin interface was found at {test_url} (HTTP 200). Admin panels should not be publicly accessible.",
 "host": host,
 "url": test_url,
 "owasp": "A01 — Broken Access Control",
 "recommendation": "Restrict admin panel access by IP whitelist. Place behind VPN. Add multi-factor authentication.",
 })

 elif status in [401, 403]:
 self._add_finding({
 "severity": "medium",
 "title": f"Admin Panel Exists (Protected): {path}",
 "detail": f"An admin interface was found at {test_url} (HTTP {status} — protected but accessible). This is a brute force target.",
 "host": host,
 "url": test_url,
 "owasp": "A07 — Identification and Authentication Failures",
 "recommendation": "Restrict admin panel to IP whitelist. Enable MFA. Consider moving to a non-standard path and placing behind VPN.",
 })

 # ══════════════════════════════════════════════════════════════
 # HTTP HELPERS — making actual web requests
 # ══════════════════════════════════════════════════════════════

 def _fetch(self, url: str, follow_redirects: bool = True) -> tuple | None:
 """
 Makes a single HTTP GET request and returns the response.
 
 Returns a tuple of: (status_code, headers_dict, body_text)
 Returns None if the request fails for any reason.
 """
 try:
 # Build the request with a realistic User-Agent
 req = urllib.request.Request(url)
 req.add_header('User-Agent', 'Mozilla/5.0 Dayea/1.0 Security Assessment')
 req.add_header('Accept', 'text/html,application/xhtml+xml,application/json,*/*')

 opener = urllib.request.build_opener(
 urllib.request.HTTPSHandler(context=self.ssl_context)
 )
 if not follow_redirects:
 opener = urllib.request.build_opener(
 urllib.request.HTTPSHandler(context=self.ssl_context),
 NoRedirectHandler()
 )

 with opener.open(req, timeout=self.timeout) as response:
 status = response.status
 headers = dict(response.headers)
 # Read up to 50KB of response body
 body = response.read(51200).decode('utf-8', errors='ignore')
 return status, headers, body

 except urllib.error.HTTPError as e:
 # HTTP errors (403, 404, 500, etc.) are still valid responses
 try:
 body = e.read(10240).decode('utf-8', errors='ignore')
 except Exception:
 body = ""
 return e.code, dict(e.headers), body

 except Exception as e:
 self.logger.debug(f"Fetch failed for {url}: {type(e).__name__}")
 return None

 def _submit_form(self, action: str, method: str, data: dict) -> tuple | None:
 """
 Submits an HTML form with the given data.
 Works for both GET forms (appends to URL) and POST forms (sends in body).
 """
 try:
 encoded = urllib.parse.urlencode(data)

 if method.upper() == 'POST':
 req = urllib.request.Request(action, data=encoded.encode(), method='POST')
 req.add_header('Content-Type', 'application/x-www-form-urlencoded')
 else:
 separator = '&' if '?' in action else '?'
 url = f"{action}{separator}{encoded}"
 req = urllib.request.Request(url)

 req.add_header('User-Agent', 'Mozilla/5.0 Dayea/1.0 Security Assessment')

 opener = urllib.request.build_opener(
 urllib.request.HTTPSHandler(context=self.ssl_context)
 )

 with opener.open(req, timeout=self.timeout) as response:
 body = response.read(51200).decode('utf-8', errors='ignore')
 return response.status, dict(response.headers), body

 except urllib.error.HTTPError as e:
 try:
 body = e.read(10240).decode('utf-8', errors='ignore')
 except Exception:
 body = ""
 return e.code, dict(e.headers), body

 except Exception as e:
 self.logger.debug(f"Form submit failed: {e}")
 return None

 # ══════════════════════════════════════════════════════════════
 # SCOPE / TARGET HELPERS
 # ══════════════════════════════════════════════════════════════

 def _build_web_targets(self) -> list:
 """
 Converts scope entries into testable HTTP/HTTPS URLs.
 
 If scope has:
 "192.168.1.5" → tries http://192.168.1.5 and https://192.168.1.5
 "https://..." → uses as-is
 "example.com" → tries https://example.com
 """
 targets = []
 for entry in self.scope:
 entry = entry.strip()
 if not entry:
 continue

 if entry.startswith('http://') or entry.startswith('https://'):
 targets.append(entry)
 else:
 # Try HTTPS first, then HTTP
 https_url = f"https://{entry}"
 http_url = f"http://{entry}"

 if self._is_reachable(https_url):
 targets.append(https_url)
 elif self._is_reachable(http_url):
 targets.append(http_url)
 else:
 self.logger.info(f" No web service found on {entry}")

 return targets

 def _is_reachable(self, url: str) -> bool:
 """Quick check if a URL is reachable"""
 result = self._fetch(url)
 return result is not None

 # ══════════════════════════════════════════════════════════════
 # UTILITY HELPERS
 # ══════════════════════════════════════════════════════════════

 def _load_payloads(self) -> dict:
 """Load the web payload database"""
 path = "config/web_payloads.json"
 try:
 with open(path, 'r') as f:
 data = json.load(f)
 self.logger.info(f"Web payload database loaded")
 return data
 except Exception as e:
 self.logger.error(f"Could not load web payloads: {e}")
 return {}

 def _add_finding(self, finding: dict):
 """Add a finding, deduplicate, and push to GUI"""
 dedup_key = f"{finding.get('host')}:{finding.get('url','')}:{finding['title'][:50]}"
 for existing in self.findings:
 existing_key = f"{existing.get('host')}:{existing.get('url','')}:{existing['title'][:50]}"
 if existing_key == dedup_key:
 return

 finding['source'] = 'Breach'
 self.findings.append(finding)
 self.finding_cb(finding)
 self.logger.info(f" Finding [{finding['severity'].upper()}]: {finding['title']}")

 def _update_progress(self, percent: int, message: str):
 self.logger.info(f"[{percent}%] {message}")
 self.progress_cb(percent, message)

 def _update_progress_msg(self, message: str):
 self.logger.info(f" → {message}")
 self.progress_cb(None, message)

 def stop(self):
 self._running = False

 # ══════════════════════════════════════════════════════════════
 # REPORT
 # ══════════════════════════════════════════════════════════════

 def _build_report(self, start_time: float) -> dict:
 elapsed = round(time.time() - start_time, 1)

 severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
 for f in self.findings:
 sev = f.get("severity", "info")
 severity_counts[sev] = severity_counts.get(sev, 0) + 1

 # Group findings by OWASP category
 by_owasp = {}
 for f in self.findings:
 category = f.get("owasp", "Uncategorised")
 by_owasp.setdefault(category, []).append(f['title'])

 return {
 "module": "web_tester",
 "scan_type": "Web Application Security Test (OWASP Top 10)",
 "timestamp": datetime.now().isoformat(),
 "duration_seconds": elapsed,
 "scope": self.scope,
 "total_findings": len(self.findings),
 "severity_summary": severity_counts,
 "owasp_coverage": by_owasp,
 "findings": sorted(self.findings, key=lambda f:
 {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
 .get(f.get('severity', 'info'), 4))
 }

 def _save_report(self, report: dict):
 os.makedirs("reports", exist_ok=True)
 timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
 filename = f"reports/web_tester_{timestamp}.json"
 with open(filename, 'w') as f:
 json.dump(report, f, indent=2)
 self.logger.info(f"Breach report saved: {filename}")


# ── Helper class — prevents urllib from following redirects ──────
class NoRedirectHandler(urllib.request.HTTPErrorProcessor):
 """
 Custom handler that stops urllib from automatically following redirects.
 We need this to detect open redirects — if we follow them automatically,
 we can't see WHERE they're redirecting to.
 """
 def http_response(self, request, response):
 return response
 https_response = http_response
