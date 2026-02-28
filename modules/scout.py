"""
scout.py — Recon: Network Scanner

This is Module 1. Think of Recon as a highly trained
reconnaissance expert who walks the perimeter of a building
and documents every door, window, and security camera.

What Recon actually does:
  1. PING SWEEP  — Finds which devices are alive on the network
                   (like knocking on every door to see who answers)

  2. PORT SCAN   — For each live device, checks which ports are open
                   (like checking if each door/window is locked or open)
                   Ports are numbered communication channels — 
                   Port 80 = web traffic, Port 22 = SSH remote access, etc.

  3. SERVICE ID  — Tries to figure out WHAT is running on open ports
                   (like looking through the window to see what's inside)

  4. OS DETECT   — Makes an educated guess at the operating system
                   (is this a Windows PC, a Linux server, a router?)

All of this uses ONLY built-in Python libraries — no exploits,
no attacks, just observation. Like a security camera, not a battering ram.

HOW PORTS WORK (simple explanation):
  Imagine a building (computer) with 65,535 numbered doors (ports).
  Some doors are open (listening for connections), most are closed.
  Open door 80? Probably a website inside.
  Open door 22? Probably SSH (remote login).
  Open door 3306? Probably a database.
  Recon's job is to find out which doors are open and what's behind them.
"""

import socket
import threading
import ipaddress
import subprocess
import platform
import time
import json
import os
from datetime import datetime
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed


# ── Well-Known Port Definitions ──────────────────────────────────
# These are the most common port→service mappings.
# Think of it as a dictionary: "if port 80 is open, it's probably HTTP"
KNOWN_PORTS = {
    21:   {"service": "FTP",         "desc": "File Transfer Protocol",         "risk": "medium"},
    22:   {"service": "SSH",         "desc": "Secure Shell (remote access)",    "risk": "low"},
    23:   {"service": "Telnet",      "desc": "Unencrypted remote access",       "risk": "high"},
    25:   {"service": "SMTP",        "desc": "Email sending",                   "risk": "medium"},
    53:   {"service": "DNS",         "desc": "Domain Name System",              "risk": "low"},
    80:   {"service": "HTTP",        "desc": "Web server (unencrypted)",        "risk": "low"},
    110:  {"service": "POP3",        "desc": "Email retrieval",                 "risk": "medium"},
    135:  {"service": "RPC",         "desc": "Windows Remote Procedure Call",   "risk": "high"},
    139:  {"service": "NetBIOS",     "desc": "Windows file sharing",            "risk": "high"},
    143:  {"service": "IMAP",        "desc": "Email protocol",                  "risk": "medium"},
    443:  {"service": "HTTPS",       "desc": "Secure web server",               "risk": "low"},
    445:  {"service": "SMB",         "desc": "Windows file sharing (SMB)",      "risk": "critical"},
    1433: {"service": "MSSQL",       "desc": "Microsoft SQL Server",            "risk": "high"},
    1521: {"service": "Oracle DB",   "desc": "Oracle Database",                 "risk": "high"},
    3306: {"service": "MySQL",       "desc": "MySQL Database",                  "risk": "high"},
    3389: {"service": "RDP",         "desc": "Remote Desktop Protocol",         "risk": "high"},
    5432: {"service": "PostgreSQL",  "desc": "PostgreSQL Database",             "risk": "high"},
    5900: {"service": "VNC",         "desc": "Virtual Network Computing",       "risk": "high"},
    6379: {"service": "Redis",       "desc": "Redis Database (often unsecured)","risk": "critical"},
    8080: {"service": "HTTP-Alt",    "desc": "Alternative web server port",     "risk": "medium"},
    8443: {"service": "HTTPS-Alt",   "desc": "Alternative HTTPS port",          "risk": "low"},
    27017:{"service": "MongoDB",     "desc": "MongoDB Database",                "risk": "critical"},
}

# Severity color mapping for the dashboard
RISK_SEVERITY = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "info":     "info"
}


class NetworkScanner:
    """
    Recon — discovers and maps networks.
    
    This class is the entire brain of Module 1.
    You create one of these, call run(), and it does everything.
    """

    def __init__(self, settings: dict, logger, progress_callback=None, finding_callback=None):
        """
        Set up the scanner with settings and callbacks.
        
        A "callback" is a function you pass in so the scanner can
        call it when something happens — like leaving a voicemail number
        so we can call you back when results are ready.
        
        Args:
            settings:          The config dict (scan speed, ports, etc.)
            logger:            The logger object for recording activity
            progress_callback: Called every time progress changes
            finding_callback:  Called every time a finding is discovered
        """
        self.settings         = settings
        self.logger           = logger
        self.progress_cb      = progress_callback or (lambda p, m: None)
        self.finding_cb       = finding_callback  or (lambda f: None)

        # Pull settings with safe defaults
        self.scope            = settings.get('scope', [])
        self.timeout          = settings.get('scan_timeout', 2)
        self.max_threads      = settings.get('max_threads', 50)
        self.port_range       = settings.get('port_range', '1-1024')
        self.scan_speed       = settings.get('scan_speed', 'normal')

        # Results storage
        self.live_hosts       = []   # IPs that responded to ping
        self.scan_results     = {}   # Full results per host
        self.findings         = []   # Security findings for the report

        # Thread-safety lock — prevents two threads writing at the same time
        # Think of it like a "one person in the bathroom at a time" sign
        self._lock            = threading.Lock()
        self._running         = True

        # Adjust timeout based on scan speed
        speed_timeouts = {'slow': 3, 'normal': 2, 'fast': 1}
        self.timeout = speed_timeouts.get(self.scan_speed, 2)

    # ══════════════════════════════════════════════════════════════
    # MAIN RUN METHOD — called from app.py
    # ══════════════════════════════════════════════════════════════

    def run(self) -> dict:
        """
        Runs the full scout scan sequence.
        
        Returns a dictionary with all discovered information.
        """
        self.logger.section("RECON — NETWORK SCANNER STARTED")
        start_time = time.time()

        # ── Phase 1: Resolve & expand scope ─────────────────────
        self._update_progress(5, "🔍 Resolving scope targets...")
        targets = self._expand_scope()

        if not targets:
            self.logger.error("No valid targets in scope")
            return {"error": "No valid targets found in scope"}

        self.logger.info(f"Scope expanded to {len(targets)} target IPs")
        self._update_progress(10, f"📋 {len(targets)} targets queued for scanning")

        # ── Phase 2: Ping Sweep — find live hosts ────────────────
        self._update_progress(15, "📡 Starting ping sweep to find live hosts...")
        self._ping_sweep(targets)

        if not self.live_hosts:
            self._update_progress(100, "⚠️ No live hosts found in scope")
            return {"live_hosts": [], "findings": [], "note": "No hosts responded to ping"}

        self.logger.info(f"Found {len(self.live_hosts)} live host(s)")
        self._update_progress(35, f"✅ Found {len(self.live_hosts)} live host(s) — starting port scan")

        # ── Phase 3: Port Scan — check each live host ────────────
        self._update_progress(40, "🔌 Scanning ports on live hosts...")
        self._port_scan_all_hosts()

        # ── Phase 4: Service Identification ─────────────────────
        self._update_progress(75, "🔎 Identifying services and grabbing banners...")
        self._identify_services()

        # ── Phase 5: Generate Findings ───────────────────────────
        self._update_progress(88, "⚠️  Analyzing results for security findings...")
        self._generate_findings()

        # ── Phase 6: Save Report ─────────────────────────────────
        self._update_progress(95, "💾 Saving scan report...")
        report = self._build_report(start_time)
        self._save_report(report)

        elapsed = round(time.time() - start_time, 1)
        self._update_progress(100, f"✅ Recon scan complete in {elapsed}s — {len(self.findings)} finding(s)")

        self.logger.info(f"Recon scan finished. Duration: {elapsed}s | Findings: {len(self.findings)}")
        return report

    # ══════════════════════════════════════════════════════════════
    # PHASE 1 — SCOPE EXPANSION
    # Turn "192.168.1.0/24" into a list of individual IP addresses
    # ══════════════════════════════════════════════════════════════

    def _expand_scope(self) -> list:
        """
        Converts scope entries into a flat list of individual IP addresses.
        
        The scope might say "192.168.1.0/24" which means
        "all 256 addresses from 192.168.1.0 to 192.168.1.255"
        This function expands that into the full list.
        
        It also resolves domain names to IPs.
        e.g. "testsite.example.com" → "203.0.113.42"
        """
        all_targets = []

        for entry in self.scope:
            entry = entry.strip()
            if not entry:
                continue

            try:
                # Is it a CIDR range like 192.168.1.0/24?
                if '/' in entry:
                    network = ipaddress.ip_network(entry, strict=False)
                    # Limit to 254 hosts max per range (skip network & broadcast)
                    hosts = list(network.hosts())[:254]
                    all_targets.extend([str(ip) for ip in hosts])
                    self.logger.info(f"Expanded {entry} to {len(hosts)} hosts")

                # Is it an IP range like 192.168.1.1-50?
                elif '-' in entry and entry.count('.') == 3:
                    parts = entry.rsplit('-', 1)
                    base_ip = parts[0]
                    end_num = int(parts[1])
                    start_num = int(base_ip.split('.')[-1])
                    base = '.'.join(base_ip.split('.')[:-1])
                    for i in range(start_num, end_num + 1):
                        all_targets.append(f"{base}.{i}")

                # Is it a plain IP like 192.168.1.100?
                elif self._is_valid_ip(entry):
                    all_targets.append(entry)

                # Must be a hostname/domain — resolve it
                else:
                    resolved = socket.gethostbyname(entry)
                    all_targets.append(resolved)
                    self.logger.info(f"Resolved {entry} → {resolved}")

            except Exception as e:
                self.logger.warning(f"Could not parse scope entry '{entry}': {e}")

        # Remove duplicates while preserving order
        seen = set()
        unique = []
        for ip in all_targets:
            if ip not in seen:
                seen.add(ip)
                unique.append(ip)

        return unique

    # ══════════════════════════════════════════════════════════════
    # PHASE 2 — PING SWEEP
    # Find which hosts are actually alive before scanning ports
    # ══════════════════════════════════════════════════════════════

    def _ping_sweep(self, targets: list):
        """
        Sends a ping to every target IP and records which ones reply.
        
        Pinging is like knocking on a door — if someone answers, 
        the host is alive. If nobody answers after a few seconds,
        we move on.
        
        Uses multi-threading to ping many hosts simultaneously,
        which is WAY faster than pinging one at a time.
        """
        self.logger.info(f"Pinging {len(targets)} hosts...")
        results = []

        def ping_host(ip):
            """Ping a single host and return True if it responds"""
            try:
                # Different ping command on Windows vs Mac/Linux
                if platform.system().lower() == 'windows':
                    cmd = ['ping', '-n', '1', '-w', '1000', ip]
                else:
                    cmd = ['ping', '-c', '1', '-W', '1', ip]

                result = subprocess.run(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=3
                )
                return ip, result.returncode == 0

            except subprocess.TimeoutExpired:
                return ip, False
            except Exception:
                # Fall back to TCP connect if ping fails (firewalls often block ping)
                return ip, self._tcp_ping(ip)

        # Run all pings simultaneously using a thread pool
        # A "thread pool" is like hiring a team of workers instead of one person
        with ThreadPoolExecutor(max_workers=min(self.max_threads, 50)) as pool:
            futures = {pool.submit(ping_host, ip): ip for ip in targets}

            completed = 0
            for future in as_completed(futures):
                if not self._running:
                    break
                ip, is_alive = future.result()
                completed += 1

                if is_alive:
                    with self._lock:
                        self.live_hosts.append(ip)
                    self.logger.info(f"  ✅ ALIVE: {ip}")
                    # Report finding: live host discovered
                    self.finding_cb({
                        "severity": "info",
                        "title": "Live Host Discovered",
                        "detail": f"Host {ip} is online and responding",
                        "host": ip,
                        "port": None,
                        "service": None
                    })

                # Update progress proportionally through the ping phase (15-35%)
                ping_progress = 15 + int((completed / len(targets)) * 20)
                self._update_progress(ping_progress, f"📡 Ping sweep: {completed}/{len(targets)} — {len(self.live_hosts)} alive")

        self.live_hosts.sort(key=lambda ip: [int(p) for p in ip.split('.')])
        self.logger.info(f"Ping sweep complete. {len(self.live_hosts)}/{len(targets)} hosts alive.")

    def _tcp_ping(self, ip: str, port: int = 80) -> bool:
        """
        Alternative to ICMP ping — tries to connect to port 80.
        Used when regular ping is blocked by a firewall.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    # ══════════════════════════════════════════════════════════════
    # PHASE 3 — PORT SCANNING
    # For each live host, check which ports are open
    # ══════════════════════════════════════════════════════════════

    def _port_scan_all_hosts(self):
        """
        Runs a port scan on every live host that was found.
        Scans them one at a time to avoid overwhelming networks.
        """
        ports_to_scan = self._parse_port_range()
        total_hosts = len(self.live_hosts)

        for idx, host in enumerate(self.live_hosts):
            if not self._running:
                break

            self.logger.info(f"Port scanning {host} ({idx+1}/{total_hosts})...")
            progress = 40 + int((idx / total_hosts) * 30)
            self._update_progress(progress, f"🔌 Scanning ports on {host} ({idx+1}/{total_hosts})")

            open_ports = self._scan_host_ports(host, ports_to_scan)

            with self._lock:
                self.scan_results[host] = {
                    "ip": host,
                    "hostname": self._resolve_hostname(host),
                    "open_ports": open_ports,
                    "os_hint": self._os_fingerprint(host, open_ports),
                    "scan_time": datetime.now().isoformat()
                }

            self.logger.info(f"  {host}: {len(open_ports)} open port(s) found")

    def _scan_host_ports(self, ip: str, ports: list) -> list:
        """
        Scans all specified ports on a single host.
        Uses multi-threading to scan many ports at once.
        
        Returns a list of open port numbers.
        """
        open_ports = []
        port_queue = Queue()

        for port in ports:
            port_queue.put(port)

        def worker():
            """Each worker thread pulls ports from the queue and checks them"""
            while not port_queue.empty():
                try:
                    port = port_queue.get_nowait()
                    if self._is_port_open(ip, port):
                        with self._lock:
                            open_ports.append(port)
                    port_queue.task_done()
                except Exception:
                    break

        # Spawn worker threads
        threads = []
        thread_count = min(self.max_threads, len(ports), 100)
        for _ in range(thread_count):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)

        for t in threads:
            t.join(timeout=30)

        return sorted(open_ports)

    def _is_port_open(self, ip: str, port: int) -> bool:
        """
        The core check: is this specific port open on this IP?
        
        We create a socket (connection attempt) and see if anything answers.
        If it connects → port is open.
        If it refuses or times out → port is closed.
        
        Think of it as dialing a phone number:
          - Rings and someone answers → open
          - Busy signal → closed (refused)
          - No answer (timeout) → filtered by firewall
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0  # 0 means success (connected!)
        except socket.error:
            return False

    # ══════════════════════════════════════════════════════════════
    # PHASE 4 — SERVICE IDENTIFICATION
    # Figure out WHAT is running on each open port
    # ══════════════════════════════════════════════════════════════

    def _identify_services(self):
        """
        For each open port found, tries to identify what service is running.
        
        Two methods:
        1. Banner grabbing — connect and read what the service says about itself
                             (like listening to a person's voicemail greeting)
        2. Port lookup    — check our KNOWN_PORTS dictionary
        """
        for ip, data in self.scan_results.items():
            enriched_ports = []
            for port in data['open_ports']:
                service_info = self._get_service_info(ip, port)
                enriched_ports.append(service_info)
                self.logger.debug(f"  {ip}:{port} → {service_info['service']}")

            self.scan_results[ip]['port_details'] = enriched_ports

    def _get_service_info(self, ip: str, port: int) -> dict:
        """
        Gets detailed info about a single open port.
        
        Returns a dict with service name, description, banner, and risk level.
        """
        # Start with known port info (if we recognize this port number)
        known = KNOWN_PORTS.get(port, {
            "service": f"Unknown ({port})",
            "desc": "Unrecognized service",
            "risk": "info"
        })

        info = {
            "port":    port,
            "service": known["service"],
            "desc":    known["desc"],
            "risk":    known["risk"],
            "banner":  None,
            "version": None
        }

        # Try banner grabbing — connect and read the first response
        banner = self._grab_banner(ip, port)
        if banner:
            info["banner"] = banner
            # Try to extract version info from banner
            info["version"] = self._parse_version_from_banner(banner)

        return info

    def _grab_banner(self, ip: str, port: int, timeout: float = 2.0) -> str | None:
        """
        Connects to a port and reads the first thing it says.
        
        Many services announce themselves when you connect:
          SSH:   "SSH-2.0-OpenSSH_8.4p1 Ubuntu-5ubuntu1.1"
          FTP:   "220 (vsFTPd 3.0.3)"
          SMTP:  "220 mail.example.com ESMTP Postfix"
        
        This is called "banner grabbing."
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))

            # For HTTP ports, send a HEAD request to get a response
            if port in [80, 8080, 8000]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port in [443, 8443]:
                sock.close()
                return None  # HTTPS needs TLS, skip for now
            else:
                # For other services, just wait for them to speak first
                pass

            # Read up to 1KB of response
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()

            # Clean up the banner — remove unprintable characters
            banner = ' '.join(banner.split())[:200]
            return banner if banner else None

        except Exception:
            return None

    def _parse_version_from_banner(self, banner: str) -> str | None:
        """
        Tries to extract a version number from a banner string.
        Example: "SSH-2.0-OpenSSH_8.4" → "OpenSSH_8.4"
        """
        if not banner:
            return None

        import re
        # Look for patterns like: word/1.2.3 or word_1.2.3 or word 1.2.3
        patterns = [
            r'(\w+)[/_\s]([\d]+\.[\d]+\.?[\d]*)',  # Apache/2.4.51
            r'(\w+)-([\d]+\.[\d]+\.?[\d]*)',         # OpenSSH-8.4
        ]
        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return f"{match.group(1)} {match.group(2)}"
        return None

    # ══════════════════════════════════════════════════════════════
    # PHASE 5 — GENERATE SECURITY FINDINGS
    # Turn raw data into actionable security findings
    # ══════════════════════════════════════════════════════════════

    def _generate_findings(self):
        """
        Analyzes all scan results and generates security findings.
        
        A "finding" is a specific, actionable security observation.
        Not just "port 23 is open" but "Telnet is running — this is
        dangerous because it sends passwords in plain text."
        """
        for ip, data in self.scan_results.items():
            port_details = data.get('port_details', [])

            for port_info in port_details:
                port    = port_info['port']
                service = port_info['service']
                risk    = port_info['risk']
                desc    = port_info['desc']
                banner  = port_info.get('banner')
                version = port_info.get('version')

                # Skip pure info items from creating findings
                if risk == 'info':
                    continue

                # Build a finding entry
                finding = {
                    "severity": risk,
                    "title":    f"Open Port: {port}/{service}",
                    "detail":   f"{desc} detected on port {port}",
                    "host":     ip,
                    "port":     port,
                    "service":  service,
                    "banner":   banner,
                    "version":  version,
                    "recommendation": self._get_recommendation(port, service)
                }

                # Escalate severity for especially dangerous combos
                if port == 23:  # Telnet
                    finding["severity"] = "critical"
                    finding["detail"]   = "Telnet sends ALL data (including passwords) in plain text. Should be disabled immediately."

                if port == 445:  # SMB — EternalBlue territory
                    finding["severity"] = "critical"
                    finding["detail"]   = "SMB (Windows file sharing) exposed. Historically targeted by WannaCry & NotPetya ransomware."

                if port in [6379, 27017] and not banner:  # Redis/MongoDB often unauthenticated
                    finding["severity"] = "critical"
                    finding["detail"]   = f"{service} database may be exposed without authentication. High risk of data breach."

                self.findings.append(finding)
                # Push the finding to the GUI in real time
                self.finding_cb(finding)
                self.logger.warning(f"Finding [{risk.upper()}]: {finding['title']} on {ip}")

    def _get_recommendation(self, port: int, service: str) -> str:
        """Returns a plain-English recommendation for each finding"""
        recs = {
            21:   "Disable FTP if possible. Use SFTP (port 22) instead — it's encrypted.",
            22:   "Ensure SSH uses key-based auth only. Disable password login.",
            23:   "DISABLE TELNET IMMEDIATELY. Replace with SSH.",
            25:   "Ensure SMTP requires authentication. Block open relay.",
            80:   "Consider redirecting HTTP to HTTPS.",
            135:  "Block RPC from external access. High malware attack vector.",
            139:  "Disable NetBIOS if not needed. Common malware target.",
            445:  "Ensure SMB is patched (MS17-010). Block from internet.",
            1433: "Database should not be internet-facing. Use a firewall.",
            3306: "Database should not be internet-facing. Use a firewall.",
            3389: "Restrict RDP to VPN only. Enable NLA. Use a jump host.",
            5900: "VNC should be behind a VPN. Change default passwords.",
            6379: "Redis must require AUTH. Should never be internet-facing.",
            27017:"MongoDB must require authentication. Should not be internet-facing.",
        }
        return recs.get(port, f"Review whether {service} needs to be publicly accessible.")

    # ══════════════════════════════════════════════════════════════
    # HELPERS — Utility functions used throughout
    # ══════════════════════════════════════════════════════════════

    def _parse_port_range(self) -> list:
        """
        Converts a port range string into a list of port numbers.
        "1-1024" → [1, 2, 3, ..., 1024]
        "22,80,443" → [22, 80, 443]
        """
        ports = []
        parts = self.port_range.split(',')
        for part in parts:
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        # Always include the most dangerous ports even if not in range
        critical_extras = [445, 3389, 6379, 27017, 1433, 3306]
        for p in critical_extras:
            if p not in ports:
                ports.append(p)
        return sorted(set(ports))

    def _resolve_hostname(self, ip: str) -> str:
        """Try to look up the hostname for an IP address"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ip

    def _is_valid_ip(self, string: str) -> bool:
        """Check if a string is a valid IP address"""
        try:
            socket.inet_aton(string)
            return True
        except socket.error:
            return False

    def _os_fingerprint(self, ip: str, open_ports: list) -> str:
        """
        Makes an educated guess at the OS based on open ports.
        
        This is NOT definitive — it's pattern matching based on
        which ports are typically open on different systems.
        """
        if 3389 in open_ports or 135 in open_ports or 139 in open_ports:
            return "Windows (likely)"
        if 22 in open_ports and 80 in open_ports:
            return "Linux/Unix (likely)"
        if 548 in open_ports or 5009 in open_ports:
            return "macOS (likely)"
        if len(open_ports) <= 2 and 80 in open_ports:
            return "Network device / IoT (possible)"
        return "Unknown"

    def _update_progress(self, percent: int, message: str):
        """Update the progress bar and log the message"""
        self.logger.info(f"[{percent}%] {message}")
        self.progress_cb(percent, message)

    def stop(self):
        """Stop the scan gracefully"""
        self._running = False
        self.logger.warning("Recon scan stopped by user")

    # ══════════════════════════════════════════════════════════════
    # PHASE 6 — REPORT GENERATION
    # ══════════════════════════════════════════════════════════════

    def _build_report(self, start_time: float) -> dict:
        """Build the final report dictionary"""
        elapsed = round(time.time() - start_time, 1)

        # Count findings by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "module":           "scout",
            "scan_type":        "Network Scanner",
            "timestamp":        datetime.now().isoformat(),
            "duration_seconds": elapsed,
            "scope":            self.scope,
            "hosts_scanned":    len(self._expand_scope()),
            "hosts_alive":      len(self.live_hosts),
            "total_findings":   len(self.findings),
            "severity_summary": severity_counts,
            "hosts":            self.scan_results,
            "findings":         self.findings
        }

    def _save_report(self, report: dict):
        """Save the report as a JSON file"""
        os.makedirs("reports", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename  = f"reports/scout_{timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        self.logger.info(f"Report saved: {filename}")
