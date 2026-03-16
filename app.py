"""
app.py — The Web Server

This is the bridge between the beautiful GUI in your browser
and the powerful toolkit engine running in Python.

Think of it like a restaurant:
  - The GUI (browser) is the dining room — what customers see
  - This file is the waiter — takes orders and delivers food
  - The toolkit modules are the kitchen — where work gets done

Flask is the framework that makes this web server possible.
When you visit http://localhost:5000, Flask serves the dashboard.
When you click "Start Scan", Flask tells the scanner to run.
"""

from flask import Flask, render_template, request, jsonify, Response
from datetime import datetime
import threading
import json
import os
import queue
import time

# ── Create the Flask application ────────────────────────────────
# This one line creates our entire web server
app = Flask(__name__)

# ── Global State ─────────────────────────────────────────────────
# These variables track what's happening across the whole session.
# Think of them as the whiteboard in the kitchen everyone can see.

scan_status = {
    "running": False,
    "module": None,
    "progress": 0,
    "findings": [],
    "log": [],
    "start_time": None,
    "authorized": False,
    "scope": []
}

# A queue is like a ticket line — results wait here until the browser picks them up
event_queue = queue.Queue()

# ── ROUTES — These are the "pages" and "actions" of the web app ──
# A route is like a door — each URL opens a different door.

@app.route('/')
def index():
    """
    The main dashboard page.
    When you open http://localhost:5000 this is what loads.
    """
    return render_template('index.html')


@app.route('/api/status', methods=['GET'])
def get_status():
    """
    Returns the current status of the toolkit as JSON.
    
    JSON is a data format — like a structured note passed between
    the server and the browser.
    
    The browser asks "what's going on?" every few seconds,
    and this endpoint answers.
    """
    return jsonify(scan_status)


@app.route('/api/authorize', methods=['POST'])
def authorize():
    """
    Handles the authorization form submission.
    
    When the user fills out the auth form and clicks Submit,
    this function processes it and confirms (or denies) authorization.
    """
    data = request.get_json()

    # Extract the form fields
    permission_confirmed = data.get('permission_confirmed', False)
    scope_input = data.get('scope', '').strip()
    legal_agreed = data.get('legal_agreed', False)

    # Validate all three requirements
    errors = []
    if not permission_confirmed:
        errors.append("You must confirm you have written permission to test.")
    if not scope_input:
        errors.append("You must define your authorized scope (target IPs or domains).")
    if not legal_agreed:
        errors.append("You must agree to the legal terms.")

    if errors:
        return jsonify({"success": False, "errors": errors}), 400

    # Parse scope into a list
    scope_list = [s.strip() for s in scope_input.split(',') if s.strip()]

    # Update global state
    scan_status['authorized'] = True
    scan_status['scope'] = scope_list

    # Log the authorization
    _add_log("Authorization confirmed", "success")
    _add_log(f" Authorized scope: {', '.join(scope_list)}", "info")

    # Save authorization record
    _save_auth_record(scope_list, data.get('permission_reference', ''))

    return jsonify({
        "success": True,
        "message": "Authorization confirmed. You may now run scans.",
        "scope": scope_list
    })


@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """
    Starts a scan module in a background thread.
    
    A "thread" is like hiring an extra worker — the scan runs
    in the background while the web page stays responsive.
    Without threading, the browser would freeze until the scan finished.
    """
    if not scan_status['authorized']:
        return jsonify({"success": False, "error": "Not authorized. Complete authorization first."}), 403

    if scan_status['running']:
        return jsonify({"success": False, "error": "A scan is already running. Please wait."}), 409

    data = request.get_json()
    module = data.get('module', 'scout')  # Which module to run

    # Reset state for new scan
    scan_status['running'] = True
    scan_status['module'] = module
    scan_status['progress'] = 0
    scan_status['findings'] = []
    scan_status['start_time'] = datetime.now().isoformat()

    # Start the scan in a background thread
    thread = threading.Thread(target=_run_scan, args=(module,))
    thread.daemon = True  # Thread dies when the main program exits
    thread.start()

    _add_log(f" {module.upper()} scan started", "info")

    return jsonify({"success": True, "message": f"{module} scan started"})


@app.route('/api/scan/stop', methods=['POST'])
def stop_scan():
    """Stop the currently running scan"""
    scan_status['running'] = False
    scan_status['progress'] = 0
    _add_log("⛔ Scan stopped by user", "warning")
    return jsonify({"success": True, "message": "Scan stopped"})


@app.route('/api/report/generate', methods=['POST'])
def generate_report():
    """
    Generates a professional PDF report from all saved scan results.
    Runs in a background thread so the browser stays responsive.
    """
    if not scan_status['authorized']:
        return jsonify({"success": False, "error": "Not authorized."}), 403

    if scan_status['running']:
        return jsonify({"success": False, "error": "A scan is running. Please wait."}), 409

    data            = request.get_json() or {}
    specific_files  = data.get('files', None)  # Optional: specific JSON files to include

    # Run report generation in background thread
    def _generate():
        scan_status['running'] = True
        scan_status['module']  = 'reporter'
        scan_status['progress'] = 0
        _add_log(" Starting PDF report generation...", "info")

        def on_progress(percent, message):
            if percent is not None:
                scan_status['progress'] = percent
                _push_event('progress', {'progress': percent, 'message': message})
            else:
                _add_log(f"  {message}", "info")

        try:
            from modules.reporter import Debrief

            settings = {'scope': scan_status['scope']}
            reporter = Debrief(
                settings=settings,
                logger=_make_simple_logger(),
                progress_callback=on_progress
            )

            pdf_path = reporter.run(specific_files=specific_files)

            scan_status['running']  = False
            scan_status['progress'] = 100
            _add_log(f"PDF report saved: {pdf_path}", "success")
            _push_event('report_ready', {'path': pdf_path, 'filename': os.path.basename(pdf_path)})

        except Exception as e:
            scan_status['running'] = False
            _add_log(f" Report generation failed: {str(e)}", "error")
            _push_event('complete', {'module': 'reporter', 'error': str(e)})

    thread = threading.Thread(target=_generate)
    thread.daemon = True
    thread.start()

    return jsonify({"success": True, "message": "Report generation started"})


@app.route('/api/reports', methods=['GET'])
def get_reports():
    """Returns a list of saved report files"""
    reports_dir = "reports"
    reports = []

    if os.path.exists(reports_dir):
        for filename in os.listdir(reports_dir):
            filepath = os.path.join(reports_dir, filename)
            stat = os.stat(filepath)
            reports.append({
                "name": filename,
                "size": f"{stat.st_size / 1024:.1f} KB",
                "created": datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M")
            })

    return jsonify({"reports": reports})


@app.route('/api/stream')
def stream():
    """
    Server-Sent Events (SSE) — Live updates pushed to the browser.
    
    This is how the progress bar updates in real time.
    Instead of the browser asking "any updates?" every second,
    the server PUSHES updates as they happen — like a live sports ticker.
    """
    def generate():
        while True:
            try:
                # Wait up to 1 second for a new event
                event = event_queue.get(timeout=1)
                yield f"data: {json.dumps(event)}\n\n"
            except queue.Empty:
                # Send a heartbeat so the connection stays alive
                yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"

    return Response(generate(), mimetype='text/event-stream')


# ── Private Helper Functions ─────────────────────────────────────
# These are internal functions — the kitchen staff, not the waiters.
# They're prefixed with _ to signal "these are internal use only"

def _run_scan(module: str):
    """
    Runs the actual scan module in the background.
    
    This dispatcher routes to the correct module class based on
    which scan was requested. Think of it as a traffic controller —
    it sends each job to the right team.
    
    Currently supported:
      scout      → NetworkScanner  (Module 1 — BUILT )
      inspector  → coming in Step 3
      web_tester → coming in Step 4
    """
    _add_log(f" Dispatching to {module} module...", "info")

    # ── Callbacks — how the module reports back to the GUI ──────
    # When the scanner finds something, it calls these functions.
    # These functions then push the data to the browser via SSE.

    def on_progress(percent, message):
        """Called by the module every time progress changes"""
        scan_status['progress'] = percent
        _push_event('progress', {'progress': percent, 'message': message})

    def on_finding(finding):
        """Called by the module every time a new finding is discovered"""
        scan_status['findings'].append(finding)
        _push_event('finding', finding)
        _add_log(f"    [{finding['severity'].upper()}] {finding['title']} — {finding['host']}", "warning")

    # ── Route to the correct module ──────────────────────────────

    if module == 'scout':
        # Recon — fully built
        try:
            from modules.scout import NetworkScanner

            settings = {
                'scope':        scan_status['scope'],
                'scan_timeout': 2,
                'max_threads':  50,
                'port_range':   '1-1024',
                'scan_speed':   'normal'
            }

            scanner = NetworkScanner(
                settings=settings,
                logger=_make_simple_logger(),
                progress_callback=on_progress,
                finding_callback=on_finding
            )

            report = scanner.run()

            if scan_status['running']:
                scan_status['running'] = False
                _add_log(f"Recon scan complete — {report.get('total_findings', 0)} finding(s)", "success")
                _push_event('complete', {
                    'module': module,
                    'summary': report.get('severity_summary', {}),
                    'hosts_alive': report.get('hosts_alive', 0)
                })

        except Exception as e:
            _add_log(f" Recon error: {str(e)}", "error")
            scan_status['running'] = False
            _push_event('complete', {'module': module, 'error': str(e)})

    elif module == 'inspector':
        # Intel — fully built
        try:
            from modules.inspector import VulnerabilityIntel

            settings = {
                'scope':        scan_status['scope'],
                'scan_timeout': 3,
                'nvd_api_key':  None  # Optional: add your free NVD key here
            }

            inspector = VulnerabilityIntel(
                settings=settings,
                logger=_make_simple_logger(),
                progress_callback=on_progress,
                finding_callback=on_finding
            )

            # Pass Recon results if available so Intel can use them
            scout_results = scan_status.get('scout_results', None)
            report = inspector.run(scout_results=scout_results)

            if scan_status['running']:
                scan_status['running'] = False
                _add_log(
                    f"Intel complete — {report.get('total_findings', 0)} "
                    f"finding(s) across {report.get('hosts_assessed', 0)} host(s)",
                    "success"
                )
                _push_event('complete', {
                    'module':          module,
                    'summary':         report.get('severity_summary', {}),
                    'hosts_assessed':  report.get('hosts_assessed', 0)
                })

        except Exception as e:
            _add_log(f" Intel error: {str(e)}", "error")
            scan_status['running'] = False
            _push_event('complete', {'module': module, 'error': str(e)})

    elif module == 'web_tester':
        # Breach — fully built
        try:
            from modules.web_tester import WebTester

            settings = {
                'scope':          scan_status['scope'],
                'scan_timeout':   5,
                'web_test_depth': 2
            }

            tester = WebTester(
                settings=settings,
                logger=_make_simple_logger(),
                progress_callback=on_progress,
                finding_callback=on_finding
            )

            report = tester.run()

            if scan_status['running']:
                scan_status['running'] = False
                _add_log(
                    f"Breach complete — {report.get('total_findings', 0)} "
                    f"finding(s) found",
                    "success"
                )
                _push_event('complete', {
                    'module':  module,
                    'summary': report.get('severity_summary', {}),
                    'owasp':   report.get('owasp_coverage', {})
                })

        except Exception as e:
            _add_log(f" Breach error: {str(e)}", "error")
            scan_status['running'] = False
            _push_event('complete', {'module': module, 'error': str(e)})

    else:
        _add_log(f" Unknown module: {module}", "error")
        scan_status['running'] = False


def _run_placeholder_scan(module: str, progress_cb, finding_cb):
    """
    Placeholder for modules not yet built.
    Shows realistic progress so the GUI looks right while we build.
    """
    phases = {
        'inspector': [
            (10, "Loading vulnerability database..."),
            (25, "Connecting to target..."),
            (40, "Checking known CVEs..."),
            (55, "Testing service versions..."),
            (70, "Checking for misconfigurations..."),
            (85, "Cross-referencing findings..."),
            (100, "Vulnerability assessment complete!")
        ],
        'web_tester': [
            (10, "Initializing web scanner..."),
            (20, "Crawling target website..."),
            (35, "Testing for SQL Injection..."),
            (50, "Testing for XSS vulnerabilities..."),
            (65, "Checking authentication controls..."),
            (80, "Testing for insecure configurations..."),
            (90, "Analyzing discovered endpoints..."),
            (100, "Web scan complete!")
        ]
    }

    for progress, message in phases.get(module, []):
        if not scan_status['running']:
            break
        time.sleep(1.5)
        progress_cb(progress, message)

        if progress in [40, 70, 85]:
            finding = _generate_simulated_finding(module, progress)
            scan_status['findings'].append(finding)
            finding_cb(finding)

    if scan_status['running']:
        scan_status['running'] = False
        _add_log(f"{module} scan complete (demo mode)", "success")
        _push_event('complete', {'module': module})


def _generate_simulated_finding(module: str, progress: int) -> dict:
    """Generate a realistic-looking simulated finding for demo purposes"""
    findings_pool = {
        'scout': [
            {"severity": "info", "title": "Open Port Discovered", "detail": "Port 22 (SSH) open on 192.168.1.1", "host": "192.168.1.1"},
            {"severity": "medium", "title": "Outdated Service Detected", "detail": "Apache 2.2.15 — version is end-of-life", "host": "192.168.1.5"},
            {"severity": "low", "title": "Multiple Open Ports", "detail": "15 open ports found on 192.168.1.22", "host": "192.168.1.22"},
        ],
        'inspector': [
            {"severity": "high", "title": "CVE-2023-44487 Detected", "detail": "HTTP/2 Rapid Reset Attack vulnerability found", "host": "192.168.1.5"},
            {"severity": "medium", "title": "Weak SSL Configuration", "detail": "TLS 1.0 still enabled — should be disabled", "host": "192.168.1.1"},
            {"severity": "critical", "title": "Default Credentials Active", "detail": "Admin panel accessible with default password", "host": "192.168.1.22"},
        ],
        'web_tester': [
            {"severity": "high", "title": "XSS Vulnerability Found", "detail": "Reflected XSS in search parameter on /search?q=", "host": "192.168.1.5"},
            {"severity": "medium", "title": "Missing Security Headers", "detail": "Content-Security-Policy header not set", "host": "192.168.1.5"},
            {"severity": "critical", "title": "SQL Injection Detected", "detail": "Login form vulnerable to boolean-based SQLi", "host": "192.168.1.5"},
        ]
    }

    pool = findings_pool.get(module, findings_pool['scout'])
    idx = [35, 65, 85].index(progress) % len(pool)
    return pool[idx]


def _generate_report(module: str):
    """Save a JSON report of the scan findings"""
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/{module}_scan_{timestamp}.json"

    report = {
        "module": module,
        "timestamp": datetime.now().isoformat(),
        "scope": scan_status['scope'],
        "findings": scan_status['findings'],
        "total_findings": len(scan_status['findings'])
    }

    with open(filename, 'w') as f:
        json.dump(report, f, indent=2)


def _add_log(message: str, level: str = "info"):
    """Add a message to the activity log"""
    entry = {
        "time": datetime.now().strftime("%H:%M:%S"),
        "message": message,
        "level": level
    }
    scan_status['log'].append(entry)
    # Keep only the last 100 log entries to prevent memory bloat
    if len(scan_status['log']) > 100:
        scan_status['log'] = scan_status['log'][-100:]
    _push_event('log', entry)


def _push_event(event_type: str, data: dict):
    """Push a live event to the browser via the SSE stream"""
    event_queue.put({"type": event_type, "data": data})


def _make_simple_logger():
    """
    Creates a lightweight logger compatible with the Recon module.
    
    Recon expects a logger with .info(), .warning(), .error(), .debug()
    methods. This simple wrapper satisfies that interface while routing
    everything through our existing _add_log system.
    """
    class SimpleLogger:
        def info(self, msg):    _add_log(f"  {msg}", "info")
        def warning(self, msg): _add_log(f"   {msg}", "warning")
        def error(self, msg):   _add_log(f"   {msg}", "error")
        def debug(self, msg):   pass  # Don't flood the GUI with debug msgs
        def section(self, title): _add_log(f"── {title} ──", "info")
    return SimpleLogger()


def _save_auth_record(scope: list, reference: str):
    """Save authorization record to disk"""
    os.makedirs("logs", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    with open(f"logs/auth_{timestamp}.txt", 'w') as f:
        f.write(f"Authorization Record\n")
        f.write(f"Time: {datetime.now().isoformat()}\n")
        f.write(f"Scope: {', '.join(scope)}\n")
        f.write(f"Reference: {reference}\n")


# ── Start the server ─────────────────────────────────────────────
if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════════╗
    ║    Dayea — Web Interface                ║
    ║                                              ║
    ║  Open your browser and go to:                ║
    ║  → http://localhost:5000                     ║
    ║                                              ║
    ║  Press Ctrl+C to stop the server             ║
    ╚══════════════════════════════════════════════╝
    """)

    # debug=False in production, debug=True shows detailed errors during dev
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
