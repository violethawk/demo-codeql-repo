#!/usr/bin/env python3
"""SAGE Interactive Demo: browser-based live remediation.

    python -m sage interactive
    # Open http://localhost:8000

Click a vulnerability. Watch SAGE process it. See the code transform.
"""

import http.server
import json
import io
import os
import sys
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse, parse_qs

# Job queue for async remediation
_jobs: dict[str, dict] = {}  # job_id -> {status, result, created_at}
_jobs_lock = threading.Lock()
_JOB_MAX_AGE = 300  # seconds — completed jobs older than this are cleaned up

# Thread-local storage for per-thread stdout capture
_thread_local = threading.local()


class _ThreadCapturingStdout:
    """Stdout wrapper that captures output per-thread when active."""

    def __init__(self, real_stdout):
        self._real = real_stdout

    def write(self, text):
        buf = getattr(_thread_local, "capture_buffer", None)
        if buf is not None:
            buf.write(text)
        else:
            self._real.write(text)

    def flush(self):
        self._real.flush()

    def __getattr__(self, name):
        return getattr(self._real, name)

# Vulnerable app.py — the known-good starting state.
# Hardcoded so the demo always starts from the vulnerable version,
# regardless of what's on disk when the server launches.
APP_PATH = Path("demo/app.py")
APP_ORIGINAL = '''\
import os
import sqlite3

from flask import Flask, request, jsonify

app = Flask(__name__)

DATABASE = "users.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/search")
def search_user():
    user_input = request.args.get("name", "")
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor = get_db().cursor()
    cursor.execute(query)
    return jsonify([dict(r) for r in cursor.fetchall()])


@app.route("/search_page")
def search_page():
    user_input = request.args.get("query", "")
    return f"<h1>Results for {user_input}</h1>"


@app.route("/ping")
def ping_host():
    host = request.args.get("host", "127.0.0.1")
    os.system("ping -c 1 " + host)
    return jsonify({"status": "ok"})


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(debug=True)
'''

# Fixed code snippets (pre-computed for instant display)
FIXED_SNIPPETS = {
    "CWE-89": {
        "before": '''    user_input = request.args.get("name", "")
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor = get_db().cursor()
    cursor.execute(query)''',
        "after": '''    user_input = request.args.get("name", "")
    cursor = get_db().cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (user_input,))''',
    },
    "CWE-79": {
        "before": '    user_input = request.args.get("query", "")\n    return f"&lt;h1&gt;Results for {user_input}&lt;/h1&gt;"',
        "after": '    user_input = request.args.get("query", "")\n    return f"&lt;h1&gt;Results for {html.escape(user_input)}&lt;/h1&gt;"',
    },
    "CWE-78": {
        "before": '''    host = request.args.get("host", "127.0.0.1")
    os.system("ping -c 1 " + host)''',
        "after": '''    host = request.args.get("host", "127.0.0.1")
    subprocess.run(["ping", "-c", "1", host], capture_output=True)''',
    },
    "CWE-798": {
        "before": '''DATABASE_PASSWORD = "supersecret123"''',
        "after": '''DATABASE_PASSWORD = os.environ["DATABASE_PASSWORD"]''',
    },
    "CWE-287": {
        "before": '''if user.role == "admin" or debug_mode:''',
        "after": '''if user.role == "admin":''',
    },
}

FIXTURES = {
    "CWE-89": "demo/fixtures/sample_alert.json",
    "CWE-79": "demo/fixtures/sample_alert_xss.json",
    "CWE-78": "demo/fixtures/sample_alert_cmdi.json",
    "CWE-798": "demo/fixtures/sample_alert_creds.json",
    "CWE-287": "demo/fixtures/sample_alert_auth.json",
}

# Routing metadata for display
ROUTING_INFO = {
    "CWE-89": {
        "action": "AUTO_REMEDIATE",
        "team": "backend",
        "channel": "#backend-security",
        "reviewers": ["backend-dev-1", "backend-dev-2"],
        "security_review": False,
        "sla": "24h",
    },
    "CWE-79": {
        "action": "REMEDIATE_WITH_REVIEW",
        "team": "frontend",
        "channel": "#frontend-security",
        "reviewers": ["frontend-dev-1"],
        "security_review": True,
        "security_reviewer": "security-lead",
        "sla": "24h",
    },
    "CWE-78": {
        "action": "REMEDIATE_WITH_REVIEW",
        "team": "platform",
        "channel": "#platform-security",
        "reviewers": ["platform-dev-1", "platform-dev-2"],
        "security_review": True,
        "security_reviewer": "security-lead",
        "sla": "24h",
    },
    "CWE-798": {
        "action": "ESCALATE",
        "team": "platform",
        "channel": "#platform-security",
        "reviewers": [],
        "security_review": True,
        "security_reviewer": "security-lead",
        "sla": "12h",
    },
    "CWE-287": {
        "action": "ESCALATE",
        "team": "backend",
        "channel": "#backend-security",
        "reviewers": [],
        "security_review": True,
        "security_reviewer": "security-lead",
        "sla": "12h",
    },
}

def _load_html() -> str:
    """Load the HTML template and inject snippet data."""
    template_path = Path(__file__).parent / "interactive.html"
    html = template_path.read_text()
    html = html.replace("{{SNIPPETS_JSON}}", json.dumps(FIXED_SNIPPETS))
    return html


def _cleanup_jobs():
    """Remove completed jobs older than _JOB_MAX_AGE."""
    now = time.monotonic()
    with _jobs_lock:
        expired = [
            jid for jid, job in _jobs.items()
            if job["status"] == "done" and (now - job.get("created_at", 0)) > _JOB_MAX_AGE
        ]
        for jid in expired:
            del _jobs[jid]




class SAGEHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)

        # Poll job status
        if parsed.path.startswith("/api/status/"):
            job_id = parsed.path.split("/")[-1]
            with _jobs_lock:
                job = _jobs.get(job_id)
            if not job:
                self._json_response(404, {"error": "job not found"})
            elif job["status"] == "running":
                self._json_response(200, {"status": "running", "job_id": job_id, "devin_mode": os.environ.get("DEVIN_MODE", "stub")})
            else:
                self._json_response(200, job["result"])
            return

        # Existing GET handler
        return self._handle_get(parsed)

    def _handle_get(self, parsed):
        if parsed.path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(_load_html().encode())
        elif parsed.path.startswith("/artifacts/"):
            artifacts_root = Path("artifacts").resolve()
            requested = parsed.path.split("/artifacts/", 1)[1]
            file_path = (artifacts_root / requested).resolve()
            if not str(file_path).startswith(str(artifacts_root) + os.sep) and file_path != artifacts_root:
                self.send_response(403)
                self.end_headers()
            elif file_path.exists() and file_path.is_file():
                self.send_response(200)
                self.send_header("Content-Type", "text/html" if parsed.path.endswith(".html") else "application/json")
                self.end_headers()
                self.wfile.write(file_path.read_bytes())
            else:
                self.send_response(404)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path == "/api/remediate":
            _cleanup_jobs()

            content_length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(content_length)) if content_length else {}
            cwe = body.get("cwe", "")

            fixture = FIXTURES.get(cwe)
            if not fixture:
                self._json_response(400, {"error": f"Unknown CWE: {cwe}"})
                return

            # Restore app.py before each run
            APP_PATH.write_text(APP_ORIGINAL)

            # Start remediation in background thread, return job ID
            job_id = uuid.uuid4().hex[:8]
            with _jobs_lock:
                _jobs[job_id] = {"status": "running", "result": None, "created_at": time.monotonic()}

            thread = threading.Thread(
                target=self._run_remediation,
                args=(job_id, cwe, fixture),
                daemon=True,
            )
            thread.start()

            self._json_response(200, {"status": "running", "job_id": job_id, "devin_mode": os.environ.get("DEVIN_MODE", "stub")})

        elif parsed.path == "/api/reset":
            APP_PATH.write_text(APP_ORIGINAL)
            # Clear database
            db_path = Path("pipeline.db")
            if db_path.exists():
                db_path.unlink()
            self._json_response(200, {"status": "reset"})

        else:
            self._json_response(404, {"error": "not found"})

    @staticmethod
    def _run_remediation(job_id: str, cwe: str, fixture: str):
        """Run the pipeline in a background thread."""
        from sage.pipeline.store import init_db
        from sage.cli.demo import process_alert

        _thread_local.capture_buffer = io.StringIO()

        try:
            db_conn = init_db()
            report = process_alert(fixture, "demo", db_conn=db_conn)
            db_conn.close()
        except Exception as e:
            report = {"disposition": "ERROR", "error": str(e)}
        finally:
            captured_output = _thread_local.capture_buffer.getvalue()
            _thread_local.capture_buffer = None

        # Load artifacts
        notif = {}
        notif_path = Path("artifacts/notification_payload.json")
        if notif_path.exists():
            try:
                notif = json.loads(notif_path.read_text())
            except Exception:
                pass

        pr_payload = {}
        pr_path = Path("artifacts/pr_payload.json")
        if pr_path.exists():
            try:
                pr_payload = json.loads(pr_path.read_text())
            except Exception:
                pass

        routing = ROUTING_INFO.get(cwe, {})
        devin_mode = os.environ.get("DEVIN_MODE", "stub")

        devin_session = {
            "mode": devin_mode,
            "session_id": report.get("devin_session_id", ""),
            "plan": report.get("remediation_plan"),
            "insights": report.get("devin_insights"),
            "pr_url": report.get("pr_url", ""),
        }

        result = {
            "status": "done",
            "cwe": cwe,
            "disposition": report.get("disposition", "ERROR"),
            "output": captured_output,
            "routing": routing,
            "notification": notif,
            "devin": devin_session,
            "pr": {
                "title": pr_payload.get("title", ""),
                "branch": pr_payload.get("branch", ""),
                "reviewers": pr_payload.get("reviewers", []),
                "labels": pr_payload.get("labels", []),
                "url": pr_payload.get("url", ""),
            },
        }

        with _jobs_lock:
            _jobs[job_id] = {"status": "done", "result": result}

    def _json_response(self, code, data):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def log_message(self, format, *args):
        # Suppress request logs to keep terminal clean
        pass


def _self_test():
    """Run a quick CWE-89 remediation to verify the system works."""
    from sage.pipeline.store import init_db
    from sage.cli.demo import process_alert

    APP_PATH.write_text(APP_ORIGINAL)
    db_path = Path("pipeline.db")
    if db_path.exists():
        db_path.unlink()

    _thread_local.capture_buffer = io.StringIO()
    try:
        db_conn = init_db()
        report = process_alert("demo/fixtures/sample_alert.json", "demo", db_conn=db_conn, quiet=True)
        db_conn.close()
    finally:
        _thread_local.capture_buffer = None

    APP_PATH.write_text(APP_ORIGINAL)
    db_path = Path("pipeline.db")
    if db_path.exists():
        db_path.unlink()
    # Clean artifacts from self-test
    for f in Path("artifacts").glob("*"):
        f.unlink()

    if report.get("disposition") == "PR_READY":
        return True, "CWE-89 → PR_READY"
    else:
        return False, f"CWE-89 → {report.get('disposition', 'ERROR')}: {report.get('error', '')}"


def main():
    # PORT env var for cloud platforms (Railway, Render, etc.)
    port = int(os.environ.get("PORT", sys.argv[1] if len(sys.argv) > 1 else 8000))

    # Install thread-safe stdout capture (must happen before any threads or self-test)
    sys.stdout = _ThreadCapturingStdout(sys.stdout)

    # Self-test before serving
    print("\n  SAGE Interactive Demo")
    print("  Running self-test...", end=" ", flush=True)
    ok, detail = _self_test()
    if ok:
        print(f"OK ({detail})")
    else:
        print(f"FAILED ({detail})")
        print("  The demo may not work correctly. Check demo/app.py")

    devin_mode = os.environ.get("DEVIN_MODE", "stub")
    print(f"  Devin mode: {devin_mode}")
    print(f"  Open http://localhost:{port}\n", flush=True)

    server = http.server.ThreadingHTTPServer(("", port), SAGEHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
        server.server_close()


if __name__ == "__main__":
    main()
