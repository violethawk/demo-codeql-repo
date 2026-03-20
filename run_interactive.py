#!/usr/bin/env python3
"""SAGE Interactive Demo: browser-based live remediation.

    python run_interactive.py
    # Open http://localhost:8000

Click a vulnerability. Watch SAGE process it. See the code transform.
"""

import http.server
import json
import io
import os
import sys
import threading
from pathlib import Path
from urllib.parse import urlparse, parse_qs

# Store original app.py content for reset
APP_PATH = Path("target_repo/app.py")
APP_ORIGINAL = APP_PATH.read_text() if APP_PATH.exists() else ""

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
        "before": '''    user_input = request.args.get("query", "")
    return f"<h1>Results for {user_input}</h1>"''',
        "after": '''    user_input = request.args.get("query", "")
    return f"<h1>Results for {html.escape(user_input)}</h1>"''',
    },
    "CWE-78": {
        "before": '''    host = request.args.get("host", "127.0.0.1")
    os.system("ping -c 1 " + host)''',
        "after": '''    host = request.args.get("host", "127.0.0.1")
    subprocess.run(["ping", "-c", "1", host], capture_output=True)''',
    },
}

FIXTURES = {
    "CWE-89": "fixtures/sample_alert.json",
    "CWE-79": "fixtures/sample_alert_xss.json",
    "CWE-78": "fixtures/sample_alert_cmdi.json",
}

HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SAGE Interactive Demo</title>
  <style>
    :root {
      --bg: #0f172a; --surface: #1e293b; --surface2: #334155;
      --border: #475569; --text: #e2e8f0; --muted: #94a3b8;
      --green: #22c55e; --red: #ef4444; --amber: #f59e0b;
      --cyan: #06b6d4; --blue: #3b82f6; --purple: #8b5cf6;
    }
    * { margin:0; padding:0; box-sizing:border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
           background: var(--bg); color: var(--text); min-height: 100vh; }

    .container { max-width: 1100px; margin: 0 auto; padding: 2rem; }

    /* Header */
    .header { margin-bottom: 2rem; }
    .header h1 { font-size: 1.5rem; font-weight: 800; }
    .header h1 span { color: var(--cyan); }
    .header .sub { color: var(--muted); font-size: 0.85rem; margin-top: 0.3rem; }

    /* Vulnerability cards */
    .vuln-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin-bottom: 1.5rem; }
    .vuln-card { background: var(--surface); border: 2px solid var(--border); border-radius: 10px;
                 padding: 1.25rem; cursor: pointer; transition: all 0.2s; position: relative; }
    .vuln-card:hover { border-color: var(--cyan); transform: translateY(-2px); }
    .vuln-card.active { border-color: var(--cyan); box-shadow: 0 0 20px rgba(6,182,212,0.15); }
    .vuln-card.done { border-color: var(--green); }
    .vuln-card.processing { border-color: var(--amber); }

    .vuln-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; }
    .vuln-cwe { font-weight: 800; font-size: 0.9rem; }
    .vuln-badge { font-size: 0.65rem; padding: 0.15rem 0.5rem; border-radius: 3px;
                  font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; }
    .badge-vuln { background: rgba(239,68,68,0.15); color: var(--red); }
    .badge-fixed { background: rgba(34,197,94,0.15); color: var(--green); }
    .badge-processing { background: rgba(245,158,11,0.15); color: var(--amber); }

    .vuln-name { font-size: 0.8rem; color: var(--muted); margin-bottom: 0.75rem; }

    .code-block { background: var(--bg); border-radius: 6px; padding: 0.75rem;
                  font-family: "SF Mono", "Fira Code", "Consolas", monospace;
                  font-size: 0.75rem; line-height: 1.6; overflow-x: auto;
                  white-space: pre; transition: all 0.5s; }
    .code-vuln { border-left: 3px solid var(--red); }
    .code-fixed { border-left: 3px solid var(--green); }

    .vuln-action { font-size: 0.75rem; color: var(--muted); margin-top: 0.6rem;
                   font-style: italic; }

    /* Terminal */
    .terminal-wrapper { background: var(--surface); border: 1px solid var(--border);
                        border-radius: 10px; overflow: hidden; }
    .terminal-bar { background: var(--surface2); padding: 0.5rem 1rem; display: flex;
                    align-items: center; gap: 0.5rem; }
    .terminal-dot { width: 10px; height: 10px; border-radius: 50%; }
    .terminal-title { font-size: 0.75rem; color: var(--muted); margin-left: 0.5rem; }
    .terminal { background: #0c0c0c; padding: 1rem; font-family: "SF Mono", "Fira Code", monospace;
                font-size: 0.78rem; line-height: 1.7; height: 420px; overflow-y: auto;
                color: var(--text); }
    .terminal .line { opacity: 0; animation: fadeIn 0.15s forwards; }
    .terminal .line-header { color: var(--cyan); font-weight: 700; }
    .terminal .line-success { color: var(--green); }
    .terminal .line-warn { color: var(--amber); }
    .terminal .line-info { color: var(--muted); }
    .terminal .line-result { color: #fff; font-weight: 700; }

    @keyframes fadeIn { to { opacity: 1; } }
    @keyframes pulse { 0%,100% { opacity:1; } 50% { opacity:0.5; } }
    .processing-indicator { animation: pulse 1s ease-in-out infinite; color: var(--amber); }

    /* Reset button */
    .reset-bar { display: flex; justify-content: space-between; align-items: center;
                 margin-top: 1rem; }
    .reset-btn { background: var(--surface2); border: 1px solid var(--border); color: var(--muted);
                 padding: 0.4rem 1rem; border-radius: 5px; cursor: pointer; font-size: 0.8rem;
                 transition: all 0.15s; }
    .reset-btn:hover { background: var(--cyan); color: var(--bg); border-color: var(--cyan); }
    .status-text { font-size: 0.8rem; color: var(--muted); }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1><span>SAGE</span> Interactive Demo</h1>
      <div class="sub">Click a vulnerability. Watch the system remediate it.</div>
    </div>

    <div class="vuln-grid">
      <div class="vuln-card" id="card-CWE-89" onclick="remediate('CWE-89')">
        <div class="vuln-header">
          <span class="vuln-cwe">CWE-89</span>
          <span class="vuln-badge badge-vuln" id="badge-CWE-89">VULNERABLE</span>
        </div>
        <div class="vuln-name">SQL Injection</div>
        <div class="code-block code-vuln" id="code-CWE-89">""" + FIXED_SNIPPETS["CWE-89"]["before"] + """</div>
        <div class="vuln-action">Policy: AUTO_REMEDIATE</div>
      </div>

      <div class="vuln-card" id="card-CWE-79" onclick="remediate('CWE-79')">
        <div class="vuln-header">
          <span class="vuln-cwe">CWE-79</span>
          <span class="vuln-badge badge-vuln" id="badge-CWE-79">VULNERABLE</span>
        </div>
        <div class="vuln-name">Cross-Site Scripting</div>
        <div class="code-block code-vuln" id="code-CWE-79">""" + FIXED_SNIPPETS["CWE-79"]["before"] + """</div>
        <div class="vuln-action">Policy: REMEDIATE_WITH_REVIEW</div>
      </div>

      <div class="vuln-card" id="card-CWE-78" onclick="remediate('CWE-78')">
        <div class="vuln-header">
          <span class="vuln-cwe">CWE-78</span>
          <span class="vuln-badge badge-vuln" id="badge-CWE-78">VULNERABLE</span>
        </div>
        <div class="vuln-name">Command Injection</div>
        <div class="code-block code-vuln" id="code-CWE-78">""" + FIXED_SNIPPETS["CWE-78"]["before"] + """</div>
        <div class="vuln-action">Policy: REMEDIATE_WITH_REVIEW</div>
      </div>
    </div>

    <div class="terminal-wrapper">
      <div class="terminal-bar">
        <div class="terminal-dot" style="background:#ef4444"></div>
        <div class="terminal-dot" style="background:#f59e0b"></div>
        <div class="terminal-dot" style="background:#22c55e"></div>
        <span class="terminal-title">SAGE Pipeline Output</span>
      </div>
      <div class="terminal" id="terminal">
        <div class="line line-info">Click a vulnerability card above to begin.</div>
      </div>
    </div>

    <div class="reset-bar">
      <button class="reset-btn" onclick="resetAll()">Reset All</button>
      <span class="status-text" id="status">Ready</span>
    </div>
  </div>

  <script>
    let processing = false;

    const fixedCode = """ + json.dumps(FIXED_SNIPPETS) + """;

    function addLine(text, cls = '') {
      const terminal = document.getElementById('terminal');
      const line = document.createElement('div');
      line.className = 'line ' + cls;
      line.textContent = text;
      terminal.appendChild(line);
      terminal.scrollTop = terminal.scrollHeight;
    }

    function clearTerminal() {
      document.getElementById('terminal').innerHTML = '';
    }

    async function remediate(cwe) {
      if (processing) return;
      processing = true;

      const card = document.getElementById('card-' + cwe);
      const badge = document.getElementById('badge-' + cwe);
      const code = document.getElementById('code-' + cwe);
      const status = document.getElementById('status');

      // Mark processing
      card.className = 'vuln-card processing';
      badge.className = 'vuln-badge badge-processing';
      badge.textContent = 'PROCESSING';
      status.textContent = 'Processing ' + cwe + '...';
      status.className = 'status-text processing-indicator';

      clearTerminal();
      addLine('$ sage remediate ' + cwe, 'line-info');
      addLine('');

      try {
        const resp = await fetch('/api/remediate', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({cwe: cwe}),
        });
        const data = await resp.json();

        // Stream output with delay for visual effect
        const lines = data.output.split('\\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          let cls = 'line-info';
          if (line.includes('[') && line.includes('/9]')) cls = 'line-header';
          else if (line.includes('PR_READY') || line.includes('COMPLETE') || line.includes('pass')) cls = 'line-success';
          else if (line.includes('REVIEW') || line.includes('REQUIRED')) cls = 'line-warn';
          else if (line.includes('SUMMARY') || line.includes('===')) cls = 'line-result';

          addLine(line, cls);
          await new Promise(r => setTimeout(r, 30));
        }

        // Update card
        if (data.disposition === 'PR_READY') {
          card.className = 'vuln-card done';
          badge.className = 'vuln-badge badge-fixed';
          badge.textContent = 'FIXED';
          code.textContent = fixedCode[cwe].after;
          code.className = 'code-block code-fixed';
          status.textContent = cwe + ' remediated successfully';
          status.className = 'status-text';
        } else {
          card.className = 'vuln-card';
          badge.className = 'vuln-badge badge-vuln';
          badge.textContent = 'ESCALATED';
          status.textContent = cwe + ' escalated for review';
          status.className = 'status-text';
        }
      } catch (e) {
        addLine('Error: ' + e.message, 'line-warn');
        card.className = 'vuln-card';
        status.textContent = 'Error';
        status.className = 'status-text';
      }

      processing = false;
    }

    async function resetAll() {
      clearTerminal();
      addLine('Resetting...', 'line-info');

      await fetch('/api/reset', {method: 'POST'});

      ['CWE-89', 'CWE-79', 'CWE-78'].forEach(cwe => {
        const card = document.getElementById('card-' + cwe);
        const badge = document.getElementById('badge-' + cwe);
        const code = document.getElementById('code-' + cwe);
        card.className = 'vuln-card';
        badge.className = 'vuln-badge badge-vuln';
        badge.textContent = 'VULNERABLE';
        code.textContent = fixedCode[cwe].before;
        code.className = 'code-block code-vuln';
      });

      document.getElementById('status').textContent = 'Ready';
      addLine('All findings reset to vulnerable state.', 'line-info');
      addLine('Click a card to begin.', 'line-info');
    }
  </script>
</body>
</html>
"""


class SAGEHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(HTML.encode())
        elif self.path.startswith("/artifacts/"):
            # Serve artifact files
            file_path = Path("." + self.path)
            if file_path.exists():
                self.send_response(200)
                self.send_header("Content-Type", "text/html" if self.path.endswith(".html") else "application/json")
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
            content_length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(content_length)) if content_length else {}
            cwe = body.get("cwe", "")

            fixture = FIXTURES.get(cwe)
            if not fixture:
                self._json_response(400, {"error": f"Unknown CWE: {cwe}"})
                return

            # Restore app.py before each run
            APP_PATH.write_text(APP_ORIGINAL)

            # Capture pipeline output
            from pipeline.store import init_db
            from run_demo import process_alert

            old_stdout = sys.stdout
            sys.stdout = captured = io.StringIO()

            try:
                db_conn = init_db()
                report = process_alert(fixture, "target_repo", db_conn=db_conn)
                db_conn.close()
            except Exception as e:
                report = {"disposition": "ERROR", "error": str(e)}
            finally:
                sys.stdout = old_stdout

            self._json_response(200, {
                "cwe": cwe,
                "disposition": report.get("disposition", "ERROR"),
                "output": captured.getvalue(),
            })

        elif parsed.path == "/api/reset":
            APP_PATH.write_text(APP_ORIGINAL)
            # Clear database
            db_path = Path("pipeline.db")
            if db_path.exists():
                db_path.unlink()
            self._json_response(200, {"status": "reset"})

        else:
            self._json_response(404, {"error": "not found"})

    def _json_response(self, code, data):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def log_message(self, format, *args):
        # Suppress request logs to keep terminal clean
        pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    server = http.server.HTTPServer(("", port), SAGEHandler)
    print(f"\n  SAGE Interactive Demo")
    print(f"  Open http://localhost:{port}\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
        server.server_close()


if __name__ == "__main__":
    main()
