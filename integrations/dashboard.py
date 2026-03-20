"""Dashboard Generator: Produce a simple HTML status page from artifacts.

Reads the remediation report JSON and renders a single-page HTML dashboard
so reviewers can see the state of the remediation loop without reading
raw JSON files.

Usage:
    from integrations.dashboard import generate_dashboard
    generate_dashboard()  # reads artifacts/, writes artifacts/dashboard.html
"""

import json
from pathlib import Path

ARTIFACTS_DIR = "artifacts"
OUTPUT_FILE = "artifacts/dashboard.html"


def _load_json(path: str) -> dict | None:
    """Load a JSON file, returning None if it does not exist."""
    p = Path(path)
    if not p.exists():
        return None
    return json.loads(p.read_text())


def _status_color(disposition: str) -> str:
    if disposition == "PR_READY":
        return "#22c55e"  # green
    if disposition == "NEEDS_HUMAN_REVIEW":
        return "#f59e0b"  # amber
    return "#6b7280"  # gray


def generate_dashboard(
    output_path: str = OUTPUT_FILE,
) -> str:
    """Generate an HTML dashboard from artifact JSON files.

    Returns the path to the generated HTML file.
    """
    report = _load_json(f"{ARTIFACTS_DIR}/remediation_report.json")
    pr_payload = _load_json(f"{ARTIFACTS_DIR}/pr_payload.json")
    notification = _load_json(f"{ARTIFACTS_DIR}/notification_payload.json")

    if report is None:
        report = {"alert_id": "N/A", "disposition": "UNKNOWN"}

    disposition = report.get("disposition", "UNKNOWN")
    color = _status_color(disposition)

    pr_url = report.get("pr_url", "")
    pr_link = f'<a href="{pr_url}">{pr_url}</a>' if pr_url else "N/A"

    notif_sent = report.get("notification_sent", False)
    notif_status = "Sent" if notif_sent else "Not sent"

    integration_mode = report.get("integration_mode", "unknown")

    validation_rows = ""
    for step in report.get("validation", []):
        result = step.get("result", "")
        badge = "PASS" if result == "pass" else "FAIL"
        badge_color = "#22c55e" if result == "pass" else "#ef4444"
        validation_rows += (
            f"<tr>"
            f"<td><code>{step.get('command', '')}</code></td>"
            f'<td><span style="color:{badge_color};font-weight:bold">'
            f"{badge}</span></td>"
            f"</tr>\n"
        )

    pr_section = ""
    if pr_payload:
        pr_section = f"""
    <div class="card">
      <h2>PR Payload</h2>
      <table>
        <tr><td><strong>Title</strong></td><td>{pr_payload.get('title', '')}</td></tr>
        <tr><td><strong>Branch</strong></td><td><code>{pr_payload.get('branch', '')}</code></td></tr>
        <tr><td><strong>Repo</strong></td><td>{pr_payload.get('repo', '')}</td></tr>
        <tr><td><strong>Status</strong></td><td>{pr_payload.get('status', '')}</td></tr>
      </table>
    </div>"""

    notif_section = ""
    if notification:
        notif_section = f"""
    <div class="card">
      <h2>Notification</h2>
      <table>
        <tr><td><strong>Channel</strong></td><td>#{notification.get('channel', '')}</td></tr>
        <tr><td><strong>Owner Team</strong></td><td>{notification.get('owner_team', '')}</td></tr>
        <tr><td><strong>Status</strong></td><td>{notification.get('status', '')}</td></tr>
        <tr><td><strong>Message</strong></td><td>{notification.get('message', '')}</td></tr>
      </table>
    </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>CodeQL Remediation Dashboard</title>
  <style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
           background: #f8fafc; color: #1e293b; padding: 2rem; max-width: 800px; margin: auto; }}
    h1 {{ font-size: 1.5rem; margin-bottom: 1.5rem; }}
    .card {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 8px;
             padding: 1.25rem; margin-bottom: 1rem; }}
    .card h2 {{ font-size: 1rem; margin-bottom: 0.75rem; color: #475569; }}
    table {{ width: 100%; border-collapse: collapse; }}
    td {{ padding: 0.35rem 0.5rem; border-bottom: 1px solid #f1f5f9; vertical-align: top; }}
    td:first-child {{ width: 160px; font-weight: 600; color: #64748b; }}
    code {{ background: #f1f5f9; padding: 0.15rem 0.4rem; border-radius: 3px; font-size: 0.85rem; }}
    a {{ color: #2563eb; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px;
              color: #fff; font-weight: 700; font-size: 0.85rem; }}
    .footer {{ margin-top: 2rem; font-size: 0.8rem; color: #94a3b8; text-align: center; }}
  </style>
</head>
<body>
  <h1>CodeQL Remediation Dashboard</h1>

  <div class="card">
    <h2>Alert Summary</h2>
    <table>
      <tr><td><strong>Alert ID</strong></td><td>{report.get('alert_id', '')}</td></tr>
      <tr><td><strong>Disposition</strong></td>
          <td><span class="badge" style="background:{color}">{disposition}</span></td></tr>
      <tr><td><strong>Confidence</strong></td><td>{report.get('confidence', '')}</td></tr>
      <tr><td><strong>Decision Trace</strong></td><td>{report.get('decision_trace', '')}</td></tr>
      <tr><td><strong>Integration Mode</strong></td><td>{integration_mode}</td></tr>
    </table>
  </div>

  <div class="card">
    <h2>Remediation</h2>
    <table>
      <tr><td><strong>Summary</strong></td><td>{report.get('summary', '')}</td></tr>
      <tr><td><strong>Root Cause</strong></td><td>{report.get('root_cause', '')}</td></tr>
      <tr><td><strong>Fix</strong></td><td>{report.get('fix', '')}</td></tr>
      <tr><td><strong>Why It Works</strong></td><td>{report.get('why_fix_works', '')}</td></tr>
      <tr><td><strong>Scope</strong></td><td>{report.get('scope', '')}</td></tr>
      <tr><td><strong>Residual Risk</strong></td><td>{report.get('residual_risk', '')}</td></tr>
    </table>
  </div>

  <div class="card">
    <h2>Validation</h2>
    <table>
      <tr><th style="text-align:left;color:#64748b">Command</th>
          <th style="text-align:left;color:#64748b">Result</th></tr>
      {validation_rows if validation_rows else '<tr><td colspan="2">No validation steps recorded</td></tr>'}
    </table>
  </div>

  <div class="card">
    <h2>Delivery</h2>
    <table>
      <tr><td><strong>PR URL</strong></td><td>{pr_link}</td></tr>
      <tr><td><strong>Notification</strong></td><td>{notif_status}</td></tr>
      <tr><td><strong>Files Changed</strong></td>
          <td>{', '.join(report.get('files_changed', [])) or 'None'}</td></tr>
      <tr><td><strong>Timestamp</strong></td><td>{report.get('timestamp', '')}</td></tr>
    </table>
  </div>
{pr_section}
{notif_section}

  <div class="footer">
    Generated from <code>artifacts/</code> &mdash; CodeQL Remediation Pipeline
  </div>
</body>
</html>
"""

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(html)
    return output_path
