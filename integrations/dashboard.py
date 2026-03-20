"""Dashboard Generator: Produce HTML status pages from pipeline data.

Two dashboard modes:
    generate_dashboard()           -- single-alert view from artifact JSON
    generate_aggregate_dashboard() -- multi-alert view from SQLite database

Usage:
    from integrations.dashboard import generate_dashboard, generate_aggregate_dashboard
    generate_dashboard()
    generate_aggregate_dashboard(db_conn)
"""

import json
from pathlib import Path

ARTIFACTS_DIR = "artifacts"
OUTPUT_FILE = "artifacts/dashboard.html"
AGGREGATE_FILE = "artifacts/dashboard_all.html"


def _load_json(path: str) -> dict | None:
    p = Path(path)
    if not p.exists():
        return None
    return json.loads(p.read_text())


def _status_color(disposition: str) -> str:
    if disposition == "PR_READY":
        return "#22c55e"
    if disposition == "NEEDS_HUMAN_REVIEW":
        return "#f59e0b"
    return "#6b7280"


def _confidence_color(confidence: str) -> str:
    if confidence == "HIGH":
        return "#22c55e"
    if confidence == "MEDIUM":
        return "#f59e0b"
    return "#ef4444"


# ---------------------------------------------------------------------------
# Single-alert dashboard (original)
# ---------------------------------------------------------------------------


def generate_dashboard(output_path: str = OUTPUT_FILE) -> str:
    """Generate an HTML dashboard from artifact JSON files."""
    report = _load_json(f"{ARTIFACTS_DIR}/remediation_report.json")
    pr_payload = _load_json(f"{ARTIFACTS_DIR}/pr_payload.json")
    notification = _load_json(f"{ARTIFACTS_DIR}/notification_payload.json")

    if report is None:
        report = {"alert_id": "N/A", "disposition": "UNKNOWN"}

    disposition = report.get("disposition", "UNKNOWN")
    disp_color = _status_color(disposition)
    confidence = report.get("confidence", "")
    conf_color = _confidence_color(confidence)
    final_status = "COMPLETE" if disposition == "PR_READY" else "ESCALATED"
    final_color = "#22c55e" if disposition == "PR_READY" else "#f59e0b"

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
      <h2>Notification Detail</h2>
      <table>
        <tr><td><strong>Channel</strong></td><td>{notification.get('channel', '')}</td></tr>
        <tr><td><strong>Owner Team</strong></td><td>{notification.get('owner_team', '')}</td></tr>
        <tr><td><strong>Status</strong></td><td>{notification.get('status', '')}</td></tr>
        <tr><td><strong>Message</strong></td><td>{notification.get('message', '')}</td></tr>
      </table>
    </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SAGE Dashboard</title>
  <style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
           background: #f8fafc; color: #1e293b; padding: 2rem; max-width: 860px; margin: auto; }}
    h1 {{ font-size: 1.6rem; margin-bottom: 0.25rem; }}
    .subtitle {{ color: #64748b; font-size: 0.9rem; margin-bottom: 1.5rem; }}
    .hero {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 10px;
             padding: 1.5rem; margin-bottom: 1.25rem;
             display: flex; justify-content: space-between; align-items: center;
             flex-wrap: wrap; gap: 1rem; }}
    .hero-left {{ flex: 1; min-width: 200px; }}
    .hero-id {{ font-size: 1.1rem; font-weight: 700; }}
    .hero-rule {{ color: #475569; font-size: 0.9rem; margin-top: 0.15rem; }}
    .hero-right {{ display: flex; gap: 0.75rem; flex-wrap: wrap; }}
    .hero-badge {{ text-align: center; padding: 0.5rem 1rem; border-radius: 6px;
                   color: #fff; font-weight: 700; font-size: 0.85rem;
                   min-width: 100px; }}
    .card {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 8px;
             padding: 1.25rem; margin-bottom: 1rem; }}
    .card h2 {{ font-size: 1rem; margin-bottom: 0.75rem; color: #475569;
                border-bottom: 1px solid #f1f5f9; padding-bottom: 0.4rem; }}
    table {{ width: 100%; border-collapse: collapse; }}
    td, th {{ padding: 0.4rem 0.5rem; border-bottom: 1px solid #f1f5f9;
              vertical-align: top; text-align: left; }}
    td:first-child {{ width: 170px; font-weight: 600; color: #64748b; }}
    code {{ background: #f1f5f9; padding: 0.15rem 0.4rem; border-radius: 3px;
            font-size: 0.85rem; }}
    a {{ color: #2563eb; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px;
              color: #fff; font-weight: 700; font-size: 0.85rem; }}
    .mode-tag {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 3px;
                 background: #e2e8f0; color: #475569; font-size: 0.8rem;
                 font-weight: 600; }}
    .footer {{ margin-top: 2rem; font-size: 0.8rem; color: #94a3b8;
               text-align: center; }}
  </style>
</head>
<body>
  <h1>SAGE Dashboard</h1>
  <div class="subtitle">Security Automation &amp; Governance Engine</div>

  <div class="hero">
    <div class="hero-left">
      <div class="hero-id">{report.get('alert_id', '')}</div>
      <div class="hero-rule">{report.get('rule_name', '')} &mdash; <code>{report.get('cwe', '')}</code></div>
    </div>
    <div class="hero-right">
      <div class="hero-badge" style="background:{disp_color}">{disposition}</div>
      <div class="hero-badge" style="background:{conf_color}">{confidence}</div>
      <div class="hero-badge" style="background:{final_color}">{final_status}</div>
    </div>
  </div>

  <div class="card">
    <h2>Alert</h2>
    <table>
      <tr><td><strong>Alert ID</strong></td><td>{report.get('alert_id', '')}</td></tr>
      <tr><td><strong>Rule</strong></td><td>{report.get('rule_name', '')}</td></tr>
      <tr><td><strong>CWE</strong></td><td>{report.get('cwe', '')}</td></tr>
      <tr><td><strong>Decision Trace</strong></td><td>{report.get('decision_trace', '')}</td></tr>
      <tr><td><strong>Integration Mode</strong></td>
          <td><span class="mode-tag">{integration_mode}</span></td></tr>
      <tr><td><strong>Timestamp</strong></td><td>{report.get('timestamp', '')}</td></tr>
    </table>
  </div>

  <div class="card">
    <h2>Remediation</h2>
    <table>
      <tr><td><strong>Summary</strong></td><td>{report.get('summary', 'N/A')}</td></tr>
      <tr><td><strong>Root Cause</strong></td><td>{report.get('root_cause', '') or 'N/A'}</td></tr>
      <tr><td><strong>Fix</strong></td><td>{report.get('fix', '') or 'N/A'}</td></tr>
      <tr><td><strong>Why It Works</strong></td><td>{report.get('why_fix_works', '') or 'N/A'}</td></tr>
      <tr><td><strong>Scope</strong></td><td>{report.get('scope', '') or 'N/A'}</td></tr>
      <tr><td><strong>Residual Risk</strong></td><td>{report.get('residual_risk', '') or 'N/A'}</td></tr>
    </table>
  </div>

  <div class="card">
    <h2>Validation</h2>
    <table>
      <tr><th>Command</th><th>Result</th></tr>
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
    </table>
  </div>
{pr_section}
{notif_section}

  <div class="footer">
    Generated by SAGE &mdash; Security Automation &amp; Governance Engine
  </div>
</body>
</html>
"""

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(html)
    return output_path


# ---------------------------------------------------------------------------
# Aggregate dashboard (multi-alert, from SQLite)
# ---------------------------------------------------------------------------


def generate_aggregate_dashboard(
    db_conn,
    output_path: str = AGGREGATE_FILE,
) -> str:
    """Generate an aggregate HTML dashboard from the alert tracking database.

    Shows remediation rate, breakdowns by CWE/team/disposition, and a
    full alert table — the view an auditor or security lead needs.
    """
    from pipeline.store import get_metrics, list_alerts

    metrics = get_metrics(db_conn)
    alerts = list_alerts(db_conn)

    total = metrics["total"]
    rate = metrics["remediation_rate"]
    by_disp = metrics["by_disposition"]
    by_cwe = metrics["by_cwe"]
    by_team = metrics["by_team"]

    pr_ready = by_disp.get("PR_READY", 0)
    needs_review = by_disp.get("NEEDS_HUMAN_REVIEW", 0)
    rate_pct = int(rate * 100)

    # Progress bar color
    if rate_pct >= 80:
        bar_color = "#22c55e"
    elif rate_pct >= 50:
        bar_color = "#f59e0b"
    else:
        bar_color = "#ef4444"

    # CWE breakdown rows
    cwe_rows = ""
    for cwe, count in sorted(by_cwe.items()):
        pct = int(count / total * 100) if total else 0
        cwe_rows += (
            f'<tr><td><code>{cwe}</code></td><td>{count}</td>'
            f'<td><div class="bar" style="width:{pct}%;background:#3b82f6">'
            f"</div></td></tr>\n"
        )

    # Team breakdown rows
    team_rows = ""
    for team, count in sorted(by_team.items()):
        pct = int(count / total * 100) if total else 0
        label = team or "(unassigned)"
        team_rows += (
            f"<tr><td>{label}</td><td>{count}</td>"
            f'<td><div class="bar" style="width:{pct}%;background:#8b5cf6">'
            f"</div></td></tr>\n"
        )

    # Alert table rows
    alert_rows = ""
    for a in alerts:
        disp = a["disposition"]
        disp_color = _status_color(disp)
        disp_label = "PR_READY" if disp == "PR_READY" else "REVIEW"
        pr_url = a.get("pr_url", "")
        pr_cell = f'<a href="{pr_url}">PR</a>' if pr_url else "&mdash;"
        ts = a["updated_at"][:16].replace("T", " ")
        alert_rows += (
            f"<tr>"
            f"<td><strong>{a['alert_id']}</strong></td>"
            f"<td><code>{a['cwe']}</code></td>"
            f"<td>{a.get('rule_name', '')}</td>"
            f"<td>{a.get('owner_team', '') or '&mdash;'}</td>"
            f'<td><span class="disp-badge" style="background:{disp_color}">'
            f"{disp_label}</span></td>"
            f"<td>{pr_cell}</td>"
            f"<td>{ts}</td>"
            f"</tr>\n"
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SAGE - Aggregate Dashboard</title>
  <style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
           background: #f8fafc; color: #1e293b; padding: 2rem; max-width: 1000px; margin: auto; }}
    h1 {{ font-size: 1.6rem; margin-bottom: 0.25rem; }}
    .subtitle {{ color: #64748b; font-size: 0.9rem; margin-bottom: 1.5rem; }}

    /* Metrics cards */
    .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                gap: 1rem; margin-bottom: 1.5rem; }}
    .metric-card {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 10px;
                    padding: 1.25rem; text-align: center; }}
    .metric-value {{ font-size: 2rem; font-weight: 800; }}
    .metric-label {{ font-size: 0.8rem; color: #64748b; margin-top: 0.25rem; }}

    /* Progress bar */
    .progress-outer {{ background: #e2e8f0; border-radius: 6px; height: 24px;
                       margin-top: 0.5rem; overflow: hidden; }}
    .progress-inner {{ height: 100%; border-radius: 6px; transition: width 0.5s;
                       display: flex; align-items: center; justify-content: center;
                       color: #fff; font-weight: 700; font-size: 0.8rem; }}

    /* Cards */
    .card {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 8px;
             padding: 1.25rem; margin-bottom: 1rem; }}
    .card h2 {{ font-size: 1rem; margin-bottom: 0.75rem; color: #475569;
                border-bottom: 1px solid #f1f5f9; padding-bottom: 0.4rem; }}
    .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem; }}

    /* Tables */
    table {{ width: 100%; border-collapse: collapse; }}
    td, th {{ padding: 0.4rem 0.5rem; border-bottom: 1px solid #f1f5f9;
              vertical-align: middle; text-align: left; font-size: 0.9rem; }}
    th {{ color: #64748b; font-weight: 600; font-size: 0.8rem; text-transform: uppercase;
          letter-spacing: 0.03em; }}
    code {{ background: #f1f5f9; padding: 0.15rem 0.4rem; border-radius: 3px;
            font-size: 0.85rem; }}
    a {{ color: #2563eb; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}

    /* Mini bar chart in tables */
    .bar {{ height: 14px; border-radius: 3px; min-width: 4px; }}

    /* Disposition badge */
    .disp-badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px;
                   color: #fff; font-weight: 700; font-size: 0.75rem; }}

    .footer {{ margin-top: 2rem; font-size: 0.8rem; color: #94a3b8; text-align: center; }}
  </style>
</head>
<body>
  <h1>SAGE Governance Dashboard</h1>
  <div class="subtitle">Security Automation &amp; Governance Engine &mdash; aggregate view</div>

  <!-- Top-level metrics -->
  <div class="metrics">
    <div class="metric-card">
      <div class="metric-value">{total}</div>
      <div class="metric-label">Total Alerts</div>
    </div>
    <div class="metric-card">
      <div class="metric-value" style="color:#22c55e">{pr_ready}</div>
      <div class="metric-label">Auto-Remediated</div>
    </div>
    <div class="metric-card">
      <div class="metric-value" style="color:#f59e0b">{needs_review}</div>
      <div class="metric-label">Needs Review</div>
    </div>
    <div class="metric-card">
      <div class="metric-value" style="color:{bar_color}">{rate_pct}%</div>
      <div class="metric-label">Remediation Rate</div>
      <div class="progress-outer">
        <div class="progress-inner" style="width:{rate_pct}%;background:{bar_color}">
          {rate_pct}%
        </div>
      </div>
    </div>
  </div>

  <!-- Breakdown cards -->
  <div class="grid-2">
    <div class="card">
      <h2>By CWE</h2>
      <table>
        <tr><th>CWE</th><th>#</th><th></th></tr>
        {cwe_rows if cwe_rows else '<tr><td colspan="3">No data</td></tr>'}
      </table>
    </div>
    <div class="card">
      <h2>By Team</h2>
      <table>
        <tr><th>Team</th><th>#</th><th></th></tr>
        {team_rows if team_rows else '<tr><td colspan="3">No data</td></tr>'}
      </table>
    </div>
  </div>

  <!-- Full alert table -->
  <div class="card">
    <h2>All Alerts</h2>
    <table>
      <tr>
        <th>Alert ID</th><th>CWE</th><th>Rule</th><th>Team</th>
        <th>Status</th><th>PR</th><th>Updated</th>
      </tr>
      {alert_rows if alert_rows else '<tr><td colspan="7">No alerts tracked yet</td></tr>'}
    </table>
  </div>

  <div class="footer">
    Generated by SAGE &mdash; Security Automation &amp; Governance Engine
  </div>
</body>
</html>
"""

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(html)
    return output_path
