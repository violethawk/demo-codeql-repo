"""Dashboard Generator: Produce HTML status pages from pipeline data.

Two dashboard modes:
    generate_dashboard()           -- single-alert view from artifact JSON
    generate_aggregate_dashboard() -- multi-alert view from SQLite database

Usage:
    from sage.integrations.dashboard import generate_dashboard, generate_aggregate_dashboard
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
    """Generate an aggregate HTML dashboard from the alert tracking database."""
    from sage.pipeline.store import get_metrics, get_kpis, list_alerts

    metrics = get_metrics(db_conn)
    kpis = get_kpis(db_conn)
    alerts = list_alerts(db_conn)

    total = metrics["total"]

    # Last activity timestamp
    last_event = db_conn.execute(
        "SELECT MAX(timestamp) FROM events",
    ).fetchone()[0] or ""
    last_event_display = last_event[:19].replace("T", " ") + " UTC" if last_event else "N/A"

    by_cwe = metrics["by_cwe"]
    by_team = metrics["by_team"]
    by_action = metrics["by_action"]
    by_lifecycle = metrics["by_lifecycle"]

    sla_pct = int(kpis["sla_compliance_rate"] * 100)
    auto_pct = int(kpis["auto_remediation_rate"] * 100)
    merge_pct = int(kpis["pr_merge_rate"] * 100)
    comp_pct = int(kpis["lifecycle_completion_rate"] * 100)
    mttr = kpis["mttr_hours"]
    mttr_str = f"{mttr * 60:.0f}m" if mttr < 1 else f"{mttr:.1f}h"
    ttfa = kpis["time_to_first_action_hours"]
    ttfa_str = f"{ttfa * 60:.0f}m" if ttfa < 1 else f"{ttfa:.1f}h"
    aging = kpis["aging_backlog"]
    unowned = kpis["unowned_findings"]
    breaches = kpis["sla_breach_count"]

    def _kpi_color(pct):
        if pct >= 80: return "#22c55e"
        if pct >= 50: return "#f59e0b"
        return "#ef4444"

    def _gov_color(val, target_zero=True):
        return "#22c55e" if val == 0 else "#ef4444"

    # Build breakdown bar rows
    def _bar_rows(data, color, max_val=None):
        if not data: return '<tr><td colspan="3" style="color:#64748b">No data</td></tr>'
        mv = max_val or max(data.values(), default=1)
        rows = ""
        for k, v in sorted(data.items()):
            label = k or "(unassigned)"
            pct = int(v / mv * 100) if mv else 0
            rows += (
                f'<tr><td>{label}</td><td style="font-weight:700">{v}</td>'
                f'<td><div class="bar" style="width:{pct}%;background:{color}"></div></td></tr>\n'
            )
        return rows

    # Alert table rows
    alert_rows = ""
    for a in alerts:
        state = a.get("lifecycle_state", "DETECTED")
        action = a.get("policy_action", "")
        pr_url = a.get("pr_url", "")
        pr_cell = f'<a href="{pr_url}" class="pr-link">View PR</a>' if pr_url else '<span style="color:#94a3b8">&mdash;</span>'
        ts = a["updated_at"][:16].replace("T", " ")

        state_colors = {
            "MERGED": "#22c55e", "CLOSED": "#64748b", "UNDER_REVIEW": "#3b82f6",
            "ESCALATED": "#ef4444", "DEFERRED": "#94a3b8", "DETECTED": "#f59e0b",
        }
        sc = state_colors.get(state, "#64748b")
        pulse = ' pulse' if state in ("UNDER_REVIEW", "ESCALATED") else ''

        alert_rows += (
            f'<tr class="alert-row" data-state="{state}" data-team="{a.get("owner_team","")}" data-cwe="{a["cwe"]}">'
            f'<td><strong>{a["alert_id"]}</strong></td>'
            f'<td><code>{a["cwe"]}</code></td>'
            f'<td class="rule-cell">{a.get("rule_name","")}</td>'
            f'<td>{a.get("owner_team","") or "&mdash;"}</td>'
            f'<td><span class="action-badge">{action}</span></td>'
            f'<td><span class="state-badge{pulse}" style="background:{sc}">{state}</span></td>'
            f'<td>{pr_cell}</td>'
            f'<td class="ts">{ts}</td>'
            f'</tr>\n'
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SAGE Governance Dashboard</title>
  <style>
    :root {{
      --bg: #0f172a; --surface: #1e293b; --surface2: #334155;
      --border: #475569; --text: #e2e8f0; --muted: #94a3b8;
      --green: #22c55e; --amber: #f59e0b; --red: #ef4444;
      --blue: #3b82f6; --purple: #8b5cf6; --cyan: #06b6d4;
    }}
    * {{ margin:0; padding:0; box-sizing:border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "SF Mono", monospace;
           background: var(--bg); color: var(--text); padding: 2rem; max-width: 1100px; margin: auto; }}

    /* Header */
    .header {{ margin-bottom: 2rem; }}
    .header h1 {{ font-size: 1.5rem; font-weight: 800; letter-spacing: -0.02em; }}
    .header h1 span {{ color: var(--cyan); }}
    .header .sub {{ color: var(--muted); font-size: 0.85rem; margin-top: 0.3rem; }}
    .header .pipeline {{ color: var(--muted); font-size: 0.75rem; margin-top: 0.75rem;
                         font-family: "SF Mono", "Fira Code", monospace; letter-spacing: 0.05em; }}
    .header .pipeline span {{ color: var(--cyan); }}

    /* KPI grid */
    .kpi-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.75rem; margin-bottom: 1.5rem; }}
    .kpi {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
            padding: 1.1rem; position: relative; overflow: hidden; }}
    .kpi-label {{ font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.08em;
                  color: var(--muted); margin-bottom: 0.4rem; }}
    .kpi-value {{ font-size: 1.8rem; font-weight: 800; line-height: 1; }}
    .kpi-detail {{ font-size: 0.75rem; color: var(--muted); margin-top: 0.3rem; }}
    .kpi-bar {{ height: 4px; border-radius: 2px; margin-top: 0.6rem; background: var(--surface2); overflow: hidden; }}
    .kpi-bar-fill {{ height: 100%; border-radius: 2px; transition: width 1s ease-out; }}
    .kpi-tag {{ position: absolute; top: 0.75rem; right: 0.75rem; font-size: 0.6rem;
                padding: 0.15rem 0.45rem; border-radius: 3px; font-weight: 700;
                text-transform: uppercase; letter-spacing: 0.05em; }}
    .tag-pass {{ background: rgba(34,197,94,0.15); color: var(--green); }}
    .tag-fail {{ background: rgba(239,68,68,0.15); color: var(--red); }}
    .tag-warn {{ background: rgba(245,158,11,0.15); color: var(--amber); }}

    /* Section */
    .section-title {{ font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.1em;
                      color: var(--muted); margin: 1.5rem 0 0.75rem; padding-bottom: 0.4rem;
                      border-bottom: 1px solid var(--surface2); }}

    /* Breakdown grid */
    .breakdown {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
                  gap: 0.75rem; margin-bottom: 1rem; }}
    .breakdown-card {{ background: var(--surface); border: 1px solid var(--border);
                       border-radius: 8px; padding: 1rem; }}
    .breakdown-card h3 {{ font-size: 0.8rem; color: var(--muted); margin-bottom: 0.6rem; }}
    .breakdown-card table {{ width: 100%; }}
    .breakdown-card td {{ padding: 0.3rem 0.4rem; border: none; font-size: 0.85rem; }}
    .breakdown-card td:nth-child(2) {{ width: 30px; text-align: right; font-weight: 700; }}
    .breakdown-card td:nth-child(3) {{ width: 50%; }}
    .bar {{ height: 10px; border-radius: 3px; min-width: 4px; transition: width 0.8s ease-out; }}

    /* Alert table */
    .alert-table {{ background: var(--surface); border: 1px solid var(--border);
                    border-radius: 8px; overflow: hidden; }}
    .alert-table table {{ width: 100%; border-collapse: collapse; }}
    .alert-table th {{ background: var(--surface2); padding: 0.6rem 0.75rem; font-size: 0.7rem;
                       text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted);
                       text-align: left; border-bottom: 1px solid var(--border); cursor: pointer;
                       user-select: none; }}
    .alert-table th:hover {{ color: var(--text); }}
    .alert-table td {{ padding: 0.6rem 0.75rem; border-bottom: 1px solid var(--surface2);
                       font-size: 0.85rem; }}
    .alert-table tr:last-child td {{ border-bottom: none; }}
    .alert-table code {{ background: var(--surface2); padding: 0.1rem 0.35rem; border-radius: 3px; }}

    .state-badge {{ display: inline-block; padding: 0.2rem 0.55rem; border-radius: 4px;
                    color: #fff; font-weight: 700; font-size: 0.7rem; letter-spacing: 0.03em; }}
    .action-badge {{ display: inline-block; padding: 0.15rem 0.45rem; border-radius: 3px;
                     background: var(--surface2); color: var(--muted); font-size: 0.7rem;
                     font-weight: 600; }}
    .pr-link {{ color: var(--cyan); font-weight: 600; }}
    .rule-cell {{ max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
    .ts {{ color: var(--muted); font-size: 0.8rem; }}

    /* Pulse animation for active states */
    @keyframes pulse {{ 0%,100% {{ opacity:1; }} 50% {{ opacity:0.7; }} }}
    .pulse {{ animation: pulse 2s ease-in-out infinite; }}

    /* Filter bar */
    .filters {{ display: flex; gap: 0.5rem; margin-bottom: 0.75rem; flex-wrap: wrap; }}
    .filter-btn {{ background: var(--surface); border: 1px solid var(--border); color: var(--muted);
                   padding: 0.3rem 0.7rem; border-radius: 4px; font-size: 0.75rem; cursor: pointer;
                   font-weight: 600; transition: all 0.15s; }}
    .filter-btn:hover, .filter-btn.active {{ background: var(--cyan); color: var(--bg); border-color: var(--cyan); }}

    .footer {{ margin-top: 2rem; font-size: 0.75rem; color: var(--muted); text-align: center;
               padding-top: 1rem; border-top: 1px solid var(--surface2); }}
  </style>
</head>
<body>

  <div class="header">
    <h1><span>SAGE</span> Governance Dashboard</h1>
    <div class="sub">Security Automation &amp; Governance Engine</div>
    <div class="pipeline">
      <span>Detection</span> &rarr; Decision &rarr; <span>Execution</span> &rarr; Review &rarr; <span>Enforcement</span> &rarr; Evidence
    </div>
  </div>

  <!-- KPIs: 3x3 grid -->
  <div class="section-title">Outcome Metrics</div>
  <div class="kpi-grid">
    <div class="kpi">
      <div class="kpi-label">SLA Compliance</div>
      <div class="kpi-value" style="color:{_kpi_color(sla_pct)}">{sla_pct}%</div>
      <div class="kpi-detail">{kpis['sla_compliant']}/{kpis['sla_total']} high-risk resolved within SLA</div>
      <div class="kpi-bar"><div class="kpi-bar-fill" style="width:{sla_pct}%;background:{_kpi_color(sla_pct)}"></div></div>
    </div>
    <div class="kpi">
      <div class="kpi-label">Mean Time to Remediation</div>
      <div class="kpi-value">{mttr_str}</div>
      <div class="kpi-detail">Average time from detection to resolution</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">Aging Backlog</div>
      <div class="kpi-value">{aging['within_sla'] + aging['at_risk'] + aging['breached']}</div>
      <div class="kpi-detail">
        <span style="color:var(--green)">{aging['within_sla']} ok</span> &middot;
        <span style="color:var(--amber)">{aging['at_risk']} at risk</span> &middot;
        <span style="color:var(--red)">{aging['breached']} breached</span>
      </div>
    </div>
  </div>

  <div class="section-title">System Effectiveness</div>
  <div class="kpi-grid">
    <div class="kpi">
      <div class="kpi-label">Auto-Remediation Rate</div>
      <div class="kpi-value" style="color:{_kpi_color(auto_pct)}">{auto_pct}%</div>
      <div class="kpi-detail">{kpis['auto_remediated']}/{total} resolved via automation</div>
      <div class="kpi-bar"><div class="kpi-bar-fill" style="width:{auto_pct}%;background:{_kpi_color(auto_pct)}"></div></div>
    </div>
    <div class="kpi">
      <div class="kpi-label">PR Merge Rate</div>
      <div class="kpi-value" style="color:{_kpi_color(merge_pct)}">{merge_pct}%</div>
      <div class="kpi-detail">{kpis['merged']}/{kpis['total_prs']} PRs merged (trust metric)</div>
      <div class="kpi-bar"><div class="kpi-bar-fill" style="width:{merge_pct}%;background:{_kpi_color(merge_pct)}"></div></div>
    </div>
    <div class="kpi">
      <div class="kpi-label">Time to First Action</div>
      <div class="kpi-value">{ttfa_str}</div>
      <div class="kpi-detail">Detection to PR or escalation</div>
    </div>
  </div>

  <div class="section-title">Governance</div>
  <div class="kpi-grid">
    <div class="kpi">
      <span class="kpi-tag {'tag-pass' if unowned == 0 else 'tag-fail'}">{'PASS' if unowned == 0 else 'FAIL'}</span>
      <div class="kpi-label">Unowned Findings</div>
      <div class="kpi-value" style="color:{_gov_color(unowned)}">{unowned}</div>
      <div class="kpi-detail">Target: 0</div>
    </div>
    <div class="kpi">
      <span class="kpi-tag {'tag-pass' if breaches == 0 else 'tag-fail'}">{'PASS' if breaches == 0 else 'FAIL'}</span>
      <div class="kpi-label">SLA Breaches</div>
      <div class="kpi-value" style="color:{_gov_color(breaches)}">{breaches}</div>
      <div class="kpi-detail">Active findings past deadline</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">Lifecycle Completion</div>
      <div class="kpi-value" style="color:{_kpi_color(comp_pct)}">{comp_pct}%</div>
      <div class="kpi-detail">{kpis['lifecycle_completed']}/{total} reached terminal state</div>
      <div class="kpi-bar"><div class="kpi-bar-fill" style="width:{comp_pct}%;background:{_kpi_color(comp_pct)}"></div></div>
    </div>
  </div>

  <!-- Breakdowns -->
  <div class="section-title">Breakdowns</div>
  <div class="breakdown">
    <div class="breakdown-card">
      <h3>By CWE</h3>
      <table>{_bar_rows(by_cwe, 'var(--blue)', total)}</table>
    </div>
    <div class="breakdown-card">
      <h3>By Team</h3>
      <table>{_bar_rows(by_team, 'var(--purple)', total)}</table>
    </div>
    <div class="breakdown-card">
      <h3>By Policy Action</h3>
      <table>{_bar_rows(by_action, 'var(--cyan)', total)}</table>
    </div>
    <div class="breakdown-card">
      <h3>By Lifecycle State</h3>
      <table>{_bar_rows(by_lifecycle, 'var(--green)', total)}</table>
    </div>
  </div>

  <!-- Alert table -->
  <div class="section-title">All Findings</div>

  <div class="filters">
    <button class="filter-btn active" onclick="filterAlerts('all')">All</button>
    <button class="filter-btn" onclick="filterAlerts('UNDER_REVIEW')">Under Review</button>
    <button class="filter-btn" onclick="filterAlerts('MERGED')">Merged</button>
    <button class="filter-btn" onclick="filterAlerts('ESCALATED')">Escalated</button>
    <button class="filter-btn" onclick="filterAlerts('DEFERRED')">Deferred</button>
  </div>

  <div class="alert-table">
    <table>
      <tr>
        <th>ID</th><th>CWE</th><th>Rule</th><th>Team</th>
        <th>Action</th><th>State</th><th>PR</th><th>Updated</th>
      </tr>
      {alert_rows if alert_rows else '<tr><td colspan="8" style="color:var(--muted)">No alerts tracked yet</td></tr>'}
    </table>
  </div>

  <div class="footer">
    SAGE &middot; {total} findings tracked &middot; Last activity: {last_event_display}
  </div>

  <script>
    // Filter alert rows by lifecycle state
    function filterAlerts(state) {{
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      event.target.classList.add('active');
      document.querySelectorAll('.alert-row').forEach(row => {{
        row.style.display = (state === 'all' || row.dataset.state === state) ? '' : 'none';
      }});
    }}

    // Animate bars on load
    document.addEventListener('DOMContentLoaded', () => {{
      document.querySelectorAll('.kpi-bar-fill, .bar').forEach(el => {{
        const w = el.style.width;
        el.style.width = '0%';
        requestAnimationFrame(() => {{ el.style.width = w; }});
      }});
    }});
  </script>
</body>
</html>
"""

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(html)
    return output_path
