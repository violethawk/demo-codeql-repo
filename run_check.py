#!/usr/bin/env python3
"""SAGE Health Check: Validate configuration and connectivity.

Run before deployment to verify everything is wired up:

    python run_check.py

Checks:
    1. sage.config.json loads and has required fields
    2. Devin API key is set and valid (if DEVIN_MODE=real)
    3. Slack webhook responds (if NOTIFY_MODE=slack)
    4. gh CLI is authenticated (if PR_MODE=github)
    5. SQLite database is accessible
    6. All pipeline modules import cleanly
    7. Tests pass
"""

import json
import os
import shutil
import subprocess
import sys
import urllib.request
import urllib.error
from pathlib import Path


SEPARATOR = "-" * 62
CHECKS: list[tuple[str, bool, str]] = []  # (name, passed, detail)


def check(name: str, passed: bool, detail: str = "") -> bool:
    CHECKS.append((name, passed, detail))
    icon = "+" if passed else "X"
    detail_str = f"  {detail}" if detail else ""
    print(f"  [{icon}] {name}{detail_str}")
    return passed


def main() -> int:
    print()
    print(SEPARATOR)
    print("  SAGE Health Check")
    print(SEPARATOR)
    print()

    # 1. Config file
    config_path = Path("sage.config.json")
    if config_path.exists():
        try:
            config = json.loads(config_path.read_text())
            has_reviewers = bool(config.get("reviewers"))
            has_slack = bool(config.get("slack", {}).get("channels"))
            has_thresholds = bool(config.get("kpi_thresholds"))
            check("sage.config.json", True, "loaded")
            check("  reviewers configured", has_reviewers,
                  f"{sum(len(v) for v in config.get('reviewers', {}).values())} reviewer(s)")
            check("  slack channels configured", has_slack)
            check("  kpi thresholds configured", has_thresholds)
        except (json.JSONDecodeError, KeyError) as e:
            check("sage.config.json", False, f"parse error: {e}")
    else:
        check("sage.config.json", False, "not found")

    # 2. Devin API
    devin_mode = os.environ.get("DEVIN_MODE", "stub")
    devin_key = os.environ.get("DEVIN_API_KEY", "")
    if devin_mode == "real":
        if devin_key:
            try:
                req = urllib.request.Request(
                    "https://api.devin.ai/v1/sessions",
                    method="GET",
                    headers={
                        "Authorization": f"Bearer {devin_key}",
                        "Accept": "application/json",
                    },
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    check("Devin API", resp.status == 200, f"authenticated (status {resp.status})")
            except (urllib.error.HTTPError, urllib.error.URLError) as e:
                check("Devin API", False, str(e))
        else:
            check("Devin API", False, "DEVIN_MODE=real but DEVIN_API_KEY not set")
    else:
        check("Devin API", True, "stub mode (no key required)")

    # 3. Slack webhook
    notify_mode = os.environ.get("NOTIFY_MODE", "stub")
    slack_url = os.environ.get("SLACK_WEBHOOK_URL", "")
    if notify_mode == "slack":
        if slack_url:
            # Don't actually post — just verify the URL is reachable
            try:
                # Slack webhooks return "no_text" for empty payloads but 200
                req = urllib.request.Request(
                    slack_url, data=b'{"text":""}',
                    method="POST",
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=10):
                    check("Slack webhook", True, "reachable")
            except urllib.error.HTTPError as e:
                # 400 is expected for empty text — means webhook is valid
                if e.code == 400:
                    check("Slack webhook", True, "reachable (400 on empty payload is expected)")
                else:
                    check("Slack webhook", False, f"HTTP {e.code}")
            except urllib.error.URLError as e:
                check("Slack webhook", False, str(e))
        else:
            check("Slack webhook", False, "NOTIFY_MODE=slack but SLACK_WEBHOOK_URL not set")
    else:
        check("Slack webhook", True, "stub mode (no webhook required)")

    # 4. gh CLI
    pr_mode = os.environ.get("PR_MODE", "stub")
    if pr_mode == "github":
        if shutil.which("gh"):
            result = subprocess.run(
                ["gh", "auth", "status"],
                capture_output=True, text=True,
            )
            check("gh CLI", result.returncode == 0,
                  "authenticated" if result.returncode == 0 else result.stderr.strip()[:80])
        else:
            check("gh CLI", False, "not installed")
    else:
        check("gh CLI", True, "stub mode (gh not required)")

    # 5. Database
    try:
        from pipeline.store import init_db
        conn = init_db()
        count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        journal = conn.execute("PRAGMA journal_mode").fetchone()[0]
        check("SQLite database", True, f"{count} alert(s), journal={journal}")
        conn.close()
    except Exception as e:
        check("SQLite database", False, str(e))

    # 6. Module imports
    try:
        import pipeline.ingest
        import pipeline.triage
        import pipeline.policy
        import pipeline.execute
        import pipeline.validate
        import pipeline.enforcement
        import pipeline.sarif
        import pipeline.store
        import pipeline.output
        import integrations.devin_client
        import integrations.pr_client
        import integrations.notify
        import integrations.dashboard
        check("Pipeline modules", True, "all 13 modules import cleanly")
    except ImportError as e:
        check("Pipeline modules", False, str(e))

    # 7. Tests
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "-q", "--tb=no"],
        capture_output=True, text=True,
    )
    test_line = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else "no output"
    check("Tests", result.returncode == 0, test_line)

    # Summary
    passed = sum(1 for _, p, _ in CHECKS if p)
    total = len(CHECKS)
    failed = total - passed

    print()
    print(SEPARATOR)
    if failed == 0:
        print(f"  All {total} checks passed. SAGE is ready.")
    else:
        print(f"  {passed}/{total} passed, {failed} failed.")
    print(SEPARATOR)
    print()

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
