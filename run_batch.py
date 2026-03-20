#!/usr/bin/env python3
"""Batch-process multiple CodeQL alerts through the remediation pipeline.

Usage:
    python run_batch.py fixtures/              # all JSON files in a directory
    python run_batch.py fixtures/sample_*.json # glob pattern
    python run_batch.py alert1.json alert2.json # explicit list
"""

import glob
import sys
from pathlib import Path

from pipeline import store
from pipeline.ingest import load_alert
from run_demo import process_alert


SEPARATOR = "-" * 56


def resolve_paths(args: list[str]) -> list[str]:
    """Expand directories and globs into a sorted list of JSON file paths."""
    paths: list[str] = []
    for arg in args:
        p = Path(arg)
        if p.is_dir():
            paths.extend(sorted(str(f) for f in p.glob("*.json")))
        elif "*" in arg or "?" in arg:
            paths.extend(sorted(glob.glob(arg)))
        elif p.is_file():
            paths.append(str(p))
        else:
            print(f"  Warning: skipping {arg} (not found)")
    return paths


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python run_batch.py <directory|glob|files...> [repo_root]")
        return 1

    # Last arg might be repo_root if it's a directory without JSON files
    args = sys.argv[1:]
    repo_root = "target_repo"

    alert_paths = resolve_paths(args)
    if not alert_paths:
        print("No alert JSON files found.")
        return 1

    db_conn = store.init_db()

    print()
    print(SEPARATOR)
    print("  SAGE Batch Remediation")
    print(SEPARATOR)
    print(f"  Alerts found: {len(alert_paths)}")
    print(f"  Target repo:  {repo_root}")
    print(SEPARATOR)
    print()

    results: list[dict] = []

    for i, alert_path in enumerate(alert_paths, 1):
        print(f"  [{i}/{len(alert_paths)}] Processing {alert_path}...")

        # Check if already processed
        try:
            alert = load_alert(alert_path)
        except (ValueError, FileNotFoundError) as e:
            print(f"    Skipped: {e}")
            results.append({
                "file": alert_path,
                "alert_id": "?",
                "cwe": "?",
                "disposition": "ERROR",
                "error": str(e),
            })
            continue

        existing = store.get_alert(db_conn, alert.alert_id)
        if existing and existing["disposition"] == "PR_READY":
            print(f"    Skipped: {alert.alert_id} already remediated (PR_READY)")
            results.append({
                "file": alert_path,
                "alert_id": alert.alert_id,
                "cwe": alert.cwe,
                "disposition": "SKIPPED (already PR_READY)",
            })
            continue

        report = process_alert(alert_path, repo_root, db_conn=db_conn, quiet=True)
        disposition = report["disposition"]
        status_icon = "+" if disposition == "PR_READY" else "!"
        print(f"    [{status_icon}] {alert.alert_id} ({alert.cwe}) -> {disposition}")
        results.append({
            "file": alert_path,
            "alert_id": alert.alert_id,
            "cwe": alert.cwe,
            "disposition": disposition,
        })

    # Summary
    print()
    print(SEPARATOR)
    print("  BATCH SUMMARY")
    print(SEPARATOR)
    print()
    print(f"  {'Alert ID':<16} {'CWE':<10} {'Disposition':<28}")
    print(f"  {'-'*14:<16} {'-'*8:<10} {'-'*26:<28}")
    for r in results:
        print(f"  {r['alert_id']:<16} {r['cwe']:<10} {r['disposition']:<28}")

    # Metrics
    metrics = store.get_metrics(db_conn)
    total = metrics["total"]
    rate = metrics["remediation_rate"]
    print()
    print(f"  Remediation rate: {rate:.0%} ({metrics['by_disposition'].get('PR_READY', 0)}/{total})")

    # Generate aggregate dashboard
    from integrations.dashboard import generate_aggregate_dashboard
    agg_path = generate_aggregate_dashboard(db_conn)
    print(f"  Aggregate dashboard: {agg_path}")
    print(SEPARATOR)

    db_conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
