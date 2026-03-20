#!/usr/bin/env python3
"""Ingest a CodeQL SARIF file and process all results through the pipeline.

Usage:
    python run_sarif.py results.sarif                    # process SARIF
    python run_sarif.py results.sarif --repo target_repo # specify repo root
    python run_sarif.py results.sarif --emit-fixtures     # just write fixture JSONs

This is the intended production entry point: connect it to your CI/CD
pipeline after `codeql database analyze` to auto-remediate findings.
"""

import argparse
import sys
import tempfile
from pathlib import Path

from pipeline import store
from pipeline.sarif import parse_sarif, sarif_to_fixtures
from run_demo import process_alert


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SAGE: Process CodeQL SARIF output through the remediation pipeline",
    )
    parser.add_argument("sarif", help="Path to SARIF JSON file")
    parser.add_argument("--repo", default="target_repo", help="Target repo root")
    parser.add_argument(
        "--emit-fixtures", action="store_true",
        help="Only write fixture JSONs (don't run the pipeline)",
    )
    parser.add_argument(
        "--fixtures-dir", default=None,
        help="Directory for fixture output (default: temp dir)",
    )
    args = parser.parse_args()

    sarif_path = args.sarif
    if not Path(sarif_path).exists():
        print(f"Error: SARIF file not found: {sarif_path}")
        return 1

    # Parse SARIF
    alerts = parse_sarif(sarif_path)
    print(f"\n  Parsed {len(alerts)} result(s) from {sarif_path}")
    for a in alerts:
        cwe = a.get("cwe", "?")
        rule = a.get("rule_name", "?")
        print(f"    {a['alert_id']}  {cwe:<10} {rule}")
    print()

    if not alerts:
        print("  No results found in SARIF file.")
        return 0

    # Emit fixtures mode
    if args.emit_fixtures:
        out_dir = args.fixtures_dir or "fixtures"
        paths = sarif_to_fixtures(sarif_path, output_dir=out_dir)
        print(f"  Wrote {len(paths)} fixture file(s) to {out_dir}/")
        for p in paths:
            print(f"    {p}")
        return 0

    # Full pipeline mode: write temp fixtures and process each
    fixtures_dir = args.fixtures_dir or tempfile.mkdtemp(prefix="codeql-sarif-")
    paths = sarif_to_fixtures(sarif_path, output_dir=fixtures_dir)

    db_conn = store.init_db()
    results: list[dict] = []

    for fixture_path in paths:
        report = process_alert(fixture_path, args.repo, db_conn=db_conn, quiet=True)
        alert_id = report.get("alert_id", "?")
        cwe = report.get("cwe", "?")
        disposition = report["disposition"]
        icon = "+" if disposition == "PR_READY" else "!"
        print(f"  [{icon}] {alert_id} ({cwe}) -> {disposition}")
        results.append(report)

    # Generate aggregate dashboard
    from integrations.dashboard import generate_aggregate_dashboard
    agg_path = generate_aggregate_dashboard(db_conn)
    print(f"\n  Aggregate dashboard: {agg_path}")

    # Summary
    total = len(results)
    remediated = sum(1 for r in results if r["disposition"] == "PR_READY")
    print(f"  Remediation rate: {remediated}/{total} ({int(remediated/total*100) if total else 0}%)")

    db_conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
