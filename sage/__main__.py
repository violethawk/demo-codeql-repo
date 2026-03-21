#!/usr/bin/env python3
"""SAGE — Security Automation & Governance Engine

Usage:
    python -m sage interactive          # browser-based demo
    python -m sage demo [fixture]       # single alert
    python -m sage batch <dir>          # batch processing
    python -m sage sarif <file>         # SARIF ingestion
    python -m sage metrics              # KPI dashboard
    python -m sage enforce [--dry-run]  # SLA + KPI enforcement
    python -m sage override <id> <act>  # human override
    python -m sage check                # validate deployment
    python -m sage full-demo            # 5-phase end-to-end
"""

import importlib
import sys


COMMANDS = {
    "interactive": ("sage.cli.interactive", "Browser-based interactive demo"),
    "demo":        ("sage.cli.demo",        "Process a single alert"),
    "batch":       ("sage.cli.batch",       "Batch-process a directory of alerts"),
    "sarif":       ("sage.cli.sarif",       "Ingest CodeQL SARIF output"),
    "metrics":     ("sage.cli.metrics",     "Display all 9 KPIs"),
    "enforce":     ("sage.cli.enforce",     "Run SLA + KPI enforcement"),
    "override":    ("sage.cli.override",    "Human override: merge/reject/defer/escalate"),
    "check":       ("sage.cli.check",       "Validate configuration and connectivity"),
    "full-demo":   ("sage.cli.full_demo",   "5-phase end-to-end demo"),
}


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print()
        print("  SAGE — Security Automation & Governance Engine")
        print()
        print("  Usage: python -m sage <command> [args...]")
        print()
        for cmd, (_, desc) in COMMANDS.items():
            print(f"    {cmd:<16} {desc}")
        print()
        print("  Examples:")
        print("    python -m sage interactive")
        print("    python -m sage demo demo/fixtures/sample_alert.json")
        print("    python -m sage batch demo/fixtures/")
        print("    python -m sage metrics")
        print("    python -m sage enforce --dry-run")
        print("    python -m sage override demo-001 merge")
        print()
        return 0

    cmd = sys.argv[1]
    if cmd not in COMMANDS:
        print(f"  Unknown command: {cmd}")
        print(f"  Run 'python -m sage help' for available commands.")
        return 1

    module_name = COMMANDS[cmd][0]
    sys.argv = [module_name] + sys.argv[2:]

    module = importlib.import_module(module_name)
    return module.main()


if __name__ == "__main__":
    sys.exit(main())
