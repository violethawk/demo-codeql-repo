#!/usr/bin/env python3
"""SAGE — Security Automation & Governance Engine

Unified entry point. Run `python sage.py` to see available commands.

Usage:
    python sage.py interactive          # browser-based demo
    python sage.py demo [fixture]       # single alert
    python sage.py batch <dir>          # batch processing
    python sage.py sarif <file>         # SARIF ingestion
    python sage.py metrics              # KPI dashboard
    python sage.py enforce [--dry-run]  # SLA + KPI enforcement
    python sage.py override <id> <act>  # human override
    python sage.py check                # validate deployment
    python sage.py full-demo            # 5-phase end-to-end
"""

import sys


COMMANDS = {
    "interactive": ("run_interactive", "Browser-based interactive demo"),
    "demo":        ("run_demo",        "Process a single alert"),
    "batch":       ("run_batch",       "Batch-process a directory of alerts"),
    "sarif":       ("run_sarif",       "Ingest CodeQL SARIF output"),
    "metrics":     ("run_metrics",     "Display all 9 KPIs"),
    "enforce":     ("run_enforce",     "Run SLA + KPI enforcement"),
    "override":    ("run_override",    "Human override: merge/reject/defer/escalate"),
    "check":       ("run_check",       "Validate configuration and connectivity"),
    "full-demo":   ("run_full_demo",   "5-phase end-to-end demo"),
}


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print()
        print("  SAGE — Security Automation & Governance Engine")
        print()
        print("  Usage: python sage.py <command> [args...]")
        print()
        for cmd, (_, desc) in COMMANDS.items():
            print(f"    {cmd:<16} {desc}")
        print()
        print("  Examples:")
        print("    python sage.py interactive")
        print("    python sage.py demo demo/fixtures/sample_alert.json")
        print("    python sage.py batch demo/fixtures/")
        print("    python sage.py metrics")
        print("    python sage.py enforce --dry-run")
        print("    python sage.py override demo-001 merge")
        print()
        return 0

    cmd = sys.argv[1]
    if cmd not in COMMANDS:
        print(f"  Unknown command: {cmd}")
        print(f"  Run 'python sage.py help' for available commands.")
        return 1

    # Remove 'sage.py <cmd>' from argv so the target script sees its own args
    module_name = COMMANDS[cmd][0]
    sys.argv = [module_name + ".py"] + sys.argv[2:]

    # Import and run
    module = __import__(module_name)
    return module.main()


if __name__ == "__main__":
    sys.exit(main())
