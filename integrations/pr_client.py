"""PR Creation Layer: Generate pull request payloads.

Produces a structured PR payload from remediation results.
When real GitHub integration is available, this would call the
GitHub API to create the actual PR.

Currently: Generates a realistic pr_payload.json artifact.
"""

import json
from pathlib import Path

from pipeline.execute import ExecutionResult
from pipeline.ingest import Alert


def build_pr_payload(alert: Alert, exec_result: ExecutionResult, pr_url: str) -> dict:
    """Build a structured PR payload from remediation results."""
    branch = f"codeql-fix/{alert.alert_id}"

    body_lines = [
        f"## [{alert.cwe}] {alert.rule_name}",
        "",
        f"**Alert ID**: {alert.alert_id}",
        f"**Severity**: {alert.severity}",
        f"**File**: `{alert.file_path}`",
        "",
        "### Root Cause",
        exec_result.root_cause,
        "",
        "### Fix",
        exec_result.fix_description,
        "",
        "### Why This Works",
        exec_result.why_fix_works,
        "",
        "---",
        "This change is intended to go through standard code review "
        "and branch protection policies in production environments.",
    ]

    return {
        "repo": f"violethawk/{alert.repo_name}",
        "branch": branch,
        "title": f"[CodeQL] Fix {alert.rule_name} in {alert.file_path}",
        "body": "\n".join(body_lines),
        "files_changed": exec_result.files_changed,
        "status": "open",
        "url": pr_url,
    }


def write_pr_payload(payload: dict, output_path: str = "artifacts/pr_payload.json") -> None:
    """Write the PR payload to a JSON artifact."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(payload, indent=2) + "\n")
