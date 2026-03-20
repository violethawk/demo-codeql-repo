"""PR Creation Layer: Generate pull request payloads.

Integration boundary:
    build_pr_payload()  → assembles a PullRequestPayload dataclass
    deliver_pr()        → stub: writes JSON artifact to disk
                           real: would POST to GitHub API

To connect to the real GitHub API, replace the body of deliver_pr()
with an authenticated POST to /repos/{owner}/{repo}/pulls.
"""

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List

from pipeline.execute import ExecutionResult
from pipeline.ingest import Alert


# ---------------------------------------------------------------------------
# Request / Response contracts
# ---------------------------------------------------------------------------


@dataclass
class PullRequestPayload:
    """Structured PR payload — the contract between pipeline and GitHub."""

    repo: str
    branch: str
    title: str
    body: str
    files_changed: List[str]
    status: str  # "open" | "merged" | "closed"
    url: str
    integration_mode: str = "stub"


@dataclass
class PRDeliveryResult:
    """Result of attempting to deliver / create the PR."""

    delivered: bool
    method: str  # "stub_artifact" | "github_api"
    artifact_path: str = ""
    error: str = ""


# ---------------------------------------------------------------------------
# Payload builder
# ---------------------------------------------------------------------------

ARTIFACT_PATH = "artifacts/pr_payload.json"


def build_pr_payload(
    alert: Alert,
    exec_result: ExecutionResult,
    pr_url: str,
    integration_mode: str = "stub",
) -> PullRequestPayload:
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

    return PullRequestPayload(
        repo=f"violethawk/{alert.repo_name}",
        branch=branch,
        title=f"[CodeQL] Fix {alert.rule_name} in {alert.file_path}",
        body="\n".join(body_lines),
        files_changed=exec_result.files_changed,
        status="open",
        url=pr_url,
        integration_mode=integration_mode,
    )


# ---------------------------------------------------------------------------
# Delivery (stub writes JSON; real would POST to GitHub)
# ---------------------------------------------------------------------------


def deliver_pr(
    payload: PullRequestPayload,
    output_path: str = ARTIFACT_PATH,
) -> PRDeliveryResult:
    """Deliver the PR payload.

    Stub mode:  serialize to a JSON artifact on disk.
    Real mode:  would POST to GitHub API (placeholder).

    To implement real delivery, replace the body with:

        import requests
        resp = requests.post(
            f"https://api.github.com/repos/{payload.repo}/pulls",
            headers={"Authorization": f"Bearer {github_token}", ...},
            json={"title": payload.title, "body": payload.body,
                  "head": payload.branch, "base": "main"},
        )
        resp.raise_for_status()
        return PRDeliveryResult(delivered=True, method="github_api")
    """
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(asdict(payload), indent=2) + "\n")
    return PRDeliveryResult(
        delivered=True,
        method="stub_artifact",
        artifact_path=output_path,
    )


# Backward-compatible alias
def write_pr_payload(
    payload: PullRequestPayload,
    output_path: str = ARTIFACT_PATH,
) -> None:
    """Write the PR payload to a JSON artifact (legacy wrapper)."""
    deliver_pr(payload, output_path)
