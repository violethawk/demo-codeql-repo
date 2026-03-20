"""PR Creation Layer: Generate pull request payloads and deliver them.

Integration modes controlled by PR_MODE environment variable:

    PR_MODE=stub  (default) -- Writes JSON artifact to disk.
    PR_MODE=github         -- Creates a real branch + PR via `gh` CLI.
                              Requires `gh auth status` to pass.
"""

import json
import os
import shutil
import subprocess
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
    reviewers: List[str] = None  # GitHub usernames for code review
    labels: List[str] = None  # Labels to apply to the PR

    def __post_init__(self):
        if self.reviewers is None:
            self.reviewers = []
        if self.labels is None:
            self.labels = []


@dataclass
class PRDeliveryResult:
    """Result of attempting to deliver / create the PR."""

    delivered: bool
    method: str  # "stub_artifact" | "github_cli"
    artifact_path: str = ""
    pr_url: str = ""
    error: str = ""


# ---------------------------------------------------------------------------
# Payload builder
# ---------------------------------------------------------------------------

ARTIFACT_PATH = "artifacts/pr_payload.json"


# Maps owner_team to GitHub usernames for code review assignment.
# In production, this would come from a config file or GitHub CODEOWNERS.
TEAM_REVIEWERS: dict[str, list[str]] = {
    "backend": [],
    "frontend": [],
    "platform": [],
    "infra": [],
}
SECURITY_REVIEWERS: list[str] = []  # GitHub usernames for security review


def build_pr_payload(
    alert: Alert,
    exec_result: ExecutionResult,
    pr_url: str,
    integration_mode: str = "stub",
    review_required: bool = False,
) -> PullRequestPayload:
    """Build a structured PR payload from remediation results."""
    branch = f"codeql-fix/{alert.alert_id}"

    body_lines = [
        f"## [{alert.cwe}] {alert.rule_name}",
        "",
        f"**Alert ID**: {alert.alert_id}",
        f"**Severity**: {alert.severity}",
        f"**File**: `{alert.file_path}`",
        f"**Policy**: {'Security review required' if review_required else 'Standard review'}",
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

    # Assign reviewers based on team + policy
    reviewers = list(TEAM_REVIEWERS.get(alert.owner_team, []))
    if review_required:
        reviewers.extend(r for r in SECURITY_REVIEWERS if r not in reviewers)

    # Labels
    labels = [f"cwe:{alert.cwe}", f"severity:{alert.severity}", "sage:auto-remediation"]
    if review_required:
        labels.append("security-review-required")

    return PullRequestPayload(
        repo=f"violethawk/{alert.repo_name}",
        branch=branch,
        title=f"[SAGE] Fix {alert.rule_name} in {alert.file_path}",
        body="\n".join(body_lines),
        files_changed=exec_result.files_changed,
        status="open",
        url=pr_url,
        integration_mode=integration_mode,
        reviewers=reviewers,
        labels=labels,
    )


# ---------------------------------------------------------------------------
# Delivery: stub (JSON artifact) or github (gh CLI)
# ---------------------------------------------------------------------------


def _get_pr_mode() -> str:
    return os.environ.get("PR_MODE", "stub")


def _gh_available() -> bool:
    return shutil.which("gh") is not None


def _deliver_pr_github(
    payload: PullRequestPayload,
    repo_root: str,
) -> PRDeliveryResult:
    """Create a real branch and PR via the `gh` CLI.

    Prerequisites:
        - `gh` CLI installed and authenticated (`gh auth status`)
        - Current directory is a git repo with a remote
    """
    if not _gh_available():
        return PRDeliveryResult(
            delivered=False,
            method="github_cli",
            error="gh CLI not found. Install it or switch to PR_MODE=stub.",
        )

    # Verify gh is authenticated
    auth_check = subprocess.run(
        ["gh", "auth", "status"],
        capture_output=True, text=True, cwd=repo_root,
    )
    if auth_check.returncode != 0:
        return PRDeliveryResult(
            delivered=False,
            method="github_cli",
            error=f"gh not authenticated: {auth_check.stderr.strip()}",
        )

    # Create and switch to branch
    subprocess.run(
        ["git", "checkout", "-b", payload.branch],
        capture_output=True, text=True, cwd=repo_root,
    )

    # Stage changed files
    for f in payload.files_changed:
        subprocess.run(
            ["git", "add", f],
            capture_output=True, text=True, cwd=repo_root,
        )

    # Commit
    commit_result = subprocess.run(
        ["git", "commit", "-m", payload.title],
        capture_output=True, text=True, cwd=repo_root,
    )
    if commit_result.returncode != 0:
        return PRDeliveryResult(
            delivered=False,
            method="github_cli",
            error=f"git commit failed: {commit_result.stderr.strip()}",
        )

    # Push
    push_result = subprocess.run(
        ["git", "push", "-u", "origin", payload.branch],
        capture_output=True, text=True, cwd=repo_root,
    )
    if push_result.returncode != 0:
        return PRDeliveryResult(
            delivered=False,
            method="github_cli",
            error=f"git push failed: {push_result.stderr.strip()}",
        )

    # Create PR
    pr_result = subprocess.run(
        [
            "gh", "pr", "create",
            "--title", payload.title,
            "--body", payload.body,
            "--base", "main",
            "--head", payload.branch,
        ],
        capture_output=True, text=True, cwd=repo_root,
    )
    if pr_result.returncode != 0:
        return PRDeliveryResult(
            delivered=False,
            method="github_cli",
            error=f"gh pr create failed: {pr_result.stderr.strip()}",
        )

    pr_url = pr_result.stdout.strip()

    # Assign reviewers
    if payload.reviewers:
        subprocess.run(
            ["gh", "pr", "edit", pr_url, "--add-reviewer",
             ",".join(payload.reviewers)],
            capture_output=True, text=True, cwd=repo_root,
        )

    # Apply labels
    if payload.labels:
        subprocess.run(
            ["gh", "pr", "edit", pr_url, "--add-label",
             ",".join(payload.labels)],
            capture_output=True, text=True, cwd=repo_root,
        )

    # Also write the artifact for audit
    Path(ARTIFACT_PATH).parent.mkdir(parents=True, exist_ok=True)
    payload_dict = asdict(payload)
    payload_dict["url"] = pr_url
    payload_dict["integration_mode"] = "github"
    Path(ARTIFACT_PATH).write_text(json.dumps(payload_dict, indent=2) + "\n")

    return PRDeliveryResult(
        delivered=True,
        method="github_cli",
        artifact_path=ARTIFACT_PATH,
        pr_url=pr_url,
    )


def _deliver_pr_stub(
    payload: PullRequestPayload,
    output_path: str = ARTIFACT_PATH,
) -> PRDeliveryResult:
    """Write PR payload as a JSON artifact (no network calls)."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(asdict(payload), indent=2) + "\n")
    return PRDeliveryResult(
        delivered=True,
        method="stub_artifact",
        artifact_path=output_path,
    )


def deliver_pr(
    payload: PullRequestPayload,
    output_path: str = ARTIFACT_PATH,
    repo_root: str = "",
) -> PRDeliveryResult:
    """Deliver a PR using the configured mode.

    Set PR_MODE=github to create real branches and PRs via `gh`.
    Defaults to stub mode (JSON artifact on disk).
    """
    mode = _get_pr_mode()
    if mode == "github" and repo_root:
        return _deliver_pr_github(payload, repo_root)
    return _deliver_pr_stub(payload, output_path)


# Backward-compatible alias
def write_pr_payload(
    payload: PullRequestPayload,
    output_path: str = ARTIFACT_PATH,
) -> None:
    """Write the PR payload to a JSON artifact (legacy wrapper)."""
    deliver_pr(payload, output_path)
