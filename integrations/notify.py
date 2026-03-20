"""Notification Layer: Notify engineering teams of remediation outcomes.

Integration boundary:
    build_notification()  → assembles a NotificationPayload dataclass
    deliver_notification() → stub: writes JSON artifact to disk
                              real: would POST to Slack / PagerDuty / email

To connect to a real channel, replace the body of deliver_notification()
with the appropriate API call (e.g., Slack chat.postMessage).
"""

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from pipeline.ingest import Alert


# ---------------------------------------------------------------------------
# Request / Response contracts
# ---------------------------------------------------------------------------


@dataclass
class NotificationPayload:
    """Structured notification — the contract between pipeline and comms."""

    channel: str
    alert_id: str
    rule_name: str
    cwe: str
    disposition: str
    pr_url: str
    owner_team: str
    status: str  # "ready_for_review" | "needs_attention"
    message: str
    integration_mode: str = "stub"


@dataclass
class NotificationDeliveryResult:
    """Result of attempting to deliver the notification."""

    delivered: bool
    method: str  # "stub_artifact" | "slack_api" | "email"
    artifact_path: str = ""
    error: str = ""


# ---------------------------------------------------------------------------
# Payload builder
# ---------------------------------------------------------------------------

ARTIFACT_PATH = "artifacts/notification_payload.json"

# Route notifications to the appropriate team channel
TEAM_CHANNELS: dict[str, str] = {
    "backend": "#backend-security",
    "frontend": "#frontend-security",
    "platform": "#platform-security",
    "infra": "#infra-security",
}
DEFAULT_CHANNEL = "#security-alerts"


def build_notification(
    alert: Alert,
    disposition: str,
    pr_url: str,
    integration_mode: str = "stub",
) -> NotificationPayload:
    """Build a notification payload for the owning team."""
    channel = TEAM_CHANNELS.get(alert.owner_team, DEFAULT_CHANNEL)

    if disposition == "PR_READY":
        status = "ready_for_review"
        message = (
            f"CodeQL alert {alert.alert_id} ({alert.cwe}) has been "
            f"auto-remediated. PR is ready for review: {pr_url}"
        )
    else:
        status = "needs_attention"
        message = (
            f"CodeQL alert {alert.alert_id} ({alert.cwe}) requires "
            f"human review. Auto-remediation was not possible."
        )

    return NotificationPayload(
        channel=channel,
        alert_id=alert.alert_id,
        rule_name=alert.rule_name,
        cwe=alert.cwe,
        disposition=disposition,
        pr_url=pr_url,
        owner_team=alert.owner_team,
        status=status,
        message=message,
        integration_mode=integration_mode,
    )


# ---------------------------------------------------------------------------
# Delivery (stub writes JSON; real would POST to Slack / PagerDuty)
# ---------------------------------------------------------------------------


def deliver_notification(
    payload: NotificationPayload,
    output_path: str = ARTIFACT_PATH,
) -> NotificationDeliveryResult:
    """Deliver the notification.

    Stub mode:  serialize to a JSON artifact on disk.
    Real mode:  would POST to Slack / PagerDuty / email (placeholder).

    To implement real delivery, replace the body with:

        import requests
        resp = requests.post(
            "https://slack.com/api/chat.postMessage",
            headers={"Authorization": f"Bearer {slack_token}"},
            json={"channel": payload.channel,
                  "text": payload.message},
        )
        resp.raise_for_status()
        return NotificationDeliveryResult(
            delivered=True, method="slack_api",
        )
    """
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(asdict(payload), indent=2) + "\n")
    return NotificationDeliveryResult(
        delivered=True,
        method="stub_artifact",
        artifact_path=output_path,
    )


# ---------------------------------------------------------------------------
# Escalation notifications
# ---------------------------------------------------------------------------

ESCALATION_CHANNELS: dict[str, str] = {
    "remind_owner": "",       # goes to team channel
    "escalate_manager": "#engineering-leads",
    "sla_breach": "#security-escalations",
}


def build_escalation_notification(
    alert_id: str,
    cwe: str,
    owner_team: str,
    action_required: str,
    hours_elapsed: float,
    sla_hours: int,
) -> NotificationPayload:
    """Build an escalation notification for enforcement actions."""
    team_channel = TEAM_CHANNELS.get(owner_team, DEFAULT_CHANNEL)

    if action_required == "remind_owner":
        channel = team_channel
        status = "needs_attention"
        message = (
            f"Reminder: SAGE alert {alert_id} ({cwe}) has been open for "
            f"{hours_elapsed:.0f}h. Please review or escalate."
        )
    elif action_required == "escalate_manager":
        channel = ESCALATION_CHANNELS.get("escalate_manager", DEFAULT_CHANNEL)
        status = "escalation"
        message = (
            f"Escalation: SAGE alert {alert_id} ({cwe}) has had no action "
            f"for {hours_elapsed:.0f}h. Assigned team: {owner_team}."
        )
    elif action_required == "sla_breach":
        channel = ESCALATION_CHANNELS.get("sla_breach", DEFAULT_CHANNEL)
        status = "sla_breach"
        message = (
            f"SLA BREACH: SAGE alert {alert_id} ({cwe}) exceeded its "
            f"{sla_hours}h SLA ({hours_elapsed:.0f}h elapsed). "
            f"Immediate action required. Team: {owner_team}."
        )
    else:
        channel = team_channel
        status = "info"
        message = f"SAGE alert {alert_id} ({cwe}): {action_required}"

    return NotificationPayload(
        channel=channel,
        alert_id=alert_id,
        rule_name="",
        cwe=cwe,
        disposition="ENFORCEMENT",
        pr_url="",
        owner_team=owner_team,
        status=status,
        message=message,
        integration_mode="stub",
    )


# Backward-compatible alias
def write_notification(
    payload: NotificationPayload,
    output_path: str = ARTIFACT_PATH,
) -> None:
    """Write the notification payload to a JSON artifact (legacy wrapper)."""
    deliver_notification(payload, output_path)
