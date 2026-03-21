"""Notification Layer: Deliver notifications to engineering teams.

Supports two delivery modes:

    NOTIFY_MODE=stub  (default) -- Writes JSON artifact to disk.
    NOTIFY_MODE=slack           -- POSTs to Slack incoming webhook.

For Slack, set SLACK_WEBHOOK_URL to your workspace's incoming webhook URL.
"""

import json
import os
import urllib.request
import urllib.error
from dataclasses import asdict, dataclass
from pathlib import Path

from sage.pipeline.ingest import Alert


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
    status: str  # "ready_for_review" | "needs_attention" | "escalation" | "sla_breach"
    message: str
    integration_mode: str = "stub"


@dataclass
class NotificationDeliveryResult:
    """Result of attempting to deliver the notification."""

    delivered: bool
    method: str  # "stub_artifact" | "slack_webhook"
    artifact_path: str = ""
    error: str = ""


# ---------------------------------------------------------------------------
# Configuration (loaded from sage.config.json + env vars)
# ---------------------------------------------------------------------------

ARTIFACT_PATH = "artifacts/notification_payload.json"


def _load_channel_config() -> tuple[dict[str, str], str, dict[str, str]]:
    """Load channel mappings from sage.config.json."""
    config_path = Path("sage.config.json")
    if config_path.exists():
        config = json.loads(config_path.read_text())
        slack = config.get("slack", {})
        channels = slack.get("channels", {})
        default = channels.pop("default", "#security-alerts")
        escalation = slack.get("escalation_channels", {})
        return channels, default, escalation
    return {}, "#security-alerts", {}


TEAM_CHANNELS, DEFAULT_CHANNEL, ESCALATION_CHANNELS = _load_channel_config()


def _get_notify_mode() -> str:
    return os.environ.get("NOTIFY_MODE", "stub")


# ---------------------------------------------------------------------------
# Payload builder
# ---------------------------------------------------------------------------


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
# Delivery
# ---------------------------------------------------------------------------


def _deliver_slack(payload: NotificationPayload) -> NotificationDeliveryResult:
    """POST to Slack incoming webhook."""
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL", "")
    if not webhook_url:
        return NotificationDeliveryResult(
            delivered=False,
            method="slack_webhook",
            error="SLACK_WEBHOOK_URL not set",
        )

    # Build Slack Block Kit message
    status_emoji = {
        "ready_for_review": ":white_check_mark:",
        "needs_attention": ":warning:",
        "escalation": ":rotating_light:",
        "sla_breach": ":red_circle:",
    }.get(payload.status, ":information_source:")

    slack_body = {
        "channel": payload.channel,
        "text": payload.message,
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{status_emoji} SAGE: {payload.alert_id}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*CWE:* {payload.cwe}"},
                    {"type": "mrkdwn", "text": f"*Status:* {payload.status}"},
                    {"type": "mrkdwn", "text": f"*Team:* {payload.owner_team}"},
                    {"type": "mrkdwn", "text": f"*Disposition:* {payload.disposition}"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": payload.message},
            },
        ],
    }

    if payload.pr_url:
        slack_body["blocks"].append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View PR"},
                    "url": payload.pr_url,
                },
            ],
        })

    data = json.dumps(slack_body).encode()
    req = urllib.request.Request(
        webhook_url,
        data=data,
        method="POST",
        headers={"Content-Type": "application/json"},
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return NotificationDeliveryResult(
                delivered=True,
                method="slack_webhook",
            )
    except (urllib.error.HTTPError, urllib.error.URLError) as e:
        return NotificationDeliveryResult(
            delivered=False,
            method="slack_webhook",
            error=str(e),
        )


def _deliver_stub(
    payload: NotificationPayload,
    output_path: str,
) -> NotificationDeliveryResult:
    """Write notification as JSON artifact (no network calls)."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(asdict(payload), indent=2) + "\n")
    return NotificationDeliveryResult(
        delivered=True,
        method="stub_artifact",
        artifact_path=output_path,
    )


def deliver_notification(
    payload: NotificationPayload,
    output_path: str = ARTIFACT_PATH,
) -> NotificationDeliveryResult:
    """Deliver a notification using the configured mode.

    Set NOTIFY_MODE=slack and SLACK_WEBHOOK_URL to deliver to Slack.
    Always writes the artifact to disk for audit regardless of mode.
    """
    # Always write artifact for audit trail
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(asdict(payload), indent=2) + "\n")

    mode = _get_notify_mode()
    if mode == "slack":
        result = _deliver_slack(payload)
        result.artifact_path = output_path
        return result

    return NotificationDeliveryResult(
        delivered=True,
        method="stub_artifact",
        artifact_path=output_path,
    )


# ---------------------------------------------------------------------------
# Escalation notifications
# ---------------------------------------------------------------------------


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
        integration_mode=_get_notify_mode(),
    )
