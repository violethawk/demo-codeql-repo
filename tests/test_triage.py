"""Tests for the triage layer."""

from sage.pipeline.ingest import Alert, LineRange
from sage.pipeline.policy import AUTO_REMEDIATE, REMEDIATE_WITH_REVIEW, ESCALATE
from sage.pipeline.triage import triage


def _make_alert(**overrides) -> Alert:
    defaults = dict(
        alert_id="test-001",
        rule_name="Test rule",
        severity="high",
        cwe="CWE-89",
        language="python",
        repo_name="repo",
        default_branch="main",
        file_path="app.py",
        line_range=LineRange(start=1, end=5),
        vulnerable_code_snippet=["x = 1"],
        alert_description="desc",
        security_guidance="fix it",
        owner_team="backend",
    )
    defaults.update(overrides)
    return Alert(**defaults)


def test_cwe89_auto_remediate():
    """CWE-89 gets AUTO_REMEDIATE action."""
    result = triage(_make_alert())
    assert result.eligible is True
    assert result.auto_fixable is True
    assert result.action == AUTO_REMEDIATE


def test_cwe79_remediate_with_review():
    """CWE-79 gets REMEDIATE_WITH_REVIEW action."""
    result = triage(_make_alert(cwe="CWE-79"))
    assert result.eligible is True
    assert result.auto_fixable is True
    assert result.action == REMEDIATE_WITH_REVIEW


def test_cwe78_remediate_with_review():
    """CWE-78 gets REMEDIATE_WITH_REVIEW action."""
    result = triage(_make_alert(cwe="CWE-78"))
    assert result.eligible is True
    assert result.auto_fixable is True
    assert result.action == REMEDIATE_WITH_REVIEW


def test_cwe798_escalate():
    """CWE-798 (hardcoded creds) gets ESCALATE action."""
    result = triage(_make_alert(cwe="CWE-798"))
    assert result.eligible is True
    assert result.auto_fixable is False
    assert result.action == ESCALATE


def test_medium_severity_not_eligible():
    result = triage(_make_alert(severity="medium"))
    assert result.eligible is False


def test_unknown_cwe_not_eligible():
    result = triage(_make_alert(cwe="CWE-999"))
    assert result.eligible is False


def test_empty_snippet_not_eligible():
    result = triage(_make_alert(vulnerable_code_snippet=[]))
    assert result.eligible is False


def test_sla_hours_propagated():
    """SLA hours from policy are propagated to triage result."""
    result = triage(_make_alert(cwe="CWE-798"))
    assert result.sla_hours == 12  # CWE-798 has 12h SLA
