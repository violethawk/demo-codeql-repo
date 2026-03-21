"""Tests for the policy layer."""

from sage.pipeline.policy import (
    AUTO_REMEDIATE, REMEDIATE_WITH_REVIEW, ESCALATE,
    get_policy,
)


def test_cwe89_auto_remediate():
    policy = get_policy("CWE-89")
    assert policy is not None
    assert policy.action == AUTO_REMEDIATE
    assert policy.fix_confidence == "HIGH"
    assert policy.sla_hours == 24


def test_cwe79_remediate_with_review():
    policy = get_policy("CWE-79")
    assert policy is not None
    assert policy.action == REMEDIATE_WITH_REVIEW
    assert policy.fix_confidence == "MEDIUM"


def test_cwe78_remediate_with_review():
    policy = get_policy("CWE-78")
    assert policy is not None
    assert policy.action == REMEDIATE_WITH_REVIEW


def test_cwe798_escalate():
    policy = get_policy("CWE-798")
    assert policy is not None
    assert policy.action == ESCALATE
    assert policy.sla_hours == 12


def test_unknown_cwe_returns_none():
    assert get_policy("CWE-999") is None
