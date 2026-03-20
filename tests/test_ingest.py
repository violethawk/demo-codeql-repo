"""Tests for the ingest layer."""

import json

import pytest

from pipeline.ingest import load_alert


def test_load_valid_alert(tmp_path):
    """Loading a well-formed alert JSON produces an Alert with correct fields."""
    data = {
        "alert_id": "test-001",
        "rule_name": "Test rule",
        "severity": "high",
        "cwe": "CWE-89",
        "file_path": "app.py",
        "line_range": {"start": 10, "end": 15},
        "vulnerable_code_snippet": ["line1"],
        "alert_description": "desc",
    }
    path = tmp_path / "alert.json"
    path.write_text(json.dumps(data))

    alert = load_alert(str(path))

    assert alert.alert_id == "test-001"
    assert alert.cwe == "CWE-89"
    assert alert.line_range.start == 10
    assert alert.line_range.end == 15
    assert alert.owner_team == ""  # optional, defaults to ""


def test_load_alert_with_all_fields(tmp_path):
    """Optional fields are populated when present."""
    data = {
        "alert_id": "test-002",
        "rule_name": "XSS",
        "severity": "high",
        "cwe": "CWE-79",
        "language": "python",
        "repo_name": "my-repo",
        "file_path": "app.py",
        "line_range": {"start": 5, "end": 8},
        "vulnerable_code_snippet": ["line1", "line2"],
        "alert_description": "XSS vulnerability",
        "security_guidance": "Escape output",
        "owner_team": "frontend",
        "auto_fix_confidence": 0.7,
    }
    path = tmp_path / "alert.json"
    path.write_text(json.dumps(data))

    alert = load_alert(str(path))

    assert alert.owner_team == "frontend"
    assert alert.auto_fix_confidence == 0.7
    assert alert.repo_name == "my-repo"


def test_load_alert_missing_required_field(tmp_path):
    """Missing a required field raises ValueError."""
    data = {
        "alert_id": "test-003",
        "severity": "high",
        # missing rule_name, cwe, file_path, etc.
    }
    path = tmp_path / "alert.json"
    path.write_text(json.dumps(data))

    with pytest.raises(ValueError, match="missing required fields"):
        load_alert(str(path))


def test_load_alert_missing_line_range_fields(tmp_path):
    """line_range without start/end raises ValueError."""
    data = {
        "alert_id": "test-004",
        "rule_name": "Test",
        "severity": "high",
        "cwe": "CWE-89",
        "file_path": "app.py",
        "line_range": {"start": 1},  # missing "end"
        "vulnerable_code_snippet": ["x"],
        "alert_description": "desc",
    }
    path = tmp_path / "alert.json"
    path.write_text(json.dumps(data))

    with pytest.raises(ValueError, match="start.*end"):
        load_alert(str(path))
