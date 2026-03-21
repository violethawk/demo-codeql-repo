"""Tests for SARIF ingestion."""

import json

from pipeline.sarif import parse_sarif, sarif_to_fixtures


def _minimal_sarif(results=None, rules=None):
    """Build a minimal valid SARIF structure."""
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": rules or [],
                    }
                },
                "results": results or [],
            }
        ],
    }


def test_parse_empty_sarif(tmp_path):
    path = tmp_path / "empty.sarif"
    path.write_text(json.dumps(_minimal_sarif()))
    alerts = parse_sarif(str(path))
    assert alerts == []


def test_parse_single_result(tmp_path):
    sarif = _minimal_sarif(
        rules=[
            {
                "id": "py/sql-injection",
                "shortDescription": {"text": "SQL injection"},
                "properties": {"tags": ["external/cwe/cwe-089"]},
            }
        ],
        results=[
            {
                "ruleId": "py/sql-injection",
                "message": {"text": "Tainted SQL query"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "app.py"},
                            "region": {
                                "startLine": 10,
                                "endLine": 15,
                                "snippet": {"text": "query = f'SELECT ...'"},
                            },
                        }
                    }
                ],
                "properties": {"security-severity": "8.0"},
            }
        ],
    )
    path = tmp_path / "scan.sarif"
    path.write_text(json.dumps(sarif))

    alerts = parse_sarif(str(path))
    assert len(alerts) == 1
    a = alerts[0]
    assert a["alert_id"] == "scan-0001"
    assert a["cwe"] == "CWE-89"
    assert a["file_path"] == "app.py"
    assert a["line_range"]["start"] == 10
    assert a["line_range"]["end"] == 15
    assert a["severity"] == "high"


def test_parse_cwe_from_rule_id_fallback(tmp_path):
    """If SARIF rule has no CWE tag, fall back to rule ID mapping."""
    sarif = _minimal_sarif(
        rules=[{"id": "py/reflective-xss", "shortDescription": {"text": "XSS"}}],
        results=[
            {
                "ruleId": "py/reflective-xss",
                "message": {"text": "XSS"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "app.py"},
                            "region": {"startLine": 5},
                        }
                    }
                ],
            }
        ],
    )
    path = tmp_path / "scan.sarif"
    path.write_text(json.dumps(sarif))
    alerts = parse_sarif(str(path))
    assert alerts[0]["cwe"] == "CWE-79"


def test_parse_multiple_results(tmp_path):
    sarif = _minimal_sarif(
        rules=[
            {"id": "py/sql-injection", "shortDescription": {"text": "SQLi"},
             "properties": {"tags": ["external/cwe/cwe-089"]}},
            {"id": "py/command-line-injection", "shortDescription": {"text": "CMDi"},
             "properties": {"tags": ["external/cwe/cwe-078"]}},
        ],
        results=[
            {
                "ruleId": "py/sql-injection",
                "message": {"text": "SQLi"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "a.py"},
                    "region": {"startLine": 1, "endLine": 5},
                }}],
            },
            {
                "ruleId": "py/command-line-injection",
                "message": {"text": "CMDi"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "b.py"},
                    "region": {"startLine": 10, "endLine": 12},
                }}],
            },
        ],
    )
    path = tmp_path / "scan.sarif"
    path.write_text(json.dumps(sarif))
    alerts = parse_sarif(str(path))
    assert len(alerts) == 2
    assert alerts[0]["cwe"] == "CWE-89"
    assert alerts[1]["cwe"] == "CWE-78"


def test_sarif_to_fixtures(tmp_path):
    sarif = _minimal_sarif(
        rules=[{"id": "py/sql-injection", "shortDescription": {"text": "SQLi"},
                "properties": {"tags": ["external/cwe/cwe-089"]}}],
        results=[
            {
                "ruleId": "py/sql-injection",
                "message": {"text": "test"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "app.py"},
                    "region": {"startLine": 1, "endLine": 5},
                }}],
            },
        ],
    )
    sarif_path = tmp_path / "scan.sarif"
    sarif_path.write_text(json.dumps(sarif))

    out_dir = tmp_path / "out"
    paths = sarif_to_fixtures(str(sarif_path), output_dir=str(out_dir))
    assert len(paths) == 1

    fixture = json.loads(out_dir.joinpath("scan-0001.json").read_text())
    assert fixture["alert_id"] == "scan-0001"
    assert fixture["cwe"] == "CWE-89"


def test_severity_mapping(tmp_path):
    sarif = _minimal_sarif(
        rules=[{"id": "test", "shortDescription": {"text": "test"}}],
        results=[
            {
                "ruleId": "test",
                "message": {"text": "low"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "a.py"},
                    "region": {"startLine": 1},
                }}],
                "properties": {"security-severity": "3.0"},
            },
            {
                "ruleId": "test",
                "message": {"text": "critical"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "b.py"},
                    "region": {"startLine": 1},
                }}],
                "properties": {"security-severity": "9.5"},
            },
        ],
    )
    path = tmp_path / "scan.sarif"
    path.write_text(json.dumps(sarif))
    alerts = parse_sarif(str(path))
    assert alerts[0]["severity"] == "low"
    assert alerts[1]["severity"] == "critical"
