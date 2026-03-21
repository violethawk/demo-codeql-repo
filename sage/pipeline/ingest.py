"""Ingest Layer: Load and validate a CodeQL alert payload from JSON."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class LineRange:
    start: int
    end: int


@dataclass
class Alert:
    alert_id: str
    rule_name: str
    severity: str
    cwe: str
    language: str
    repo_name: str
    default_branch: str
    file_path: str
    line_range: LineRange
    vulnerable_code_snippet: List[str]
    alert_description: str
    security_guidance: str
    owner_team: str
    auto_fix_confidence: Optional[float] = None


def load_alert(path: str) -> Alert:
    """Load a CodeQL alert from a JSON file and return a structured Alert."""
    raw = json.loads(Path(path).read_text())

    required_fields = [
        "alert_id",
        "rule_name",
        "severity",
        "cwe",
        "file_path",
        "line_range",
        "vulnerable_code_snippet",
        "alert_description",
    ]
    missing = [f for f in required_fields if f not in raw]
    if missing:
        raise ValueError(f"Alert JSON missing required fields: {missing}")

    lr = raw["line_range"]
    if "start" not in lr or "end" not in lr:
        raise ValueError("line_range must contain 'start' and 'end'")

    return Alert(
        alert_id=raw["alert_id"],
        rule_name=raw["rule_name"],
        severity=raw["severity"],
        cwe=raw["cwe"],
        language=raw.get("language", ""),
        repo_name=raw.get("repo_name", ""),
        default_branch=raw.get("default_branch", "main"),
        file_path=raw["file_path"],
        line_range=LineRange(start=lr["start"], end=lr["end"]),
        vulnerable_code_snippet=raw["vulnerable_code_snippet"],
        alert_description=raw["alert_description"],
        security_guidance=raw.get("security_guidance", ""),
        owner_team=raw.get("owner_team", ""),
        auto_fix_confidence=raw.get("auto_fix_confidence"),
    )
