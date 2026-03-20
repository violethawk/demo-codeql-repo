"""SARIF Ingestion: Convert CodeQL SARIF output into pipeline alert fixtures.

CodeQL produces SARIF 2.1.0 JSON. This module parses it and emits one
alert JSON file per result, ready for the pipeline to consume.

Usage:
    from pipeline.sarif import parse_sarif
    alerts = parse_sarif("results.sarif")

    from pipeline.sarif import sarif_to_fixtures
    paths = sarif_to_fixtures("results.sarif", output_dir="fixtures/")
"""

import json
import re
from pathlib import Path

# Map CodeQL rule IDs to CWEs. CodeQL rules embed CWE tags in their
# metadata, but the mapping is also maintained here as a fallback for
# common rules.
_RULE_CWE_MAP: dict[str, str] = {
    "py/sql-injection": "CWE-89",
    "py/reflective-xss": "CWE-79",
    "py/command-line-injection": "CWE-78",
    "js/sql-injection": "CWE-89",
    "js/xss": "CWE-79",
    "js/command-line-injection": "CWE-78",
    "java/sql-injection": "CWE-89",
    "java/xss": "CWE-79",
    "java/command-line-injection": "CWE-78",
    "rb/sql-injection": "CWE-89",
    "rb/reflective-xss": "CWE-79",
    "go/sql-injection": "CWE-89",
}

# Map numeric CVSS-style severity to text
_SEVERITY_MAP = {
    range(0, 4): "low",
    range(4, 7): "medium",
    range(7, 9): "high",
    range(9, 11): "critical",
}


def _numeric_severity(score: float) -> str:
    for r, label in _SEVERITY_MAP.items():
        if int(score) in r:
            return label
    return "high"


def _normalize_cwe(cwe: str) -> str:
    """Normalize CWE identifiers: CWE-089 -> CWE-89, CWE-0079 -> CWE-79."""
    match = re.match(r"(CWE-)0*(\d+)", cwe, re.IGNORECASE)
    if match:
        return f"CWE-{match.group(2)}"
    return cwe


def _extract_cwe(rule: dict, rule_id: str) -> str:
    """Extract CWE from rule metadata, falling back to the hardcoded map."""
    # Check rule properties for CWE tags
    props = rule.get("properties", {})
    tags = props.get("tags", [])
    for tag in tags:
        match = re.match(r"external/cwe/(cwe-\d+)", tag, re.IGNORECASE)
        if match:
            return _normalize_cwe(match.group(1).upper())

    # Check rule.relationships for CWE taxonomies
    for rel in rule.get("relationships", []):
        target = rel.get("target", {})
        tid = target.get("id", "")
        if tid.startswith("CWE-"):
            return _normalize_cwe(tid)

    # Fallback to hardcoded map
    return _RULE_CWE_MAP.get(rule_id, "")


def _extract_snippet(result: dict) -> list[str]:
    """Extract code snippet from SARIF result."""
    snippets = []
    for loc in result.get("locations", []):
        phys = loc.get("physicalLocation", {})
        region = phys.get("region", {})
        snippet = region.get("snippet", {})
        text = snippet.get("text", "")
        if text:
            snippets.extend(line for line in text.strip().splitlines() if line.strip())
    # Also check codeFlows
    for flow in result.get("codeFlows", []):
        for thread in flow.get("threadFlows", []):
            for step in thread.get("locations", []):
                loc = step.get("location", {})
                phys = loc.get("physicalLocation", {})
                region = phys.get("region", {})
                snippet = region.get("snippet", {})
                text = snippet.get("text", "")
                if text:
                    snippets.extend(
                        line for line in text.strip().splitlines() if line.strip()
                    )
    return snippets or ["(snippet not available in SARIF)"]


def parse_sarif(sarif_path: str) -> list[dict]:
    """Parse a SARIF file and return a list of alert dicts.

    Each dict matches the schema expected by pipeline.ingest.load_alert().
    Alert IDs are namespaced by the SARIF filename to prevent collisions
    when processing multiple scan files.
    """
    raw = json.loads(Path(sarif_path).read_text())
    alerts: list[dict] = []

    # Namespace prefix from filename (e.g., "results.sarif" → "results")
    prefix = Path(sarif_path).stem.replace(" ", "-")

    for run in raw.get("runs", []):
        tool = run.get("tool", {}).get("driver", {})
        rules_by_id: dict[str, dict] = {}
        for rule in tool.get("rules", []):
            rules_by_id[rule["id"]] = rule

        for i, result in enumerate(run.get("results", [])):
            rule_id = result.get("ruleId", "")
            rule = rules_by_id.get(rule_id, {})

            # Location
            locations = result.get("locations", [])
            file_path = ""
            start_line = 0
            end_line = 0
            if locations:
                phys = locations[0].get("physicalLocation", {})
                artifact = phys.get("artifactLocation", {})
                file_path = artifact.get("uri", "")
                region = phys.get("region", {})
                start_line = region.get("startLine", 0)
                end_line = region.get("endLine", start_line)

            # CWE
            cwe = _extract_cwe(rule, rule_id)

            # Severity
            severity = "high"
            props = result.get("properties", rule.get("properties", {}))
            sec_sev = props.get("security-severity")
            if sec_sev is not None:
                severity = _numeric_severity(float(sec_sev))

            # Message
            message = result.get("message", {}).get("text", "")

            # Guidance from rule help
            guidance = ""
            help_obj = rule.get("help", {})
            if isinstance(help_obj, dict):
                guidance = help_obj.get("text", "")
            elif isinstance(help_obj, str):
                guidance = help_obj
            if not guidance:
                guidance = rule.get("shortDescription", {}).get("text", "")

            alert = {
                "alert_id": f"{prefix}-{i+1:04d}",
                "rule_name": rule.get("shortDescription", {}).get("text", "")
                or rule.get("name", "")
                or rule_id,
                "severity": severity,
                "cwe": cwe,
                "language": "",
                "repo_name": "",
                "default_branch": "main",
                "file_path": file_path,
                "line_range": {"start": start_line, "end": end_line},
                "vulnerable_code_snippet": _extract_snippet(result),
                "alert_description": message,
                "security_guidance": guidance,
                "owner_team": "",
                "auto_fix_confidence": None,
            }
            alerts.append(alert)

    return alerts


def sarif_to_fixtures(
    sarif_path: str,
    output_dir: str = "fixtures",
) -> list[str]:
    """Parse a SARIF file and write each result as a fixture JSON file.

    Returns the list of written file paths.
    """
    alerts = parse_sarif(sarif_path)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    paths: list[str] = []
    for alert in alerts:
        filename = f"{alert['alert_id']}.json"
        path = out_dir / filename
        path.write_text(json.dumps(alert, indent=2) + "\n")
        paths.append(str(path))

    return paths
