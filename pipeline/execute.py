"""Execution Layer: Apply minimal safe fix for eligible vulnerabilities."""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List

from pipeline.ingest import Alert


@dataclass
class ExecutionResult:
    success: bool
    files_changed: List[str]
    summary: str
    root_cause: str
    fix_description: str
    why_fix_works: str
    error: str = ""


def _fix_cwe89(file_path: Path, alert: Alert) -> ExecutionResult:
    """Fix CWE-89: SQL injection via string interpolation.

    Replace f-string / format-string SQL with parameterized queries.
    """
    lines = file_path.read_text().splitlines(keepends=True)

    start = alert.line_range.start - 1  # 0-indexed
    end = alert.line_range.end  # exclusive

    if start < 0 or end > len(lines):
        return ExecutionResult(
            success=False,
            files_changed=[],
            summary="",
            root_cause="",
            fix_description="",
            why_fix_works="",
            error=f"Line range {alert.line_range.start}-{alert.line_range.end} "
            f"out of bounds for file with {len(lines)} lines",
        )

    # Scan the target region for the f-string SQL pattern
    new_lines = list(lines)
    query_var_line_idx = None
    execute_line_idx = None
    query_var_name = None

    for i in range(start, end):
        line = lines[i]

        # Match: variable = f"SELECT ... {user_var} ..."
        fstring_match = re.match(
            r"(\s*)(\w+)\s*=\s*f[\"'](.+?)[\"']\s*$", line
        )
        if fstring_match:
            query_var_name = fstring_match.group(2)
            sql_template = fstring_match.group(3)

            # Extract interpolated variable names
            interpolated_vars = re.findall(r"\{(\w+)\}", sql_template)
            if not interpolated_vars:
                continue

            # Build parameterized SQL: replace '{var}' with ?
            param_sql = re.sub(r"'\{(\w+)\}'", "?", sql_template)
            # Also handle without quotes: {var} → ?
            param_sql = re.sub(r"\{(\w+)\}", "?", param_sql)

            query_var_line_idx = i
            # We'll remove this line and fold into the execute call
            continue

        # Match: cursor.execute(query_var)
        if query_var_name:
            exec_match = re.match(
                r"(\s*)(\w+)\.execute\(\s*" + re.escape(query_var_name) + r"\s*\)",
                line,
            )
            if exec_match:
                execute_line_idx = i
                break

    if query_var_line_idx is None or execute_line_idx is None:
        return ExecutionResult(
            success=False,
            files_changed=[],
            summary="",
            root_cause="",
            fix_description="",
            why_fix_works="",
            error="Could not locate f-string SQL + execute pattern in target lines",
        )

    # Re-extract what we need from the matched f-string line
    fstring_line = lines[query_var_line_idx]
    fstring_match = re.match(
        r"(\s*)(\w+)\s*=\s*f[\"'](.+?)[\"']\s*$", fstring_line
    )
    if not fstring_match:
        return ExecutionResult(
            success=False,
            files_changed=[],
            summary="",
            root_cause="",
            fix_description="",
            why_fix_works="",
            error="Failed to re-parse f-string line",
        )

    sql_template = fstring_match.group(3)
    interpolated_vars = re.findall(r"\{(\w+)\}", sql_template)

    param_sql = re.sub(r"'\{(\w+)\}'", "?", sql_template)
    param_sql = re.sub(r"\{(\w+)\}", "?", param_sql)

    # Build the replacement execute line
    exec_line = lines[execute_line_idx]
    exec_match = re.match(
        r"(\s*)(\w+)\.execute\(\s*" + re.escape(query_var_name) + r"\s*\)",
        exec_line,
    )
    if not exec_match:
        return ExecutionResult(
            success=False,
            files_changed=[],
            summary="",
            root_cause="",
            fix_description="",
            why_fix_works="",
            error="Failed to re-parse execute line",
        )

    exec_indent = exec_match.group(1)
    cursor_name = exec_match.group(2)
    params_tuple = ", ".join(interpolated_vars)
    new_exec_line = (
        f'{exec_indent}{cursor_name}.execute("{param_sql}", ({params_tuple},))\n'
    )

    # Remove the query variable assignment line, replace execute line
    new_lines[execute_line_idx] = new_exec_line
    new_lines[query_var_line_idx] = ""  # remove f-string line

    file_path.write_text("".join(new_lines))

    return ExecutionResult(
        success=True,
        files_changed=[str(alert.file_path)],
        summary=(
            f"SQL injection (CWE-89) fixed in {alert.file_path} by replacing "
            f"f-string SQL with parameterized query."
        ),
        root_cause=(
            f"User-controlled input was directly interpolated into a SQL query "
            f"via f-string in {alert.file_path} at lines "
            f"{alert.line_range.start}-{alert.line_range.end}, allowing "
            f"arbitrary SQL injection."
        ),
        fix_description=(
            f"Removed f-string query construction and replaced "
            f"cursor.execute({query_var_name}) with a parameterized call: "
            f'{cursor_name}.execute("{param_sql}", ({params_tuple},)). '
            f"Net change: 1 file, removed intermediate query variable."
        ),
        why_fix_works=(
            "Parameterized queries separate SQL code from data. The ? "
            "placeholder ensures user input is treated strictly as a data "
            "value by the database driver, never as executable SQL. This "
            "eliminates the injection vector regardless of input content."
        ),
    )


# Dispatch table: CWE → fix function
_FIX_DISPATCH = {
    "CWE-89": _fix_cwe89,
}


def execute(alert: Alert, repo_root: str) -> ExecutionResult:
    """Apply the minimal safe fix for the given alert."""
    fix_fn = _FIX_DISPATCH.get(alert.cwe)
    if fix_fn is None:
        return ExecutionResult(
            success=False,
            files_changed=[],
            summary="",
            root_cause="",
            fix_description="",
            why_fix_works="",
            error=f"No fix handler registered for {alert.cwe}",
        )

    target_file = Path(repo_root) / alert.file_path
    if not target_file.exists():
        return ExecutionResult(
            success=False,
            files_changed=[],
            summary="",
            root_cause="",
            fix_description="",
            why_fix_works="",
            error=f"Target file not found: {target_file}",
        )

    return fix_fn(target_file, alert)
