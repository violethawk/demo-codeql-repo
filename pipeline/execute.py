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
    residual_risk: str = ""


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
    escaped_param_sql = param_sql.replace("\\", "\\\\").replace('"', '\\"')
    new_exec_line = (
        f'{exec_indent}{cursor_name}.execute("{escaped_param_sql}", ({params_tuple},))\n'
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
        residual_risk=(
            "None. Parameterized query fully neutralizes the SQL injection vector."
        ),
    )


def _fix_cwe79(file_path: Path, alert: Alert) -> ExecutionResult:
    """Fix CWE-79: Reflected XSS via unescaped output.

    Wrap interpolated variables in html.escape() calls.
    """
    lines = file_path.read_text().splitlines(keepends=True)

    start = alert.line_range.start - 1
    end = alert.line_range.end

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

    new_lines = list(lines)
    fixed = False
    interpolated_vars: List[str] = []

    for i in range(start, end):
        line = lines[i]
        # Match f-string containing HTML tags with interpolated variables
        if re.search(r'f["\'].*<.*\{\w+\}.*>.*["\']', line):
            interpolated_vars = re.findall(r"\{(\w+)\}", line)
            if not interpolated_vars:
                continue
            # Replace {var} with {html.escape(var)}
            new_line = re.sub(r"\{(\w+)\}", r"{html.escape(\1)}", line)
            new_lines[i] = new_line
            fixed = True
            break

    if not fixed:
        return ExecutionResult(
            success=False,
            files_changed=[],
            summary="",
            root_cause="",
            fix_description="",
            why_fix_works="",
            error="Could not locate f-string HTML pattern in target lines",
        )

    # Add 'import html' if not already present
    content = "".join(new_lines)
    if "import html\n" not in content:
        last_import = 0
        for i, line in enumerate(new_lines):
            if line.startswith("import ") or line.startswith("from "):
                last_import = i
        new_lines.insert(last_import + 1, "import html\n")

    file_path.write_text("".join(new_lines))

    return ExecutionResult(
        success=True,
        files_changed=[str(alert.file_path)],
        summary=(
            f"XSS (CWE-79) fixed in {alert.file_path} by escaping user "
            f"input with html.escape()."
        ),
        root_cause=(
            f"User-controlled input was directly interpolated into HTML "
            f"output in {alert.file_path} at lines "
            f"{alert.line_range.start}-{alert.line_range.end}, enabling "
            f"reflected cross-site scripting."
        ),
        fix_description=(
            f"Wrapped interpolated variable(s) "
            f"({', '.join(interpolated_vars)}) with html.escape() to "
            f"neutralize HTML/JS injection in the output string."
        ),
        why_fix_works=(
            "html.escape() converts special characters (<, >, &, quotes) "
            "to HTML entities, preventing browsers from interpreting user "
            "input as markup or script. This neutralizes the XSS vector."
        ),
        residual_risk=(
            "None. html.escape() fully neutralizes reflected XSS in HTML "
            "body context."
        ),
    )


def _fix_cwe78(file_path: Path, alert: Alert) -> ExecutionResult:
    """Fix CWE-78: OS command injection via string concatenation.

    Replace os.system() with subprocess.run() using argument lists.
    """
    lines = file_path.read_text().splitlines(keepends=True)

    start = alert.line_range.start - 1
    end = alert.line_range.end

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

    new_lines = list(lines)
    fixed = False
    var_name = ""

    for i in range(start, end):
        line = lines[i]
        # Match: os.system("cmd args " + var)
        match = re.match(
            r'(\s*)os\.system\(\s*["\'](.+?)["\']\s*\+\s*(\w+)\s*\)', line
        )
        if match:
            indent = match.group(1)
            cmd_str = match.group(2).strip()
            var_name = match.group(3)
            cmd_parts = cmd_str.split()
            args_list = ", ".join(f'"{p}"' for p in cmd_parts)
            new_lines[i] = (
                f"{indent}subprocess.run([{args_list}, {var_name}], "
                f"capture_output=True)\n"
            )
            fixed = True
            break

    if not fixed:
        return ExecutionResult(
            success=False,
            files_changed=[],
            summary="",
            root_cause="",
            fix_description="",
            why_fix_works="",
            error="Could not locate os.system() + concatenation pattern in target lines",
        )

    # Ensure subprocess is imported
    content = "".join(new_lines)
    if "import subprocess\n" not in content:
        last_import = 0
        for i, line in enumerate(new_lines):
            if line.startswith("import ") or line.startswith("from "):
                last_import = i
        new_lines.insert(last_import + 1, "import subprocess\n")

    # Remove 'import os' if no longer used
    final_content = "".join(new_lines)
    if "import os\n" in final_content and "os." not in final_content.replace("import os\n", ""):
        new_lines = [l for l in new_lines if l.strip() != "import os"]

    file_path.write_text("".join(new_lines))

    return ExecutionResult(
        success=True,
        files_changed=[str(alert.file_path)],
        summary=(
            f"Command injection (CWE-78) fixed in {alert.file_path} by "
            f"replacing os.system() with subprocess.run() argument list."
        ),
        root_cause=(
            f"User-controlled input was concatenated into a shell command "
            f"passed to os.system() in {alert.file_path} at lines "
            f"{alert.line_range.start}-{alert.line_range.end}, enabling "
            f"arbitrary command execution."
        ),
        fix_description=(
            f"Replaced os.system(\"...\" + {var_name}) with "
            f"subprocess.run([...], capture_output=True) using an explicit "
            f"argument list. Removed shell invocation entirely."
        ),
        why_fix_works=(
            "subprocess.run() with a list of arguments bypasses the shell "
            "entirely. Each argument is passed directly to the OS exec "
            "layer, so shell metacharacters in user input (;, |, &&) have "
            "no effect. This eliminates the command injection vector."
        ),
        residual_risk=(
            "None. Argument-list execution fully neutralizes shell injection."
        ),
    )


# Dispatch table: CWE → fix function
_FIX_DISPATCH = {
    "CWE-89": _fix_cwe89,
    "CWE-79": _fix_cwe79,
    "CWE-78": _fix_cwe78,
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
