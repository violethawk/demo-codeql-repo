"""Validation Layer: Run deterministic checks on the fixed code."""

import shutil
import subprocess
from dataclasses import dataclass
from typing import List


@dataclass
class ValidationStep:
    command: str
    result: str  # "pass" or "fail"


@dataclass
class ValidationResult:
    passed: bool
    steps: List[ValidationStep]


def validate(file_path: str) -> ValidationResult:
    """Run validation steps against the target file.

    1. python -m py_compile <file>
    2. ruff check <file> (if ruff is installed)
    """
    steps: List[ValidationStep] = []
    all_passed = True

    # Step 1: py_compile
    cmd_compile = f"python -m py_compile {file_path}"
    try:
        subprocess.run(
            ["python", "-m", "py_compile", file_path],
            capture_output=True,
            text=True,
            check=True,
        )
        steps.append(ValidationStep(command=cmd_compile, result="pass"))
    except subprocess.CalledProcessError:
        steps.append(ValidationStep(command=cmd_compile, result="fail"))
        all_passed = False

    # Step 2: ruff (if available)
    if shutil.which("ruff"):
        cmd_ruff = f"ruff check {file_path}"
        try:
            subprocess.run(
                ["ruff", "check", file_path],
                capture_output=True,
                text=True,
                check=True,
            )
            steps.append(ValidationStep(command=cmd_ruff, result="pass"))
        except subprocess.CalledProcessError:
            steps.append(ValidationStep(command=cmd_ruff, result="fail"))
            all_passed = False

    return ValidationResult(passed=all_passed, steps=steps)
