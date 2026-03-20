"""Tests for the validate layer."""

from pipeline.validate import validate


def test_valid_python_passes(tmp_path):
    """Valid Python file passes validation."""
    f = tmp_path / "good.py"
    f.write_text("x = 1\n")
    result = validate(str(f))
    assert result.passed is True
    assert any(s.result == "pass" for s in result.steps)


def test_invalid_python_fails(tmp_path):
    """File with syntax error fails validation."""
    f = tmp_path / "bad.py"
    f.write_text("def f(\n")  # syntax error
    result = validate(str(f))
    assert result.passed is False
    assert any(s.result == "fail" for s in result.steps)
