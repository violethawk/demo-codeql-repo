"""Tests for the execute layer."""

from pipeline.execute import execute
from pipeline.ingest import Alert, LineRange


def _make_alert(**overrides) -> Alert:
    defaults = dict(
        alert_id="test-001",
        rule_name="Test",
        severity="high",
        cwe="CWE-89",
        language="python",
        repo_name="repo",
        default_branch="main",
        file_path="app.py",
        line_range=LineRange(start=1, end=5),
        vulnerable_code_snippet=["x"],
        alert_description="desc",
        security_guidance="fix",
        owner_team="backend",
    )
    defaults.update(overrides)
    return Alert(**defaults)


class TestCWE89:
    def test_fixes_fstring_sql(self, tmp_path):
        """CWE-89: f-string SQL is replaced with parameterized query."""
        code = '''\
def search():
    user_input = request.args.get("name", "")
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor = db.cursor()
    cursor.execute(query)
    return cursor.fetchall()
'''
        (tmp_path / "app.py").write_text(code)

        alert = _make_alert(
            cwe="CWE-89",
            file_path="app.py",
            line_range=LineRange(start=1, end=6),
        )
        result = execute(alert, str(tmp_path))

        assert result.success is True
        fixed = (tmp_path / "app.py").read_text()
        assert "f\"SELECT" not in fixed
        assert "cursor.execute(\"SELECT * FROM users WHERE name = ?\"" in fixed
        assert "(user_input,)" in fixed

    def test_fixes_percent_format_sql(self, tmp_path):
        """CWE-89: %-format SQL is replaced with parameterized query."""
        code = '''\
def search():
    user_input = request.args.get("name", "")
    query = "SELECT * FROM users WHERE name = '%s'" % user_input
    cursor = db.cursor()
    cursor.execute(query)
    return cursor.fetchall()
'''
        (tmp_path / "app.py").write_text(code)

        alert = _make_alert(
            cwe="CWE-89",
            file_path="app.py",
            line_range=LineRange(start=1, end=6),
        )
        result = execute(alert, str(tmp_path))

        assert result.success is True
        fixed = (tmp_path / "app.py").read_text()
        assert "%s" not in fixed
        assert "?" in fixed
        assert "(user_input,)" in fixed

    def test_fixes_format_method_sql(self, tmp_path):
        """CWE-89: .format() SQL is replaced with parameterized query."""
        code = '''\
def search():
    user_input = request.args.get("name", "")
    query = "SELECT * FROM users WHERE name = '{}'".format(user_input)
    cursor = db.cursor()
    cursor.execute(query)
    return cursor.fetchall()
'''
        (tmp_path / "app.py").write_text(code)

        alert = _make_alert(
            cwe="CWE-89",
            file_path="app.py",
            line_range=LineRange(start=1, end=6),
        )
        result = execute(alert, str(tmp_path))

        assert result.success is True
        fixed = (tmp_path / "app.py").read_text()
        assert ".format(" not in fixed
        assert "?" in fixed

    def test_fixes_concat_sql(self, tmp_path):
        """CWE-89: string concatenation SQL is replaced with parameterized query."""
        code = '''\
def search():
    user_input = request.args.get("name", "")
    query = "SELECT * FROM users WHERE name = " + user_input
    cursor = db.cursor()
    cursor.execute(query)
    return cursor.fetchall()
'''
        (tmp_path / "app.py").write_text(code)

        alert = _make_alert(
            cwe="CWE-89",
            file_path="app.py",
            line_range=LineRange(start=1, end=6),
        )
        result = execute(alert, str(tmp_path))

        assert result.success is True
        fixed = (tmp_path / "app.py").read_text()
        assert "+ user_input" not in fixed
        assert "?" in fixed

    def test_missing_pattern_fails(self, tmp_path):
        """CWE-89: returns failure when no SQL pattern found."""
        (tmp_path / "app.py").write_text("x = 1\ny = 2\n")
        alert = _make_alert(
            cwe="CWE-89",
            file_path="app.py",
            line_range=LineRange(start=1, end=2),
        )
        result = execute(alert, str(tmp_path))
        assert result.success is False


class TestCWE79:
    def test_fixes_xss(self, tmp_path):
        """CWE-79: f-string HTML is wrapped with html.escape()."""
        code = '''\
from flask import request

def search_page():
    user_input = request.args.get("query", "")
    return f"<h1>Results for {user_input}</h1>"
'''
        (tmp_path / "app.py").write_text(code)

        alert = _make_alert(
            cwe="CWE-79",
            file_path="app.py",
            line_range=LineRange(start=3, end=5),
        )
        result = execute(alert, str(tmp_path))

        assert result.success is True
        fixed = (tmp_path / "app.py").read_text()
        assert "html.escape(user_input)" in fixed
        assert "import html" in fixed

    def test_missing_pattern_fails(self, tmp_path):
        """CWE-79: returns failure when HTML pattern not found."""
        (tmp_path / "app.py").write_text("x = 1\n")
        alert = _make_alert(
            cwe="CWE-79",
            file_path="app.py",
            line_range=LineRange(start=1, end=1),
        )
        result = execute(alert, str(tmp_path))
        assert result.success is False


class TestCWE78:
    def test_fixes_command_injection(self, tmp_path):
        """CWE-78: os.system() is replaced with subprocess.run() list."""
        code = '''\
import os
from flask import request

def ping():
    host = request.args.get("host", "127.0.0.1")
    os.system("ping -c 1 " + host)
    return "ok"
'''
        (tmp_path / "app.py").write_text(code)

        alert = _make_alert(
            cwe="CWE-78",
            file_path="app.py",
            line_range=LineRange(start=4, end=7),
        )
        result = execute(alert, str(tmp_path))

        assert result.success is True
        fixed = (tmp_path / "app.py").read_text()
        assert "os.system" not in fixed
        assert "subprocess.run(" in fixed
        assert "import subprocess" in fixed

    def test_missing_pattern_fails(self, tmp_path):
        """CWE-78: returns failure when os.system pattern not found."""
        (tmp_path / "app.py").write_text("x = 1\n")
        alert = _make_alert(
            cwe="CWE-78",
            file_path="app.py",
            line_range=LineRange(start=1, end=1),
        )
        result = execute(alert, str(tmp_path))
        assert result.success is False


def test_unknown_cwe_fails(tmp_path):
    """Unknown CWE returns failure."""
    (tmp_path / "app.py").write_text("x = 1\n")
    alert = _make_alert(
        cwe="CWE-999",
        file_path="app.py",
        line_range=LineRange(start=1, end=1),
    )
    result = execute(alert, str(tmp_path))
    assert result.success is False
    assert "No fix handler" in result.error


def test_missing_file_fails(tmp_path):
    """Missing target file returns failure."""
    alert = _make_alert(file_path="nonexistent.py")
    result = execute(alert, str(tmp_path))
    assert result.success is False
    assert "not found" in result.error
