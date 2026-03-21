"""Tests verifying CWE-78 command injection fix in demo/app.py."""

import ast
from pathlib import Path
from unittest.mock import patch

import pytest


DEMO_APP_PATH = Path(__file__).resolve().parent.parent / "demo" / "app.py"


class TestStaticAnalysis:
    """Verify the source code no longer contains the vulnerable pattern."""

    def test_no_os_system_call(self):
        """demo/app.py must not call os.system()."""
        source = DEMO_APP_PATH.read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if (
                    isinstance(func, ast.Attribute)
                    and isinstance(func.value, ast.Name)
                    and func.value.id == "os"
                    and func.attr == "system"
                ):
                    pytest.fail("os.system() call found in demo/app.py")

    def test_no_os_import(self):
        """demo/app.py should not import os (no longer needed)."""
        source = DEMO_APP_PATH.read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "os":
                        pytest.fail("'import os' found in demo/app.py")

    def test_subprocess_run_uses_list(self):
        """subprocess.run() must be called with a list argument, not a string."""
        source = DEMO_APP_PATH.read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if (
                    isinstance(func, ast.Attribute)
                    and isinstance(func.value, ast.Name)
                    and func.value.id == "subprocess"
                    and func.attr == "run"
                ):
                    # First positional arg must be a List, not a string
                    assert node.args, "subprocess.run() has no positional args"
                    first_arg = node.args[0]
                    assert isinstance(first_arg, ast.List), (
                        "subprocess.run() first arg must be a list, "
                        f"got {type(first_arg).__name__}"
                    )
                    return
        pytest.fail("No subprocess.run() call found in demo/app.py")


class TestRuntimeBehavior:
    """Verify the /ping endpoint handles input safely at runtime."""

    @patch("subprocess.run")
    def test_ping_endpoint_calls_subprocess_with_list(self, mock_run):
        """The /ping endpoint must invoke subprocess.run with a list."""
        from demo.app import app

        mock_run.return_value = None
        client = app.test_client()
        client.get("/ping?host=8.8.8.8")

        mock_run.assert_called_once()
        args = mock_run.call_args
        cmd_list = args[0][0]  # first positional arg
        assert isinstance(cmd_list, list)
        assert cmd_list == ["ping", "-c", "1", "8.8.8.8"]

    @patch("subprocess.run")
    def test_ping_malicious_input_is_not_shell_expanded(self, mock_run):
        """Shell metacharacters in host must be passed as a literal string."""
        from demo.app import app

        mock_run.return_value = None
        client = app.test_client()
        client.get("/ping?host=127.0.0.1;+rm+-rf+/")

        mock_run.assert_called_once()
        cmd_list = mock_run.call_args[0][0]
        assert isinstance(cmd_list, list)
        # The malicious input is treated as a single argument, not expanded
        assert cmd_list[-1] == "127.0.0.1; rm -rf /"

    @patch("subprocess.run")
    def test_ping_default_host(self, mock_run):
        """Default host is 127.0.0.1 when no host param provided."""
        from demo.app import app

        mock_run.return_value = None
        client = app.test_client()
        client.get("/ping")

        mock_run.assert_called_once()
        cmd_list = mock_run.call_args[0][0]
        assert cmd_list == ["ping", "-c", "1", "127.0.0.1"]
