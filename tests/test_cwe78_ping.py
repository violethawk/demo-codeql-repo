"""Tests for CWE-78 command injection fix in target_repo/app.py."""

import subprocess
from unittest.mock import patch

import pytest

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'target_repo'))

from app import app, _is_valid_host


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


class TestIsValidHost:
    """Unit tests for the _is_valid_host helper."""

    def test_valid_ipv4(self):
        assert _is_valid_host("127.0.0.1") is True

    def test_valid_ipv6(self):
        assert _is_valid_host("::1") is True

    def test_valid_hostname(self):
        assert _is_valid_host("example.com") is True

    def test_valid_subdomain(self):
        assert _is_valid_host("sub.example.com") is True

    def test_rejects_shell_semicolon(self):
        assert _is_valid_host("127.0.0.1; rm -rf /") is False

    def test_rejects_shell_pipe(self):
        assert _is_valid_host("127.0.0.1 | cat /etc/passwd") is False

    def test_rejects_shell_backticks(self):
        assert _is_valid_host("`whoami`") is False

    def test_rejects_dollar_subshell(self):
        assert _is_valid_host("$(cat /etc/passwd)") is False

    def test_rejects_ampersand(self):
        assert _is_valid_host("127.0.0.1 && echo pwned") is False

    def test_rejects_newline(self):
        assert _is_valid_host("127.0.0.1\nwhoami") is False

    def test_rejects_empty_string(self):
        assert _is_valid_host("") is False


class TestPingEndpoint:
    """Integration tests for the /ping endpoint."""

    @patch("app.subprocess.run")
    def test_ping_default_host(self, mock_run, client):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["ping", "-c", "1", "127.0.0.1"],
            returncode=0,
            stdout="PING 127.0.0.1: 1 packets transmitted, 1 received\n",
            stderr="",
        )
        resp = client.get("/ping")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        mock_run.assert_called_once_with(
            ["ping", "-c", "1", "127.0.0.1"],
            capture_output=True,
            text=True,
            timeout=10,
        )

    @patch("app.subprocess.run")
    def test_ping_valid_host(self, mock_run, client):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["ping", "-c", "1", "8.8.8.8"],
            returncode=0,
            stdout="ok\n",
            stderr="",
        )
        resp = client.get("/ping?host=8.8.8.8")
        assert resp.status_code == 200
        mock_run.assert_called_once_with(
            ["ping", "-c", "1", "8.8.8.8"],
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_ping_rejects_command_injection_semicolon(self, client):
        resp = client.get("/ping?host=127.0.0.1;+rm+-rf+/")
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "Invalid host"

    def test_ping_rejects_command_injection_pipe(self, client):
        resp = client.get("/ping?host=127.0.0.1+|+cat+/etc/passwd")
        assert resp.status_code == 400

    def test_ping_rejects_command_injection_backtick(self, client):
        resp = client.get("/ping?host=`whoami`")
        assert resp.status_code == 400

    def test_ping_rejects_command_injection_subshell(self, client):
        resp = client.get("/ping?host=$(id)")
        assert resp.status_code == 400

    def test_ping_uses_subprocess_not_os_system(self):
        """Verify the source code no longer contains os.system for ping."""
        import inspect
        from app import ping_host
        source = inspect.getsource(ping_host)
        assert "os.system" not in source
        assert "subprocess.run" in source

    def test_ping_uses_list_args_not_shell_string(self):
        """Verify subprocess.run is called with a list, not a shell string."""
        import inspect
        from app import ping_host
        source = inspect.getsource(ping_host)
        assert 'shell=True' not in source
        assert '["ping"' in source
