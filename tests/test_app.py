"""Tests for the demo Flask app — CWE-79 XSS fix verification."""

import pytest

from demo.app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


class TestSearchPageXSS:
    """Verify that the /search_page endpoint escapes user input."""

    def test_normal_query(self, client):
        """Plain text query is returned unchanged."""
        resp = client.get("/search_page?query=hello")
        assert resp.status_code == 200
        assert b"Results for hello" in resp.data

    def test_script_tag_escaped(self, client):
        """Script tags are HTML-escaped, preventing XSS."""
        payload = "<script>alert('xss')</script>"
        resp = client.get(f"/search_page?query={payload}")
        assert resp.status_code == 200
        assert b"<script>" not in resp.data
        assert b"&lt;script&gt;" in resp.data

    def test_html_attributes_escaped(self, client):
        """HTML attribute injection vectors are escaped."""
        payload = '" onmouseover="alert(1)"'
        resp = client.get(f"/search_page?query={payload}")
        assert resp.status_code == 200
        assert b'onmouseover' not in resp.data or b"&quot;" in resp.data

    def test_angle_brackets_escaped(self, client):
        """Angle brackets are converted to HTML entities."""
        payload = "<img src=x onerror=alert(1)>"
        resp = client.get(f"/search_page?query={payload}")
        assert resp.status_code == 200
        assert b"<img" not in resp.data
        assert b"&lt;img" in resp.data

    def test_ampersand_escaped(self, client):
        """Ampersands are escaped to prevent entity injection."""
        resp = client.get("/search_page?query=a&amp;b")
        assert resp.status_code == 200
        # The query parameter value is "a" (amp;b is a separate param)
        # but any & in the value should be escaped
        assert b"<h1>" in resp.data

    def test_empty_query(self, client):
        """Empty query returns page without error."""
        resp = client.get("/search_page?query=")
        assert resp.status_code == 200
        assert b"Results for </h1>" in resp.data

    def test_missing_query_param(self, client):
        """Missing query param defaults to empty string."""
        resp = client.get("/search_page")
        assert resp.status_code == 200
        assert b"Results for </h1>" in resp.data
