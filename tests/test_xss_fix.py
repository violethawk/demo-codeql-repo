"""Tests for CWE-79 reflected XSS fix in demo/app.py."""

import html
import sys
from pathlib import Path

import pytest

# Ensure the demo package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "demo"))

from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_search_page_escapes_html_tags(client):
    """Malicious <script> tags must be escaped in the response."""
    resp = client.get("/search_page?query=<script>alert(1)</script>")
    assert resp.status_code == 200
    body = resp.data.decode()
    assert "<script>" not in body
    assert "&lt;script&gt;" in body


def test_search_page_escapes_attributes(client):
    """Injection via HTML attributes must be escaped."""
    payload = '" onmouseover="alert(1)"'
    resp = client.get(f"/search_page?query={payload}")
    body = resp.data.decode()
    assert 'onmouseover' not in body or '&quot;' in body


def test_search_page_normal_input(client):
    """Normal, safe input should render correctly."""
    resp = client.get("/search_page?query=hello+world")
    assert resp.status_code == 200
    body = resp.data.decode()
    assert "hello world" in body


def test_search_page_empty_query(client):
    """Empty query should return a valid page."""
    resp = client.get("/search_page?query=")
    assert resp.status_code == 200
    body = resp.data.decode()
    assert "<h1>Results for </h1>" in body


def test_search_page_escapes_ampersand(client):
    """Ampersands in input must be escaped."""
    resp = client.get("/search_page?query=a%26b")
    body = resp.data.decode()
    assert "&amp;" in body


def test_html_escape_used_directly():
    """Verify html.escape handles the XSS payload correctly."""
    malicious = '<script>alert("XSS")</script>'
    escaped = html.escape(malicious)
    assert "<" not in escaped
    assert "&lt;script&gt;" in escaped
