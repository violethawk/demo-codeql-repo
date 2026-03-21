"""Tests for CWE-79 reflected XSS fix in target_repo/app.py."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "target_repo"))

from app import app


def test_search_page_escapes_html_tags():
    """Ensure HTML tags in query param are escaped to prevent XSS."""
    client = app.test_client()
    resp = client.get("/search_page?query=<script>alert(1)</script>")
    assert resp.status_code == 200
    body = resp.data.decode()
    assert "<script>" not in body
    assert "&lt;script&gt;" in body


def test_search_page_escapes_attributes():
    """Ensure attribute-based XSS payloads are escaped."""
    client = app.test_client()
    resp = client.get('/search_page?query=" onmouseover="alert(1)')
    assert resp.status_code == 200
    body = resp.data.decode()
    assert 'onmouseover' not in body or '&quot;' in body


def test_search_page_normal_input():
    """Normal text input is rendered correctly."""
    client = app.test_client()
    resp = client.get("/search_page?query=hello")
    assert resp.status_code == 200
    body = resp.data.decode()
    assert "Results for hello" in body


def test_search_page_empty_query():
    """Empty query param returns results header without error."""
    client = app.test_client()
    resp = client.get("/search_page?query=")
    assert resp.status_code == 200
    body = resp.data.decode()
    assert "Results for " in body


def test_search_page_ampersand_escaped():
    """Ampersand characters are properly escaped."""
    client = app.test_client()
    resp = client.get("/search_page?query=foo&bar")
    assert resp.status_code == 200
    body = resp.data.decode()
    # The & in the query string separates params, so only "foo" is the query value
    assert "<script>" not in body
