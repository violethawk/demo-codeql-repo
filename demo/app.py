import ipaddress
import os
import re
import sqlite3
import subprocess

from flask import Flask, request, jsonify

app = Flask(__name__)

DATABASE = "users.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/search")
def search_user():
    user_input = request.args.get("name", "")
    cursor = get_db().cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (user_input,))
    return jsonify([dict(r) for r in cursor.fetchall()])


@app.route("/search_page")
def search_page():
    user_input = request.args.get("query", "")
    return f"<h1>Results for {user_input}</h1>"


def _is_valid_host(host: str) -> bool:
    """Validate that host is a legitimate IP address or hostname."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # Allow valid hostnames: alphanumeric, hyphens, dots
    return bool(re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', host))


@app.route("/ping")
def ping_host():
    host = request.args.get("host", "127.0.0.1")
    if not _is_valid_host(host):
        return jsonify({"error": "Invalid host"}), 400
    result = subprocess.run(
        ["ping", "-c", "1", host],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return jsonify({"status": "ok", "output": result.stdout})


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(debug=True)
