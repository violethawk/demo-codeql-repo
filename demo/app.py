import os
import sqlite3

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
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor = get_db().cursor()
    cursor.execute(query)
    return jsonify([dict(r) for r in cursor.fetchall()])


@app.route("/search_page")
def search_page():
    user_input = request.args.get("query", "")
    return f"<h1>Results for {user_input}</h1>"


@app.route("/ping")
def ping_host():
    host = request.args.get("host", "127.0.0.1")
    os.system("ping -c 1 " + host)
    return jsonify({"status": "ok"})


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(debug=True)
