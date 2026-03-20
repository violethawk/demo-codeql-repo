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
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(query)
    results = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(results)


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(debug=True)
