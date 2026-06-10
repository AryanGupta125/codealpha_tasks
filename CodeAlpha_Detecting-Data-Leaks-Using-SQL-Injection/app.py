"""
Flask Web API — SQL Injection Detection & Security System
Run: python app.py
"""

from flask import Flask, request, jsonify, send_from_directory
from security_system import (
    init_db, secure_register, secure_login,
    test_injection, get_users, get_security_logs,
    get_attacks, get_stats
)

app = Flask(__name__, static_folder="static")

# Initialize AWS RDS tables on startup
init_db()


@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json()
    ip = request.remote_addr
    result = secure_register(
        data.get("username", ""),
        data.get("email", ""),
        data.get("password", ""),
        ip
    )
    return jsonify(result)


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json()
    ip = request.remote_addr
    result = secure_login(
        data.get("username", ""),
        data.get("password", ""),
        ip
    )
    return jsonify(result)


@app.route("/api/test-injection", methods=["POST"])
def api_test_injection():
    data = request.get_json()
    ip = request.remote_addr
    result = test_injection(data.get("input", ""), ip)
    return jsonify(result)


@app.route("/api/users", methods=["GET"])
def api_users():
    return jsonify(get_users())


@app.route("/api/logs", methods=["GET"])
def api_logs():
    return jsonify(get_security_logs())


@app.route("/api/attacks", methods=["GET"])
def api_attacks():
    return jsonify(get_attacks())


@app.route("/api/stats", methods=["GET"])
def api_stats():
    return jsonify(get_stats())


if __name__ == "__main__":
    print("\n🔐 Security System starting at http://localhost:5000\n")
    app.run(host="0.0.0.0", port=10000, debug=False)
