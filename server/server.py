# server_flask.py

from flask import Flask, request, jsonify
import os
import json
import hashlib
import hmac

app = Flask(__name__)

# A simple in-memory "database" of users:
USER_DB = {}

# Replace with a secure, randomly generated key for HMACs or session tokens
# For demonstration only; in production, manage secrets via environment variables
SECRET_KEY = b"my_super_secret_key"

def hash_password(password: str) -> str:
    """
    Returns the SHA-256 hash of the input password.
    For stronger security, incorporate salt & stretching (e.g., PBKDF2).
    """
    return hashlib.sha256(password.encode()).hexdigest()

@app.route("/register", methods=["POST"])
def register():
    """
    JSON Body: {
      "username": "alice",
      "password": "p@ssw0rd"
    }
    """
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if username in USER_DB:
        return jsonify({"error": "User already exists"}), 400

    # Store hashed password
    USER_DB[username] = {
        "hashed_pw": hash_password(password),
        "location": None,   # placeholder for location
        "friends": set()    # or store in a DB
    }

    return jsonify({"status": "Registration successful"}), 200

@app.route("/login", methods=["POST"])
def login():
    """
    JSON Body: {
      "username": "alice",
      "password": "p@ssw0rd"
    }
    """
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user_record = USER_DB.get(username)
    if not user_record:
        return jsonify({"error": "Invalid credentials"}), 401

    # Compare stored hash with hash of provided password
    if user_record["hashed_pw"] != hash_password(password):
        return jsonify({"error": "Invalid credentials"}), 401

    # Generate a simple "session token" – for production, consider JWT or robust session management
    # At the very least, sign or HMAC this token to prevent tampering.
    session_token = hmac.new(SECRET_KEY, username.encode(), hashlib.sha256).hexdigest()

    return jsonify({"session_token": session_token}), 200

@app.route("/update_location", methods=["POST"])
def update_location():
    """
    JSON Body: {
      "username": "alice",
      "session_token": "...",
      "x": 12345,
      "y": 67890
    }
    """
    data = request.get_json()
    username = data.get("username")
    session_token = data.get("session_token")
    x_coord = data.get("x")
    y_coord = data.get("y")

    user_record = USER_DB.get(username)
    if not user_record:
        return jsonify({"error": "User not found"}), 404

    # Verify session token (again, you might store tokens in a proper DB or memory)
    expected_token = hmac.new(SECRET_KEY, username.encode(), hashlib.sha256).hexdigest()
    if session_token != expected_token:
        return jsonify({"error": "Unauthorized"}), 401

    # Store the user’s location
    user_record["location"] = (x_coord, y_coord)

    return jsonify({"status": "Location updated"}), 200

# Placeholder for future endpoints, e.g.:
# @app.route("/add_friend", methods=["POST"])
# @app.route("/proximity_check", methods=["POST"])
# etc.

if __name__ == "__main__":
    # Set host='0.0.0.0' to allow external connections, port can be 5000 or any free port
    app.run(host="127.0.0.1", port=5000, debug=True)
