# client.py

import requests
import sys

SERVER_URL = "http://127.0.0.1:5000"

def register_user(username: str, password: str):
    url = f"{SERVER_URL}/register"
    data = {
        "username": username,
        "password": password
    }
    response = requests.post(url, json=data)
    return response.json()

def login_user(username: str, password: str):
    url = f"{SERVER_URL}/login"
    data = {
        "username": username,
        "password": password
    }
    response = requests.post(url, json=data)
    return response.json()

def update_location(username: str, session_token: str, x: int, y: int):
    url = f"{SERVER_URL}/update_location"
    data = {
        "username": username,
        "session_token": session_token,
        "x": x,
        "y": y
    }
    response = requests.post(url, json=data)
    return response.json()

if __name__ == "__main__":
    # Example usage:
    try:
        # 1) Register new user
        reg_resp = register_user("alice", "p@ssw0rd")
        print("Register:", reg_resp)

        # 2) Login user
        login_resp = login_user("alice", "p@ssw0rd")
        print("Login:", login_resp)

        session_token = login_resp.get("session_token", None)
        if not session_token:
            sys.exit("Error: Could not retrieve session_token")

        # 3) Update user location
        loc_resp = update_location("alice", session_token, x=12345, y=67890)
        print("Update location:", loc_resp)

    except KeyboardInterrupt:
        print("Client shutting down.")
        sys.exit(0)
