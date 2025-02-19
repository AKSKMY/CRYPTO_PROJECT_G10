import socket
import threading
import json

users = {}  # {username: {"password": "pass", "friends": set(), "location": (None, None), "inbox": [], "past_grids": set(), "messaged": set()}}

def handle_client(client_socket):
    while True:
        try:
            data = client_socket.recv(1024).decode()
            if not data:
                break
            request = json.loads(data)
            response = process_request(request)
            client_socket.send(json.dumps(response).encode())
        except:
            break
    client_socket.close()

def process_request(request):
    command = request.get("command")

    if command == "register":
        username, password = request["username"], request["password"]
        if username in users:
            return {"status": "error", "message": "User already exists"}
        users[username] = {"password": password, "friends": set(), "location": (None, None), "inbox": [], "past_grids": set(), "messaged": set()}
        return {"status": "success", "message": "Registration successful"}

    elif command == "login":
        username, password = request["username"], request["password"]
        if username in users and users[username]["password"] == password:
            return {"status": "success", "message": "Login successful"}
        return {"status": "error", "message": "Invalid credentials"}

    elif command == "add_friend":
        user, friend = request["user"], request["friend"]
        if friend not in users:
            return {"status": "error", "message": "Friend does not exist"}
        
        # Only allow adding friends if they have messaged each other before
        if friend in users[user]["messaged"] and user in users[friend]["messaged"]:
            users[user]["friends"].add(friend)
            users[friend]["friends"].add(user)
            return {"status": "success", "message": f"{friend} added as a friend"}
        else:
            return {"status": "error", "message": "You can only add users you have messaged before"}

    elif command == "update_location":
        user, x, y = request["user"], request["x"], request["y"]
        new_grid = (x // 1000, y // 1000)
        users[user]["location"] = (x, y)
        users[user]["past_grids"].add(new_grid)  # Track past grid encounters
        return {"status": "success", "message": "Location updated"}

    elif command == "check_proximity":
        user = request["user"]
        ux, uy = users[user]["location"]
        if None in (ux, uy):
            return {"status": "error", "message": "Location not set"}
        user_cell = (ux // 1000, uy // 1000)
        nearby_users = [u for u in users if u != user and users[u]["location"] != (None, None) and (users[u]["location"][0] // 1000, users[u]["location"][1] // 1000) == user_cell]
        return {"status": "success", "nearby_users": nearby_users}

    elif command == "send_message":
        sender, recipient, message = request["sender"], request["recipient"], request["message"]
        if recipient not in users:
            return {"status": "error", "message": "Recipient not found"}
        
        sender_grid = (users[sender]["location"][0] // 1000, users[sender]["location"][1] // 1000)
        recipient_grid = (users[recipient]["location"][0] // 1000, users[recipient]["location"][1] // 1000)

        # Check messaging conditions
        if (
            sender_grid == recipient_grid or  # Same grid
            (sender_grid in users[recipient]["past_grids"] and recipient in users[sender]["messaged"]) or  # Previously encountered and messaged
            recipient in users[sender]["friends"]  # Friends
        ):
            users[recipient]["inbox"].append(f"From {sender}: {message}")
            users[sender]["messaged"].add(recipient)  # Track messaging history
            users[recipient]["messaged"].add(sender)
            return {"status": "success", "message": "Message sent"}
        else:
            return {"status": "error", "message": "Cannot message this user"}

    elif command == "view_inbox":
        user = request["user"]
        inbox = users[user]["inbox"]
        return {"status": "success", "inbox": inbox}

    return {"status": "error", "message": "Unknown command"}

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 5555))
    server.listen(5)
    print("Server started on port 5555")

    while True:
        client_socket, _ = server.accept()
        threading.Thread(target=handle_client, args=(client_socket,)).start()

if __name__ == "__main__":
    start_server()
