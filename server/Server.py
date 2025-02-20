import socket
import threading
import json
import sqlite3
import bcrypt
import sys
import signal
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_key_pair():
    """Generate an RSA private/public key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Serialize private key
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    return private_key_pem

def get_public_key(private_key_pem):
    # Extract public key
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    public_key = private_key.public_key()
    
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("127.0.0.1", 5555))
server.listen(5)

conn = sqlite3.connect("proximity.db", check_same_thread=False)
cursor = conn.cursor()


shutdown = False

# Create tables
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        private_key TEXT NOT NULL
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS locations (
        user_id INTEGER PRIMARY KEY,
        x INTEGER NOT NULL,
        y INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS friendships (
        user_id1 INTEGER,
        user_id2 INTEGER,
        status TEXT NOT NULL CHECK(status IN ('pending', 'accepted')),
        public_key1 TEXT NOT NULL,  -- ✅ Store user_id1's public key
        public_key2 TEXT NOT NULL,  -- ✅ Store user_id2's public key
        PRIMARY KEY (user_id1, user_id2),
        FOREIGN KEY (user_id1) REFERENCES users(id),
        FOREIGN KEY (user_id2) REFERENCES users(id)
    )
''')


conn.commit()
active_clients = {}  # ✅ Dictionary to store online users and their sockets

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode() # decode() to convert bytes to string to store in database

def verify_password(password, password_hash):
    return bcrypt.checkpw(password.encode(), password_hash.encode()) # encode() to convert to bytes for comparison

# Function to fetch user ID by username
def get_user_id(username):
    cursor.execute("SELECT id FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    return user[0] if user else None

#users = {}  # {username: {"password": "pass", "friends": set(), "location": (None, None), "inbox": [], "past_grids": set(), "messaged": set()}}

def handle_client(client_socket):
    username = None
    try:
        while True:
            data = client_socket.recv(1024).decode()
            if not data.strip():
                print("Received empty request")
                break  # Ignore empty requests

            request = json.loads(data)
            command = request.get("command")

            if command == "login":
                username = request["username"]
                active_clients[username] = client_socket  # ✅ Store user in active_clients
                print(f"[SERVER] {username} is now online.")
            response = process_request(request)
            print(f"[DEBUG] Sent response to {username}: {response}")
            client_socket.send(json.dumps(response).encode())
    except Exception as e:
        print(f"[ERROR] Connection error: {str(e)}")

    finally:
        if username and username in active_clients:
            print(f"[SERVER] {username} has disconnected.")
            del active_clients[username]  # ✅ Remove user when they disconnect

        client_socket.close()

def process_request(request):
    command = request.get("command")

    if command == "register":
        #username, password = request["username"], request["password"]
        username = request["username"]
        password = request["password"]
        if not username or not password:
            return {"status": "error", "message": "Username and password cannot be empty"}
        password_hash = hash_password(password)
        private_key = generate_key_pair()
        try:
            cursor.execute("INSERT INTO users (username, password_hash, private_key) VALUES (?, ?, ?)", (username, password_hash, private_key))
            conn.commit()
            return {"status": "error", "message": "Registration successful"}
        except sqlite3.IntegrityError:
            return {"status": "success", "message": "User already exists"}
        except Exception as e:
            return {"status": "error", "message": f"Database error: {str(e)}"}
    
    elif command == "login":
        username, password = request["username"], request["password"]
        cursor.execute("SELECT password_hash FROM users WHERE username=?", (username,))
        user = cursor.fetchone()
        if user and verify_password(password, user[0]):
            return {"status": "success", "message": "Login successful"}
        return {"status": "error", "message": "Invalid credentials"}
    
    elif command == "add_friend":
        user_id = get_user_id(request["user"])
        friend_id = get_user_id(request["friend"])

        if not user_id or not friend_id:
            return {"status": "error", "message": "User not found"}

        # ✅ If no existing request, send a new friend request
        try:
            cursor.execute("INSERT INTO friendships (user_id1, user_id2, status, public_key1, public_key2) VALUES (?, ?, 'pending', '', '')",
                        (user_id, friend_id))
            conn.commit()
            # Check if a pending request already exists from the other user
            cursor.execute("SELECT status FROM friendships WHERE user_id1=? AND user_id2=?", (user_id, friend_id))
            existing_request_1 = cursor.fetchone()
            cursor.execute("SELECT status FROM friendships WHERE user_id1=? AND user_id2=?", (friend_id, user_id))
            existing_request_2 = cursor.fetchone()
            if existing_request_2 == None:
                return {"status": "success", "message": f"Friend request sent to {request['friend']}"}
            if existing_request_1[0] and existing_request_2[0] == "pending":
                # ✅ Fetch both users' public keys
                cursor.execute("SELECT private_key FROM users WHERE id=?", (user_id,))
                user_public_key = get_public_key(cursor.fetchone()[0])

                cursor.execute("SELECT private_key FROM users WHERE id=?", (friend_id,))
                friend_public_key = get_public_key(cursor.fetchone()[0])

                # ✅ Update friendship to accepted and store public keys
                cursor.execute("UPDATE friendships SET status='accepted', public_key1=?, public_key2=? WHERE user_id1=? AND user_id2=?", 
                            (user_public_key, friend_public_key, user_id, friend_id))

                cursor.execute("UPDATE friendships SET status='accepted', public_key1=?, public_key2=? WHERE user_id1=? AND user_id2=?", 
                            (friend_public_key, user_public_key, friend_id, user_id))

                conn.commit()
                return {"status": "success", "message": f"Friendship with {request['friend']} accepted! Public keys exchanged."}
            
        except sqlite3.IntegrityError:
            return {"status": "error", "message": "Friend request already sent or already friends"}

        

        
    elif command == "update_location":
        user_id = get_user_id(request["user"])
        if user_id:
            x, y = request["x"], request["y"]
            cursor.execute("INSERT INTO locations (user_id, x, y) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET x=?, y=?", 
                           (user_id, x, y, x, y))
            conn.commit()
            return {"status": "success", "message": "Location updated"}
        return {"status": "error", "message": "User not found"}

    elif command == "check_proximity":
        user_id = get_user_id(request["user"])
        if not user_id:
            return {"status": "error", "message": "User not found"}

        cursor.execute("SELECT x, y FROM locations WHERE user_id=?", (user_id,))
        user_location = cursor.fetchone()
        if not user_location:
            return {"status": "error", "message": "Location not set"}

        x1, y1 = user_location
        user_cell = (x1 // 1000, y1 // 1000)
        cursor.execute("SELECT users.username FROM locations JOIN users ON locations.user_id = users.id WHERE FLOOR(CAST(x AS INTEGER) / 1000) = ? AND FLOOR(CAST(y AS INTEGER) / 1000) = ?", (user_cell[0], user_cell[1]))
        nearby_users = [row[0] for row in cursor.fetchall() if row[0] != request["user"]]

        return {"status": "success", "nearby_users": nearby_users}
        
    elif command == "send_message":
        sender_id = get_user_id(request["sender"])
        recipient_id = get_user_id(request["recipient"])
        message = request["message"]
        if not sender_id or not recipient_id:
            return {"status": "error", "message": "User not found"}

        # Get sender's location grid
        cursor.execute("SELECT x, y FROM locations WHERE user_id=?", (sender_id,))
        sender_location = cursor.fetchone()
        # Get recipient's location grid
        cursor.execute("SELECT x, y FROM locations WHERE user_id=?", (recipient_id,))
        recipient_location = cursor.fetchone()
        if not sender_location or not recipient_location:
            return {"status": "error", "message": "Location not set"}

        sender_grid = (sender_location[0] // 1000, sender_location[1] // 1000)
        recipient_grid = (recipient_location[0] // 1000, recipient_location[1] // 1000)
        # Check if sender and recipient are friends
        cursor.execute("SELECT 1 FROM friendships WHERE (user_id1=? AND user_id2=? AND status='accepted') OR (user_id1=? AND user_id2=? AND status='accepted')",
                   (sender_id, recipient_id, recipient_id, sender_id))
        are_friends = cursor.fetchone()
        # Check if sender's grid has been visited by recipient in the past
        # Condition checks
        if (sender_grid == recipient_grid) or are_friends:
            # Store message in the database
            if request["recipient"] in active_clients:
                print(f"Recipient socket is {active_clients[request['recipient']]}")
                print(f"Recipient of message is {request['recipient']}, message is {message}")
                recipient_socket = active_clients[request["recipient"]]
                try:
                    recipient_socket.send(json.dumps({"from": request["sender"], "message": message}).encode())
                    return {"status": "success", "message": "Message delivered"}
                except:
                    return {"status": "error", "message": "Failed to send message"}

            return {"status": "error", "message": "Recipient is offline"}

        return {"status": "error", "message": "Cannot message this user"}
    
    elif command == "view_inbox":
        user_id = get_user_id(request["user"])
        if user_id:
            cursor.execute("SELECT users.username, message, timestamp FROM messages JOIN users ON messages.sender_id = users.id WHERE recipient_id=? ORDER BY timestamp DESC", (user_id,))
            messages = [{"from": row[0], "message": row[1], "timestamp": row[2]} for row in cursor.fetchall()]
            return {"status": "success", "inbox": messages}
        return {"status": "error", "message": "User not found"}

    elif command == "remove_friend":
        user_id = get_user_id(request["user"])
        friend_id = get_user_id(request["friend"])

        if not user_id or not friend_id:
            return {"status": "error", "message": "User not found"}

        # Check if they are actually friends
        cursor.execute("SELECT 1 FROM friendships WHERE (user_id1=? AND user_id2=?) OR (user_id1=? AND user_id2=?)",
                    (user_id, friend_id, friend_id, user_id))
        friendship_exists = cursor.fetchone()

        if not friendship_exists:
            return {"status": "error", "message": "You are not friends with this user"}

        # Remove friendship from database
        cursor.execute("DELETE FROM friendships WHERE (user_id1=? AND user_id2=?) OR (user_id1=? AND user_id2=?)",
                    (user_id, friend_id, friend_id, user_id))
        conn.commit()

        return {"status": "success", "message": f"You are no longer friends with {request['friend']}"}

    return {"status": "error", "message": "Unknown command"}
    
def signal_handler(sig, frame):
    """Handles Ctrl+C signal to shut down the server cleanly."""
    global shutdown
    print("\nShutting down server...")

    # Set flag to stop the server loop
    shutdown = True

    # Close server socket
    server.close()
    print("Server socket closed.")

    # Close database connection
    conn.close()
    print("Database connection closed.")

    sys.exit(0)  # Exit cleanly

def start_server():
    print("Server started on port 5555. Press Ctrl+C to stop.")
    signal.signal(signal.SIGINT, signal_handler)
    server.settimeout(1.0)
    try:
        while not shutdown:
            try:
                client_socket, _ = server.accept()
                threading.Thread(target=handle_client, args=(client_socket,)).start()
            except socket.timeout:
                continue
    except OSError:
        pass

if __name__ == "__main__":
    start_server()
