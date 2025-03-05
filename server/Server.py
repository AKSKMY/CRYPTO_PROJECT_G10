import socket
import threading
import json
import sqlite3
import bcrypt
import sys
import signal
import ssl
import os

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from algorithms.encryption_utils import encrypt_message, decrypt_message

# server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# server.bind(("127.0.0.1", 5555))
# server.listen(5)

# Load SSL certificate and private key (Generate using OpenSSL or self-signed for testing)
server_cert = "server/server_cert.pem"
server_key = "server/server_key.pem"

# Create an SSL context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=server_cert, keyfile=server_key)

# Create and wrap the server socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("127.0.0.1", 5555))
server.listen(5)

# Wrap socket with SSL
server = context.wrap_socket(server, server_side=True)

print("Secure server started on port 5555...")

conn = sqlite3.connect("proximity.db", check_same_thread=False)
cursor = conn.cursor()

shutdown = False

# Create tables
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        public_key TEXT NOT NULL
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
        status TEXT,  -- Can be 'pending', 'acquaintance', or 'accepted'
        public_key1 TEXT,  -- Stores user1's public key
        public_key2 TEXT,  -- Stores user2's public key
        PRIMARY KEY (user_id1, user_id2),
        FOREIGN KEY (user_id1) REFERENCES users(id),
        FOREIGN KEY (user_id2) REFERENCES users(id)
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER,
        recipient_id INTEGER,
        message TEXT NOT NULL,
        sender_grid_x INTEGER,
        sender_grid_y INTEGER,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (sender_id) REFERENCES users(id),
        FOREIGN KEY (recipient_id) REFERENCES users(id)
    )
''')

conn.commit()

def verify_signature(public_key_pem, message, signature_hex):
    """Verify the digital signature of a request."""
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        signature = bytes.fromhex(signature_hex)

        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"Signature verification error: {str(e)}")
        return False

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
    while True:
        try:
            encrypted_data = client_socket.recv(4096).decode()
            if not encrypted_data:
                print("Received empty request. Closing connection.")
                break
            
            # print(f"Raw request received: {data}")  # Debugging log

            # 🔓 Decrypt the request
            decrypted_data = decrypt_message(encrypted_data)
            # print(f"Decrypted request received: {decrypted_data}")
            
            try:
                request = json.loads(decrypted_data)
            except json.JSONDecodeError:
                print("Error: Received invalid JSON format.")
                client_socket.close()
                return
            
            # print(f"Server received request: {request}")
            
            response = process_request(request)

            # 🔒 Encrypt the response before sending
            encrypted_response = encrypt_message(json.dumps(response))
            client_socket.send(encrypted_response.encode())

        except Exception as e:
            print(f"Error handling client request: {e}")
            break  # Ensure socket is closed properly
    client_socket.close()


def process_request(request):
    command = request.get("command")
    username = request.get("user")
    signature = request.get("signature")

    print(f"Command received: {command} by user {username}.\n")

    # ✅ Handle registration requests first (NO signature needed)
    if command == "register":
        username, password, public_key = request["username"], request["password"], request["public_key"]

        if not username or not password or not public_key:
            return {"status": "error", "message": "Username, password, and public key cannot be empty"}

        password_hash = hash_password(password)

        try:
            cursor.execute("INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)", 
                           (username, password_hash, public_key))
            conn.commit()
            return {"status": "success", "message": "Registration successful"}
        except sqlite3.IntegrityError:
            return {"status": "error", "message": "User already exists"}
        except Exception as e:
            return {"status": "error", "message": f"Database error: {str(e)}"}

    # ✅ Handle login requests separately (NO signature verification needed)
    if command == "login":
        username, password = request["username"], request["password"]
        
        # Retrieve user credentials from database
        cursor.execute("SELECT password_hash, public_key FROM users WHERE username=?", (username,))
        user = cursor.fetchone()

        if user and verify_password(password, user[0]):
            return {
                "status": "success",
                "message": "Login successful",
                "public_key": user[1]  # ✅ Return public key for later authentication
            }
        
        return {"status": "error", "message": "Invalid credentials"}

    # ✅ Ensure non-login requests have a valid signature
    if command not in ["login", "register"]:
        # print(f"signature: {signature}")
        if not signature:
            return {"status": "error", "message": "Missing authentication signature"}
        
        username = request["user"]

        # ✅ Retrieve the user's public key
        cursor.execute("SELECT public_key FROM users WHERE username=?", (username,))
        user = cursor.fetchone()

        if not user:
            return {"status": "error", "message": "User not found"}

        public_key_pem = user[0]

        # ✅ Verify the signature
        try:
            request_copy = request.copy()
            del request_copy["signature"]  # Remove signature before verification
            request_json = json.dumps(request_copy)

            if not verify_signature(public_key_pem, request_json, signature):
                return {"status": "error", "message": "Invalid digital signature"}
        except Exception as e:
            print(f"Signature verification error: {e}")
            return {"status": "error", "message": "Signature verification failed"}
    
        if command == "check_message_history":
            user_id = get_user_id(request["user"])
            friend_id = get_user_id(request["friend"])

            if not user_id or not friend_id:
                return {"status": "error", "message": "User or friend not found"}

            # Check if the user has sent a message to the friend
            cursor.execute(
                "SELECT 1 FROM messages WHERE sender_id=? AND recipient_id=? LIMIT 1",
                (user_id, friend_id)
            )
            message_sent = cursor.fetchone()

            if message_sent:
                return {"status": "success", "message": "Message history found"}
            else:
                return {"status": "error", "message": "No message history found"}

        
        elif command == "add_friend":
            user_id = get_user_id(request["user"])
            friend_id = get_user_id(request["friend"])

            if not user_id or not friend_id:
                return {"status": "error", "message": "User not found"}

            # ✅ Check if a friendship record already exists
            cursor.execute(
                "SELECT status FROM friendships WHERE (user_id1=? AND user_id2=?) OR (user_id1=? AND user_id2=?)",
                (user_id, friend_id, friend_id, user_id)
            )
            existing_friendship = cursor.fetchone()
            if existing_friendship:
                friendship_status = existing_friendship[0]

                # ✅ If both users already sent a request, change status to "accepted"
                if friendship_status == "pending":
                    cursor.execute(
                        "UPDATE friendships SET status='accepted' WHERE (user_id1=? AND user_id2=?) OR (user_id1=? AND user_id2=?)",
                        (user_id, friend_id, friend_id, user_id)
                    )
                    conn.commit()

                    # ✅ Fetch and exchange public keys
                    cursor.execute("SELECT public_key FROM users WHERE id=?", (user_id,))
                    user_public_key = cursor.fetchone()[0]
                    cursor.execute("SELECT public_key FROM users WHERE id=?", (friend_id,))
                    friend_public_key = cursor.fetchone()[0]

                    cursor.execute(
                        "UPDATE friendships SET public_key1=?, public_key2=? WHERE (user_id1=? AND user_id2=?) OR (user_id1=? AND user_id2=?)",
                        (user_public_key, friend_public_key, user_id, friend_id, friend_id, user_id)
                    )
                    conn.commit()

                    return {"status": "success", "message": f"Friendship accepted! Public keys exchanged."}

                # ✅ If the existing status is "acquaintance", upgrade it to "pending"
                elif friendship_status == "acquaintance":
                    cursor.execute(
                        "UPDATE friendships SET status='pending' WHERE (user_id1=? AND user_id2=?) OR (user_id1=? AND user_id2=?)",
                        (user_id, friend_id, friend_id, user_id)
                    )
                    conn.commit()
                    return {"status": "success", "message": f"Friend request sent to {request['friend']}."}

                return {"status": "error", "message": "Friend request already sent or already friends."}

            # ✅ If no prior friendship exists, insert a new pending request
            print("here")
            cursor.execute(
            "INSERT INTO friendships (user_id1, user_id2, status) VALUES (?, ?, 'pending')",
            (user_id, friend_id)
            )
            conn.commit()

            return {"status": "success", "message": f"Friend request sent to {request['friend']}."}
            
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
            cursor.execute("SELECT 1 FROM friendships WHERE (user_id1=? AND user_id2=?) OR (user_id1=? AND user_id2=?)",
                        (sender_id, recipient_id, recipient_id, sender_id))
            are_friends = cursor.fetchone()
            # Check if sender's grid has been visited by recipient in the past
            cursor.execute("SELECT 1 FROM messages WHERE sender_id=? AND recipient_id=? AND (sender_grid_x=? AND sender_grid_y=?)",
                        (sender_id, recipient_id, sender_grid[0], sender_grid[1]))
            
            # Condition checks
            if (sender_grid == recipient_grid) or are_friends:
                # Store message in the database
                cursor.execute("INSERT INTO messages (sender_id, recipient_id, message) VALUES (?, ?, ?)", 
                            (sender_id, recipient_id, message))
                conn.commit()

                return {"status": "success", "message": "Message sent"}

            else:
                return {"status": "error", "message": "Cannot message this user as you are not in close proximity"}
        
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

            # In process_request function on the server
        elif command == "clear_messages":
            username = request["username"]
            user_id = get_user_id(username)

            if user_id:
                try:
                    cursor.execute("DELETE FROM messages WHERE recipient_id=?", (user_id,))
                    conn.commit()
                    return {"status": "success", "message": "All messages deleted"}
                except Exception as e:
                    return {"status": "error", "message": f"Error deleting messages: {str(e)}"}
            return {"status": "error", "message": "No messages to delete for the current user!"}



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
