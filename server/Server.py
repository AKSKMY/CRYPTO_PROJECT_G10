import socket
import threading
import json
import sqlite3
import bcrypt
import sys
import signal
import select
import os
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

friendship_lock = threading.Lock()  # Global lock

def is_socket_valid(sock):
    readable, writable, _ = select.select([sock], [sock], [], 0)
    return bool(readable or writable)
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("127.0.0.1", 5555))
server.listen(5)

conn = sqlite3.connect("proximity.db", check_same_thread=False)
cursor = conn.cursor()

active_clients = {}  

shutdown = False

# Create tables
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        public_key TEXT NOT NULL
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

# Function to fetch user ID by username
def get_user_id(username):
    cursor.execute("SELECT id FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    return user[0] if user else None

def handle_client(client_socket):
    while True:
        try:
            data = client_socket.recv(4096).decode().strip()  # Strip spaces and newlines
            if not data:
                break
            request = json.loads(data)
            try:
                print(f"Server received command: '{request['command']}' from user '{request['username']}'")
            except:
                print(f"Server received command request: {request['command']}")
            if request["command"] == "login":
                username = request["username"]
                active_clients[username] = client_socket  # ✅ Store active client
                print(f"[SERVER] {username} is now online.")

            response = process_request(request)
            client_socket.send(json.dumps(response).encode())
        except:
            break
    client_socket.close()

def generate_aes_key():
    """Generate a random 256-bit AES key."""
    return os.urandom(32)  # 256-bit key

def encrypt_aes(data, aes_key):
    """Encrypts data using AES."""
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Padding (AES requires input to be a multiple of 16 bytes)
    padded_data = data + (16 - len(data) % 16) * " "
    ciphertext = encryptor.update(padded_data.encode()) + encryptor.finalize()

    # ✅ Generate HMAC using SHA256
    hmac_key = aes_key  # Using the AES key as HMAC key (or derive separately)
    hmac_obj = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256)
    hmac_digest = hmac_obj.digest()

    return iv + ciphertext + hmac_digest  # Return IV + Encrypted Data

def encrypt_aes_key(aes_key, rsa_public_key):
    """Encrypt AES key using recipient's RSA public key."""
    return rsa_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def process_request(request):
    command = request.get("command")
    signature = request.get("signature")
    if signature:
        signable_request = {k: v for k, v in request.items() if k not in ["user2", "signature"]}
        request_string = json.dumps(signable_request, separators=(',', ':'))
        username = request.get("username")
        cursor.execute("SELECT public_key FROM users WHERE username=?", (username,))
        user_data = cursor.fetchone()
        if not user_data:
            return {"status": "error", "message": "User not found"}
        user_public_key = serialization.load_pem_public_key(user_data[0].encode())
        try:
            user_public_key.verify(bytes.fromhex(signature), request_string.encode(), padding.PSS(mgf = padding.MGF1(hashes.SHA256()), salt_length = padding.PSS.MAX_LENGTH), hashes.SHA256())
            print("Verification successful")
        except InvalidSignature :
            return {"status": "error", "message": "Signature verification failed"}
        
    if command == "register":
        username, password_hash, public_key, salt = request["username"], request["password_hash"], request["public_key"], request["salt"]
        
        if not username or not password_hash or not salt or not public_key:
            return {"status": "error", "message": "Username, password, and public key cannot be empty"}

        try:
            cursor.execute("INSERT INTO users (username, password_hash, salt, public_key) VALUES (?, ?, ?, ?)", 
                           (username, password_hash, salt, public_key))
            conn.commit()
            return {"status": "success", "message": "Registration successful. Please login now."}
        except sqlite3.IntegrityError:
            return {"status": "error", "message": "User already exists"}
        except Exception as e:
            return {"status": "error", "message": f"Database error: {str(e)}"}

    elif command == "get_salt":
        username = request["username"]
        
        cursor.execute("SELECT salt FROM users WHERE username=?", (username,))
        result = cursor.fetchone()

        if result:
            return {"status": "success", "salt": result[0]}  # ✅ Send the stored salt

        return {"status": "error", "message": "User not found"}

    elif command == "login":
        username, password_hash = request["username"], request["password_hash"]
        
        # Retrieve user credentials from database
        cursor.execute("SELECT password_hash, public_key FROM users WHERE username=?", (username,))
        user = cursor.fetchone()

        if user and user[0]==password_hash:
            return {
                "status": "success",
                "message": "Login successful",
                "public_key": user[1]  # Include the public key in the response
            }
        
        return {"status": "error", "message": "Invalid credentials"}


    elif command == "get_public_key":
        username = request["user"]
        recipient = request["recipient"]
        cursor.execute("SELECT public_key FROM users WHERE username=?", (recipient,))
        recipient_public_key_string = cursor.fetchone()

        if recipient_public_key_string and recipient_public_key_string[0]:
            cursor.execute("SELECT public_key FROM users WHERE username=?", (username,))
            user_public_key_string = cursor.fetchone()
            user_public_key = serialization.load_pem_public_key(user_public_key_string[0].encode())
            aes_key = generate_aes_key()

            # ✅ Encrypt the recipient’s public key with AES
            encrypted_recipient_public_key = encrypt_aes(recipient_public_key_string[0], aes_key)

            # ✅ Encrypt the AES key with the user’s RSA public key
            encrypted_aes_key = encrypt_aes_key(aes_key, user_public_key)
            return {"status": "success", "encrypted_aes_key": encrypted_aes_key.hex(), "encrypted_public_key": encrypted_recipient_public_key.hex(), "message": "Encrypted keys sent."}
        
        return {"status": "error", "message": "User not found or no public key stored"}


    elif command == "add_friend":
        with friendship_lock:  # Prevent race condition
            user_id = get_user_id(request["username"])
            friend_id = get_user_id(request["friend"])

            cursor.execute("SELECT public_key FROM users WHERE id=?", (user_id,))
            user_public_key = cursor.fetchone()[0]
            user_public_key_pem = serialization.load_pem_public_key(user_public_key.encode())

            aes_key = generate_aes_key()

            if not user_id or not friend_id:
                encrypted_message = encrypt_aes("User not found.", aes_key)
                encrypted_aes_key = encrypt_aes_key(aes_key, user_public_key_pem)

                hmac_digest = hmac.new(aes_key, encrypted_message[:-32], hashlib.sha256).digest().hex()
                # print(f"[SERVER DEBUG] Sent HMAC (hex): {hmac_digest}") 

                return {"status": "error", "encrypted_aes_key": encrypted_aes_key.hex(), "encrypted_message": encrypted_message.hex(), "hmac": hmac_digest}

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

                    cursor.execute("SELECT public_key FROM users WHERE id=?", (friend_id,))
                    friend_public_key = cursor.fetchone()[0]

                    cursor.execute(
                        "UPDATE friendships SET public_key1=?, public_key2=? WHERE (user_id1=? AND user_id2=?) OR (user_id1=? AND user_id2=?)",
                        (user_public_key, friend_public_key, user_id, friend_id, friend_id, user_id)
                    )
                    conn.commit()

                    encrypted_message = encrypt_aes("Friendship accepted! Public keys exchanged.", aes_key)
                    encrypted_aes_key = encrypt_aes_key(aes_key, user_public_key_pem)

                    hmac_digest = hmac.new(aes_key, encrypted_message[:-32], hashlib.sha256).digest().hex()

                    return {"status": "success", "encrypted_aes_key": encrypted_aes_key.hex(), "encrypted_message": encrypted_message.hex(), "hmac": hmac_digest}
            
                encrypted_message = encrypt_aes("Friend request already sent or already friends.", aes_key)
                encrypted_aes_key = encrypt_aes_key(aes_key, user_public_key_pem)

                hmac_digest = hmac.new(aes_key, encrypted_message[:-32], hashlib.sha256).digest().hex()

                return {"status": "error", "encrypted_aes_key": encrypted_aes_key.hex(), "encrypted_message": encrypted_message.hex(), "hmac": hmac_digest}

            # ✅ If no prior friendship exists, insert a new pending request
            cursor.execute(
            "INSERT INTO friendships (user_id1, user_id2, status) VALUES (?, ?, 'pending')",
            (user_id, friend_id)
            )
            conn.commit()

            encrypted_message = encrypt_aes(f"Friend request sent to {request['friend']}.", aes_key)
            encrypted_aes_key = encrypt_aes_key(aes_key, user_public_key_pem)

            hmac_digest = hmac.new(aes_key, encrypted_message[:-32], hashlib.sha256).digest().hex()

            return {"status": "error", "encrypted_aes_key": encrypted_aes_key.hex(), "encrypted_message": encrypted_message.hex(), "hmac": hmac_digest}
        
    elif command == "update_location":
        user_id = get_user_id(request["username"])

        user_public_key = cursor.fetchone()[0]
        user_public_key_pem = serialization.load_pem_public_key(user_public_key.encode())

        aes_key = generate_aes_key()

        if user_id:
            x, y = request["x"], request["y"]
            cursor.execute("INSERT INTO locations (user_id, x, y) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET x=?, y=?", 
                           (user_id, x, y, x, y))
            conn.commit()

            encrypted_message = encrypt_aes("Location updated.", aes_key)
            encrypted_aes_key = encrypt_aes_key(aes_key, user_public_key_pem)

            hmac_digest = hmac.new(aes_key, encrypted_message[:-32], hashlib.sha256).digest().hex()
            return {"status": "error", "encrypted_aes_key": encrypted_aes_key.hex(), "encrypted_message": encrypted_message.hex(), "hmac": hmac_digest}
        
        encrypted_message = encrypt_aes("User not found.", aes_key)
        encrypted_aes_key = encrypt_aes_key(aes_key, user_public_key_pem)

        return {"status": "error", "encrypted_aes_key": encrypted_aes_key.hex(), "encrypted_message": encrypted_message.hex()}

    elif command == "check_proximity":
        try:
            
            username = request["username"]
            user_id = get_user_id(username)

            if not user_id:
                return {"status": "error", "message": "User not found"}
            
            cursor.execute("SELECT public_key FROM users WHERE id=?", (user_id,))
            user_public_key = cursor.fetchone()[0]
            user_public_key_pem = serialization.load_pem_public_key(user_public_key.encode())

            aes_key = generate_aes_key()

            # Find all friends
            cursor.execute(
                """SELECT username FROM users WHERE id IN 
                (SELECT user_id2 FROM friendships WHERE user_id1=? AND status='accepted' 
                UNION 
                SELECT user_id1 FROM friendships WHERE user_id2=? AND status='accepted')""",
                (user_id, user_id),
            )
            friends = [row[0] for row in cursor.fetchall()]
            if not friends:
                response = {"status": "error", "message": "No friends found"}
                socket = active_clients[username]
                socket.send(json.dumps(response).encode())
                return response

            # Forward encrypted values to friends
            for friend in friends:
                if friend in active_clients:
                    friend_socket = active_clients[friend]
                    request["user2"] = friend
                    friend_socket.send(json.dumps(request).encode())
                    
                else:
                    response = {"status": "error", "message": f"{friend} is not online"}
                    socket = active_clients[username]
                    socket.send(json.dumps(response).encode())
                    return response
                
            return {"status": "success", "message": f"Sent encrypted to {friend}"}

        except Exception as error:
            print(error)
    
    elif command == "send_encrypted_distance":

        friend_socket = active_clients[request["user1"]]
        friend_socket.send(json.dumps(request).encode())
        return {"status": "success", "message": "Encrypted euclidean sent."}
    
    elif command == "remove_friend":
        with friendship_lock:
            user_id = get_user_id(request["username"])
            friend_id = get_user_id(request["friend"])

            cursor.execute("SELECT public_key FROM users WHERE id=?", (user_id,))
            user_public_key = cursor.fetchone()[0]
            user_public_key_pem = serialization.load_pem_public_key(user_public_key.encode())

            aes_key = generate_aes_key()

            if not user_id or not friend_id:

                encrypted_message = encrypt_aes("User not found.", aes_key)
                encrypted_aes_key = encrypt_aes_key(aes_key, user_public_key_pem)
                
                hmac_digest = hmac.new(aes_key, encrypted_message[:-32], hashlib.sha256).digest().hex()

                return {"status": "error", "encrypted_aes_key": encrypted_aes_key.hex(), "encrypted_message": encrypted_message.hex(), "hmac": hmac_digest}

            # Check if they are actually friends
            cursor.execute("SELECT 1 FROM friendships WHERE (user_id1=? AND user_id2=?) OR (user_id1=? AND user_id2=?)",
                        (user_id, friend_id, friend_id, user_id))
            friendship_exists = cursor.fetchone()

            if not friendship_exists:

                encrypted_message = encrypt_aes("You are not friends with this user.", aes_key)
                encrypted_aes_key = encrypt_aes_key(aes_key, user_public_key_pem)

                hmac_digest = hmac.new(aes_key, encrypted_message[:-32], hashlib.sha256).digest().hex()

                return {"status": "error", "encrypted_aes_key": encrypted_aes_key.hex(), "encrypted_message": encrypted_message.hex(), "hmac": hmac_digest}

            # Remove friendship from database
            cursor.execute("DELETE FROM friendships WHERE (user_id1=? AND user_id2=?) OR (user_id1=? AND user_id2=?)",
                        (user_id, friend_id, friend_id, user_id))
            conn.commit()

            encrypted_message = encrypt_aes(f"You are no longer friends with {request['friend']}", aes_key)
            encrypted_aes_key = encrypt_aes_key(aes_key, user_public_key_pem)
            
            hmac_digest = hmac.new(aes_key, encrypted_message[:-32], hashlib.sha256).digest().hex()

            return {"status": "success", "encrypted_aes_key": encrypted_aes_key.hex(), "encrypted_message": encrypted_message.hex(), "hmac": hmac_digest}
    
    elif command == "logout":
        username = request["username"]
        del active_clients[username]
        return {"status": "success", "message": f"{username} has logged out."}
    return {"status": "error", "message": f"Unknown command {command}"}
    
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