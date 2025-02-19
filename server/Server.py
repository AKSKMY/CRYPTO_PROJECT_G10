import socket
import threading
import json
import sqlite3
import bcrypt
import sys
import signal

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
        password_hash TEXT NOT NULL
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
            data = client_socket.recv(1024).decode()
            if not data:
                print("Received empty request.")
                break
            request = json.loads(data)
            print(f"Server received request: {request}")
            response = process_request(request)
            print(f"Server sending response: {response}")
            client_socket.send(json.dumps(response).encode())
        except:
            break
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
        try:
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
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
        friend = request["friend"]
        user_id = get_user_id(request["user"])
        friend_id = get_user_id(friend)
        

        if user_id and friend_id:
            try:
                cursor.execute("INSERT INTO friendships (user_id1, user_id2) VALUES (?, ?)", (user_id, friend_id))
                
                cursor.execute("INSERT INTO friendships (user_id1, user_id2) VALUES (?, ?)", (friend_id, user_id))
                
                conn.commit()
                return {"status": "success", "message": f"Added {friend} as a friend"}
            except sqlite3.IntegrityError:
                return {"status": "error", "message": "Already friends"}
        return {"status": "error", "message": "Friend not found"}

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
