import socket
import json
import getpass
import os
import threading
import time
logged_in = False
username = None
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("127.0.0.1", 5555))
        
def receive_messages():
    """Continuously listens for incoming messages."""
    client.setblocking(False)
    while logged_in:
        try:
            data = client.recv(1024).decode()
            if data:
                
                try:
                    message = json.loads(data)
                    if "from" in message and "message" in message:
                        sender = message["from"]
                        content = message["message"]
                        print(f"\n🔹 New message from {sender}: {content}\nSelect an option: ", end="")
                
                except json.JSONDecodeError:
                    print("[ERROR] Received invalid JSON format.")

        except BlockingIOError:
            time.sleep(0.1)  # ✅ Allow other operations to proceed without blocking
            continue

        
        except (ConnectionResetError, OSError):
            #print("[ERROR] Disconnected from server.")
            continue

def send_request(request):
    try:
        client.send(json.dumps(request).encode())
        client.settimeout(1)
        response_data = client.recv(1024)
        if not response_data:
            raise ValueError("No response from server")
        response = json.loads(response_data.decode())
        if "status" in response:
            if "message" and "from" in response:
                print(response['message'])  
        return response
    except json.JSONDecodeError:
        return {"status": "error", "message": "Invalid server response"}
    except Exception as e:
        return {"status": "none", "message": ""}

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")  # Cross-platform screen clearing

def main():
    global logged_in  # Ensure this function accesses the global login status
    logged_in = False
    username = None
    
    while True:
        clear_screen()
        if not logged_in:
            print("=== Welcome to Group 10 Crypto Project ===")
            print("1. Register")
            print("2. Login")
            print("3. Exit")
            choice = input("Select an option: ").strip()
            
            if choice == "1":
                uname = input("Enter username: ").strip()
                pwd = getpass.getpass("Enter password: ").strip()
                if not uname or not pwd:
                    print("Error: Username and password cannot be empty.")
                    input("Press Enter to continue...")
                    continue
                response = send_request({"command": "register", "username": uname, "password": pwd})
                print(response["message"])
                input("Press Enter to continue...")
            
            elif choice == "2":
                uname = input("Enter username: ").strip()
                pwd = getpass.getpass("Enter password: ").strip()
                if not uname or not pwd:
                    print("Error: Username and password cannot be empty.")
                    input("Press Enter to continue...")
                    continue
                response = send_request({"command": "login", "username": uname, "password": pwd})
                print(response["message"])
                if response["status"] == "success":
                    logged_in = True
                    username = uname
            
                input("Press Enter to continue...")
            
            elif choice == "3":
                break
            
            else:
                print("Invalid option. Try again.")
                input("Press Enter to continue...")

        else:
            clear_screen()
            threading.Thread(target=receive_messages, daemon=True).start()

            print(f"=== Logged in as: {username} ===")
            print("1. Update Location")
            print("2. Display Proximity")
            print("3. Add Friend (only if you've messaged them before)")
            print("4. Send Message")
            print("5. View Inbox")
            print("6. Remove Friend")
            print("7. Logout")
            choice = input("Select an option: ").strip()

            if choice == "1":  # Update Location
                while True:
                    x = input("Enter X coordinate (0-99999): ").strip()
                    y = input("Enter Y coordinate (0-99999): ").strip()

                    if not x or not y:
                        print("Error: Coordinates cannot be empty. Please enter valid numbers.")
                    elif not x.isdigit() or not y.isdigit():
                        print("Error: Please enter only numeric values for X and Y.")
                    else:
                        x, y = int(x), int(y)
                        if 0 <= x <= 99999 and 0 <= y <= 99999:
                            response = send_request({"command": "update_location", "user": username, "x": x, "y": y})
                            print(response["message"])
                            break  # Exit the loop once valid input is provided
                        else:
                            print("Error: Coordinates must be within the range 0-99999.")
                time.sleep(0.1)
                input("Press Enter to continue...")

            elif choice == "2":  # Display Proximity
                response = send_request({"command": "check_proximity", "user": username})
                if response["status"] == "success":
                    nearby_users = [user for user in response["nearby_users"] if user != username]
                    if nearby_users:
                        print("Nearby users:", ", ".join(nearby_users))
                    else:
                        print("No users nearby.")
                else:
                    print(response["message"])
                time.sleep(0.1)
                input("Press Enter to continue...")

            elif choice == "3":  # Add Friend
                friend = input("Enter friend's username: ").strip()
                if not friend:
                    print("Error: Friend's username cannot be empty.")
                else:
                    response = send_request({"command": "add_friend", "user": username, "friend": friend})
                    print(response["message"])
                time.sleep(0.1)
                input("Press Enter to continue...")

            elif choice == "4":  # Send Message
                recipient = input("Enter recipient's username: ").strip()
                if not recipient:
                    print("Error: Recipient's username cannot be empty.")
                    input("Press Enter to continue...")
                    continue

                message = input("Enter your message: ").strip()
                if not message:
                    print("Error: Message cannot be empty.")
                    input("Press Enter to continue...")
                    continue

                response = send_request({"command": "send_message", "sender": username, "recipient": recipient, "message": message})
                print(response["message"])
                time.sleep(0.1)
                input("Press Enter to continue...")

            elif choice == "5":  # View Inbox
                response = send_request({"command": "view_inbox", "user": username})
                if response["status"] == "success":
                    inbox = response["inbox"]
                    if inbox:
                        print("\nInbox Messages:")
                        for msg in inbox:
                            print(msg)
                    else:
                        print("Your inbox is empty.")
                else:
                    print(response["message"])
                input("Press Enter to continue...")

            elif choice == "6":  # Remove Friend
                friend = input("Enter friend's username to remove: ").strip()
                if not friend:
                    print("Error: Friend's username cannot be empty.")
                else:
                    response = send_request({"command": "remove_friend", "user": username, "friend": friend})
                    print(response["message"])
                time.sleep(0.1)
                input("Press Enter to continue...")

            elif choice == "7":  # Logout
                logged_in = False
                username = None
                print("Logged out successfully.")
                time.sleep(0.1)
                input("Press Enter to continue...")

if __name__ == "__main__":
    main()
