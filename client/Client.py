import socket
import json
import getpass
import os
import sys
import tkinter as tk
from tkinter import filedialog

# Ensure the parent directory is in the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from algorithms.rsa_private_auth import is_private_key_correct

from algorithms.rsa_keygen import generate_rsa_keys, encrypt_message, decrypt_message

def send_request(request):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(("127.0.0.1", 5555))
        client.send(json.dumps(request).encode())

        response_data = client.recv(4096)

        if not response_data:
            raise ValueError("No response from server")

        response = json.loads(response_data.decode())
        client.close()
        return response
    except json.JSONDecodeError:
        return {"status": "error", "message": "Invalid server response"}
    except Exception as e:
        return {"status": "error", "message": f"Client error: {str(e)}"}

def prompt_for_save_location(default_filename):
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    file_path = filedialog.asksaveasfilename(
        defaultextension=".pem",
        initialfile=default_filename,
        filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
    )
    return file_path

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")  # Cross-platform screen clearing

def main():
    logged_in = False
    username = None
    private_key = None  # Store private key after login
    
    while True:
        clear_screen()
        if not logged_in:
            print("=== Welcome to Group 10 Crypto Project ===")
            print("1. Register")
            print("2. Login")
            print("3. Exit")
            choice = input("Select an option: ").strip()
            
            if choice == "1":  # Register
                uname = input("Enter username: ").strip()
                pwd = getpass.getpass("Enter password: ").strip()
                if not uname or not pwd:
                    print("Error: Username and password cannot be empty.")
                    input("Press Enter to continue...")
                    continue

                # In main() method, inside the registration section
                private_key_pem, public_key_pem = generate_rsa_keys()

                # Prompt user with a print statement about saving the private key
                print(f"\nPlease save your private key securely. This key is unique to your account.")
                print(f"The private key for {uname} will be saved with the filename: {uname}_private.pem")

                # Save private key to a file specific to the user
                private_key_filename = f"{uname}_private.pem"
                private_key_path = prompt_for_save_location(private_key_filename)

                if private_key_path:
                    with open(private_key_path, "w") as key_file:
                        key_file.write(private_key_pem)
                    print(f"Private key saved to: {private_key_path}")
                else:
                    print("Warning: Private key not saved. Store it securely!")

                # Register user with public key
                response = send_request({
                    "command": "register",
                    "username": uname,
                    "password": pwd,
                    "public_key": public_key_pem
                })
                print(response["message"])

                if response["status"] == "success":
                    private_key = private_key_pem  # Store in memory for use
                    print("Registration successful. Please log in now.")
                    input("Press Enter to continue...")  # Wait for user input
                    continue  # Return to the main menu after registration

            
            elif choice == "2":  # Login
                uname = input("Enter username: ").strip()
                pwd = getpass.getpass("Enter password: ").strip()
                
                if not uname or not pwd:
                    print("Error: Username and password cannot be empty.")
                    input("Press Enter to continue...")
                    continue  # Return to the Welcome page

                # Send login request to server
                response = send_request({"command": "login", "username": uname, "password": pwd})

                # Debug: Print the full response from the server
                print("DEBUG: Server response:", response)  # This will print the entire response to check its structure

                if response["status"] == "success":
                    logged_in = True
                    username = uname

                    # Ensure that the response contains "public_key"
                    if "public_key" in response:
                        public_key_pem = response["public_key"]

                        # Proceed with private key selection and verification
                        print("Please select your private key file for decryption.")
                        private_key_path = filedialog.askopenfilename(
                            title="Select Private Key File",
                            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
                        )

                        if private_key_path and os.path.exists(private_key_path):
                            with open(private_key_path, "r") as key_file:
                                private_key_pem = key_file.read()
                            print("Private key loaded successfully.")

                            # Verify the loaded private key
                            challenge = "some_random_challenge"  # Replace with actual challenge from server
                            if is_private_key_correct(private_key_pem, public_key_pem, challenge):
                                print("Private key is correct!")
                                input("Press Enter to continue...")
                            else:
                                print("Private key is incorrect!")
                                input("Press Enter to return to the Welcome page...")
                                logged_in = False
                        else:
                            private_key_pem = None
                            print("Warning: No private key selected. Decryption may fail.")
                    else:
                        print("Error: Public key not found in server response.")
                
                else:
                    print("Error: Login failed -", response["message"])  # Show proper error message
                    input("Press Enter to return to the Welcome page...")
                    continue  # Return to Welcome page



            
            elif choice == "3":
                break
            
            else:
                print("Invalid option. Try again.")
                input("Press Enter to continue...")

        else:
            clear_screen()
            print(f"=== Logged in as: {username} ===")
            print("1. Update Location")
            print("2. Display Proximity")
            print("3. Add Friend (only if you've messaged them before)")
            print("4. Send Encrypted Message (Only if you are in close proximity or friend)")
            print("5. View Inbox (Decrypt Messages)")
            print("6. Remove Friend")
            print("7. Logout")
            choice = input("Select an option: ").strip()

            if choice == "1":  # Update Location
                x = input("Enter X coordinate (0-99999): ").strip()
                y = input("Enter Y coordinate (0-99999): ").strip()

                if not x or not y:
                    print("Error: Coordinates cannot be empty.")
                elif not x.isdigit() or not y.isdigit():
                    print("Error: Please enter only numeric values for X and Y.")
                else:
                    x, y = int(x), int(y)
                    if 0 <= x <= 99999 and 0 <= y <= 99999:
                        response = send_request({"command": "update_location", "user": username, "x": x, "y": y})
                        print(response["message"])
                    else:
                        print("Error: Coordinates must be within the range 0-99999.")

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
                input("Press Enter to continue...")

            elif choice == "3":  # Add Friend
                friend_name = input("Enter the username of the friend you want to add: ").strip()

                if not friend_name:
                    print("Error: Friend username cannot be empty.")
                    input("Press Enter to continue...")
                    continue

                response = send_request({"command": "add_friend", "user": username, "friend": friend_name})

                if response and "message" in response:
                    print(response["message"])
                else:
                    print("[ERROR] Failed to send a friend request.")
                input("Press Enter to continue...")

            elif choice == "4":  # Send Encrypted Message
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

                # Fetch recipient's public key
                response = send_request({"command": "get_public_key", "user": recipient})
                if response["status"] != "success":
                    print("Error: Unable to fetch recipient's public key.")
                    input("Press Enter to continue...")
                    continue

                recipient_public_key = response["public_key"]
                encrypted_message = encrypt_message(recipient_public_key, message)

                response = send_request({
                    "command": "send_message",
                    "sender": username,
                    "recipient": recipient,
                    "message": encrypted_message
                })
                print(response["message"])
                input("Press Enter to continue...")

            elif choice == "5":  # View Inbox (Decrypt Messages)
                if private_key_pem is None:
                    print("Error: No private key loaded. Please select your private key.")
                    
                    # Prompt user to select private key
                    private_key_path = filedialog.askopenfilename(
                        title="Select Private Key File",
                        filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
                    )

                    if private_key_path and os.path.exists(private_key_path):
                        with open(private_key_path, "r") as key_file:
                            private_key_pem = key_file.read()
                        print("Private key loaded successfully.")
                    else:
                        print("Error: No private key selected. Cannot decrypt messages.")
                        input("Press Enter to continue...")
                        continue  # Return to menu

                # Now proceed to decrypt messages
                response = send_request({"command": "view_inbox", "user": username})

                if response["status"] == "success":
                    inbox_messages = response.get("inbox", [])

                    if not inbox_messages:
                        print("\nInbox is empty. No messages to display.")
                    else:
                        print("\nInbox Messages:")
                        for message in inbox_messages:
                            sender = message["from"]
                            timestamp = message["timestamp"]
                            encrypted_message = message["message"]

                            try:
                                decrypted_message = decrypt_message(private_key_pem, encrypted_message)
                                print(f"From {sender} at {timestamp}: {decrypted_message}")
                            except Exception as e:
                                print(f"From {sender} at {timestamp}: (Decryption failed - {str(e)})")

                else:
                    print("Error:", response["message"])

                input("Press Enter to continue...")



            elif choice == "6":  # Remove Friend
                friend = input("Enter friend's username to remove: ").strip()
                if not friend:
                    print("Error: Friend's username cannot be empty.")
                else:
                    response = send_request({"command": "remove_friend", "user": username, "friend": friend})
                    print(response["message"])

                input("Press Enter to continue...")

            elif choice == "7":  # Logout
                if logged_in:  # Ensure user is logged in before logging out
                    response = send_request({"command": "clear_messages", "username": username})
                    print(response["message"])
                    logged_in = False
                    username = None
                else:
                    print("Error: No user logged in.")
                print("Logged out successfully.")
                input("Press Enter to continue...")


if __name__ == "__main__":
    main()