import socket
import json
import getpass
import os
import sys
import tkinter as tk
from tkinter import filedialog
import ssl

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

# Ensure the parent directory is in the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from algorithms.rsa_private_auth import is_private_key_correct
from algorithms.rsa_keygen import generate_rsa_keys, encrypt_message, decrypt_message

from algorithms.encryption_utils import encrypt_message as encrypt_aes, decrypt_message as decrypt_aes


def sign_message(private_key_pem, message):
    """Sign a message with the client's private key."""
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    signature = private_key.sign(
        message.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return signature.hex()

def send_request(request, private_key_pem=None):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Disable certificate verification for testing

        client = context.wrap_socket(client)
        client.connect(("127.0.0.1", 5555))

        request_string = json.dumps(request)

        # Only sign the message if a private key is available AND it's not a registration request
        if private_key_pem and request["command"] not in ["register", "login"]:
            try:
                signature = sign_message(private_key_pem, request_string)
                request["signature"] = signature  # Attach signature to request
                # print("Request signed successfully")
            except Exception as e:
                print(f"Error signing message: {e}")
                return {"status": "error", "message": "Signing error"}
        else:
            request["signature"] = None  # Explicitly indicate no signature

        request_json = json.dumps(request)
        # print(f"Sending request: {request}")  # Debugging output

        # 🔒 Encrypt the request before sending
        encrypted_request = encrypt_aes(request_json)
        client.sendall(encrypted_request.encode())
        # client.send(json.dumps(request).encode())

        response_data = client.recv(4096)
        # if not response_data:
        #     return {"status": "error", "message": "No response from server"}

        # response = json.loads(response_data.decode())

        # print(f"Received response: {response}")  # Debugging output
        
        # 🔓 Decrypt the response
        decrypted_response = decrypt_aes(response_data.decode())
        response = json.loads(decrypted_response)
        client.close()
        return response

    except json.JSONDecodeError:
        return {"status": "error", "message": "Invalid server response"}
    except Exception as e:
        return {"status": "error", "message": f"Client error: {str(e)}"}

# def send_request(request):
#     try:
#         client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         client.connect(("127.0.0.1", 5555))
#         client.send(json.dumps(request).encode())

#         response_data = client.recv(4096)

#         if not response_data:
#             raise ValueError("No response from server")

#         response = json.loads(response_data.decode())
#         client.close()
#         return response
#     except json.JSONDecodeError:
#         return {"status": "error", "message": "Invalid server response"}
#     except Exception as e:
#         return {"status": "error", "message": f"Client error: {str(e)}"}


def prompt_for_save_location(default_filename):
    root = tk.Tk()
    root.withdraw()  # Hide the root window

    # ✅ Force window to the front
    root.attributes("-topmost", True)
    root.update()

    file_path = filedialog.asksaveasfilename(
        defaultextension=".pem",
        initialfile=default_filename,
        filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
    )

    root.destroy() 
    return file_path

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")  # Cross-platform screen clearing

def main():
    logged_in = False
    
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

                # ✅ Step 1: Check if the username already exists
                check_response = send_request({"command": "check_username", "username": uname}, None)

                if check_response["status"] == "error" or check_response["message"] == "User already exists":
                    
                    print(f"Error: Username '{uname}' is already taken. Please try a different one.")
                    input("Press Enter to continue...")

                else:
                    # ✅ Step 2: Generate and save keys ONLY if the username is available
                    private_key_pem, public_key_pem = generate_rsa_keys()

                    print(f"\nPlease save your private key securely. This key is unique to your account.")
                    print(f"The private key for {uname} will be saved with the filename: {uname}_private.pem")

                    private_key_filename = f"{uname}_private.pem"
                    private_key_path = prompt_for_save_location(private_key_filename)

                    if private_key_path:
                        with open(private_key_path, "w") as key_file:
                            key_file.write(private_key_pem)
                        print(f"Private key saved to: {private_key_path}")
                    else:
                        print("Warning: Private key not saved. Store it securely!")

                    # ✅ Step 3: Register user with public key
                    request_data = {
                        "command": "register",
                        "username": uname,
                        "password": pwd,
                        "public_key": public_key_pem
                    }

                    response = send_request(request_data, None)  # No private key needed for registration

                    if "status" in response and response["status"] == "success":
                        print("Registration successful. Please log in now.")
                    else:
                        print(f"Error: Registration failed - {response.get('message', 'Unknown error')}")

                    input("Press Enter to continue...")

            elif choice == "2":  # Login
                uname = input("Enter username: ").strip()
                pwd = getpass.getpass("Enter password: ").strip()

                if not uname or not pwd:
                    print("Error: Username and password cannot be empty.")
                    input("Press Enter to continue...")
                    continue  # Return to the Welcome page

                # Send login request to server (without signing it)
                response = send_request({"command": "login", "username": uname, "password": pwd})

                # print("DEBUG: Server response:", response)

                if response["status"] == "success":
                    logged_in = True
                    username = uname

                    if "public_key" in response:
                        public_key_pem = response["public_key"]

                        # Create a hidden root window and bring it to the front
                        root = tk.Tk()
                        root.withdraw()  # Hide the root window
                        root.attributes('-topmost', True)  # Bring file dialog to the front
                        root.update()

                        # Prompt user to select their private key
                        print("Please select your private key file.")
                        private_key_path = filedialog.askopenfilename(
                            title="Select Private Key File",
                            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
                        )

                        root.destroy() 

                        if private_key_path and os.path.exists(private_key_path):
                            with open(private_key_path, "r") as key_file:
                                private_key_pem = key_file.read()
                            print("Private key loaded successfully.")

                            # Verify the loaded private key
                            challenge = "some_random_challenge"  # Replace with actual challenge from server
                            if is_private_key_correct(private_key_pem, public_key_pem, challenge):
                                print("Private key is correct! Secure transactions enabled.")
                            else:
                                print("Private key is incorrect!")
                                input("Press Enter to return to the Welcome page...")
                                logged_in = False
                                private_key_pem = None  # Ensure private key is cleared
                        else:
                            print("Warning: No private key selected. Some actions may not work.")
                            private_key_pem = None  # Ensure private key is set to None

                else:
                    print("Error: Login failed -", response["message"])
                    input("Press Enter to return to the Welcome page...")
                    continue
            
            elif choice == "3":
                break
            
            else:
                print("Invalid option. Try again.")
                input("Press Enter to continue...")

        else:
            clear_screen()
            print(f"=== Logged in as: {uname} ===")
            print("1. Update Location")
            print("2. Display Proximity")
            print("3. Add Friend")
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
                        response = send_request({"command": "update_location", "user": uname, "x": x, "y": y}, private_key_pem)
                        print(response["message"])
                    else:
                        print("Error: Coordinates must be within the range 0-99999.")

                input("Press Enter to continue...")

            elif choice == "2":  # Display Proximity
                response = send_request({"command": "check_proximity", "user": uname}, private_key_pem)
                if response["status"] == "success":
                    nearby_users = [user for user in response["nearby_users"] if user != uname]
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

                # Check if a message history exists before adding the friend
                response = send_request({"command": "add_friend", "user": uname, "friend": friend_name}, private_key_pem)

                # print("DEBUG: Server response:", response)  # Debugging

                if response["status"] == "success":
                    # If a message history exists, proceed with adding the friend
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
                response = send_request({"command": "get_public_key", "user": recipient}, private_key_pem)
                if response["status"] != "success":
                    print("Error: Unable to fetch recipient's public key.")
                    input("Press Enter to continue...")
                    continue

                recipient_public_key = response["public_key"]
                encrypted_message = encrypt_message(recipient_public_key, message)

                response = send_request({
                    "command": "send_message",
                    "sender": uname,
                    "recipient": recipient,
                    "message": encrypted_message
                }, private_key_pem)
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
                response = send_request({"command": "view_inbox", "user": uname}, private_key_pem)

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
                    response = send_request({"command": "remove_friend", "user": uname, "friend": friend}, private_key_pem)
                    print(response["message"])

                input("Press Enter to continue...")

            elif choice == "7":  # Logout
                if logged_in:  # Ensure user is logged in before logging out
                    response = send_request({"command": "clear_messages", "username": uname}, private_key_pem)
                    print(response["message"])
                    logged_in = False
                    uname = None
                else:
                    print("Error: No user logged in.")
                print("Logged out successfully.")
                input("Press Enter to continue...")


if __name__ == "__main__":
    main()