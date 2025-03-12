import socket
import json
import getpass
import os
import sys
import tkinter as tk
from tkinter import filedialog
import bcrypt
import threading
import traceback
import time
import psutil
import hmac
import hashlib
from phe import generate_paillier_keypair, paillier

# Ensure the parent directory is in the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from algorithms.rsa_private_auth import is_private_key_correct
from algorithms.elgamal import *
from algorithms.rsa_keygen import generate_rsa_keys
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

# Store Paillier key pair
paillier_public_key = None
paillier_private_key = None

# Store Elgamal key pair
keys = None

def generate_salt():
    """Generate a random 16-byte salt and return it as a base64 string."""
    return bcrypt.gensalt().decode()  # ✅ Generate a unique salt

def hash_password(password, salt):
    """Hash the password using the provided salt."""
    return bcrypt.hashpw(password.encode(), salt.encode()).decode()

def decrypt_aes_key(encrypted_aes_key, private_key):
    """Decrypt the AES key using user's RSA private key."""
    return private_key.decrypt(
        bytes.fromhex(encrypted_aes_key),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_aes(encrypted_data, aes_key, received_hmac=None):
    """Decrypt AES-encrypted data."""
    encrypted_data = bytes.fromhex(encrypted_data)

    if len(encrypted_data) < 48:  # IV (16 bytes) + Minimum Cipher + HMAC (32 bytes)
        raise ValueError("[CLIENT ERROR] Encrypted data too short!")

    iv = encrypted_data[:16]  # Extract IV
    ciphertext = encrypted_data[16:-32]  # Extract ciphertext

    if received_hmac:
        # ✅ Compute HMAC on received IV + ciphertext
        hmac_obj = hmac.new(aes_key, iv + ciphertext, hashlib.sha256)
        computed_hmac = hmac_obj.digest()

        # print(f"[CLIENT DEBUG] Received HMAC (hex): {received_hmac.hex()}")
        # print(f"[CLIENT DEBUG] Computed HMAC (hex): {computed_hmac.hex()}")

        if not hmac.compare_digest(received_hmac, computed_hmac):
            raise ValueError("[CLIENT ERROR] HMAC verification failed! Message integrity compromised.")
            

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_padded.decode().strip()  # Remove padding

def process_proximity_request(request, client_socket):
    """Computes the encrypted Euclidean distance for proximity checking and sends it back."""

    # print(f"request = {request}")
    username = request["username"]
    user2 = request["user2"]
    public_key_n = request["public_key"]  # Received from User1

    # Load User2's saved location
    save_path = f"proximity_json/{user2}_location.json"
    if not os.path.exists(save_path):
        print("[ERROR] Location not found. Cannot process proximity request.")
        return

    with open(save_path, "r") as json_file:
        location_data = json.load(json_file)
    if request["method"] == "1":
        x2, y2 = location_data["x_location"], location_data["y_location"]
        paillier_public_key_1 = paillier.PaillierPublicKey(int(public_key_n))
        # Convert received encrypted values to Paillier format
        enc_x1 = paillier.EncryptedNumber(paillier_public_key_1, int(request["enc_x1"]))
        enc_y1 = paillier.EncryptedNumber(paillier_public_key_1, int(request["enc_y1"]))
        enc_x1_sq = paillier.EncryptedNumber(paillier_public_key_1, int(request["enc_x1_sq"]))
        enc_y1_sq = paillier.EncryptedNumber(paillier_public_key_1, int(request["enc_y1_sq"]))
        # Encrypt User2's values using User1's public key
        enc_x2 = paillier_public_key_1.encrypt(x2)
        enc_y2 = paillier_public_key_1.encrypt(y2)
        enc_x2_sq = enc_x2 * x2
        enc_y2_sq = enc_y2 * y2
        enc_2_x1_x2 = enc_x1 * x2
        enc_2_y1_y2 = enc_y1 * y2
        # Compute encrypted Euclidean distance: (x1 - x2)^2 + (y1 - y2)^2
        # ✅ Compute (x1 - x2)^2 in encrypted form
        enc_dx2 = enc_x1_sq - 2 * enc_2_x1_x2 + enc_x2_sq
        enc_dy2 = enc_y1_sq - 2 * enc_2_y1_y2 + enc_y2_sq
        enc_distance = enc_dx2 + enc_dy2  # Final encrypted squared Euclidean distance
        enc_distance = enc_distance.ciphertext()
    elif request["method"] == "2":
        x2, y2 = location_data["x_location"], location_data["y_location"]
        b = [x2, y2]
        enc_b = [elgamal_encrypt(request['public_key'], val) for val in b]
        enc_a = request['enc_a']
        # Calculate approximate encrypted distance (simplified demonstration)
        enc_distance = euclidean_distance_homomorphic(request['public_key'], enc_a, enc_b)

    # Send the result back to User1 via the server
    response = {
        "command": "send_encrypted_distance",
        "user1": username,
        "user2": user2,
        "enc_distance": enc_distance,
        "method": request["method"]
    }
    # send_request(client_socket,response)
    client_socket.send(json.dumps(response).encode())

    # def receive_messages(client_socket):
    """Continuously listen for incoming messages or check_proximity requests from the server."""

    response_data = client_socket.recv(4096)

    response = json.loads(response_data.decode())
    if "command" in response and response["command"] == "check_proximity":
        # print(f"\n[SERVER] Received check_proximity request from {response['username']}.")
        process_proximity_request(response, client_socket)

    elif "command" in response and response["command"] == "send_encrypted_distance":
        print(f"response of send_encrypted_distance is {response}")
        handle_encrypted_distance(response)
    
def handle_encrypted_distance(response):
    """Decrypt and process the encrypted distance received from a friend."""
    global end_time
    try:
        user2 = response["user2"]
        enc_distance_ciphertext = response["enc_distance"]  # ✅ Convert back to int
        if response["method"] == "1":
            # ✅ Reconstruct the EncryptedNumber
            enc_distance = paillier.EncryptedNumber(paillier_public_key, enc_distance_ciphertext)

            # ✅ Decrypt the value
            decrypted_distance = paillier_private_key.decrypt(enc_distance)
        elif response["method"] == "2":
            # ✅ Decrypt the value
            global keys
            decrypted_distance = elgamal_decrypt(keys['public'], keys['private'], response['enc_distance'])

        # ✅ Square root to get the actual Euclidean distance
        distance = decrypted_distance ** 0.5
        
        if distance < 1000:
            print(f"{user2} is close!")
        else:
            print(f"{user2} is far!")
        end_time = time.time()
        # ✅ Calculate results
        execution_time = end_time - start_time  # Time taken in seconds
        if response["method"] == "1":
            print(f"Execution Time using Paillier: {execution_time:.4f} seconds")
        elif response["method"] == "2":
            print(f"Execution Time using ElGamal: {execution_time:.4f} seconds")
    except Exception as e:
        print(f"[CLIENT ERROR] Failed to process encrypted distance: {e}")
        traceback.print_exc()  # ✅ Print detailed error log

def receive_messages(client_socket, username, private_key_pem):
    """Continuously listen for incoming messages from the server without blocking."""
    client_socket.settimeout(1)  # ✅ Prevents indefinite blocking
    try:
        while True:
            try:
                response_data = client_socket.recv(4096)

                if not response_data:
                    print("[CLIENT] Server closed connection. Stopping message listener.")
                    break  # ✅ Exit the loop if the server closes the connection
                
                response = json.loads(response_data.decode())  # ✅ Decode response
                signature = response.get("signature")
                
                if signature:
                    signable_request = {k: v for k, v in response.items() if k not in ["user2", "signature"]}
                    request_string = json.dumps(signable_request, separators=(',', ':'))
                    recipient = response.get("username")

                    get_encrypted_recipient_public_key = send_request(client_socket,{"command": "get_public_key", "user": username, "recipient": recipient})
                    if(get_encrypted_recipient_public_key["status"] == "error"):
                        print("Client timed out")
                        continue
                    encrypted_recipient_public_key = get_encrypted_recipient_public_key["encrypted_public_key"]

                    if not encrypted_recipient_public_key:
                        print("User's public key is not found")
                        continue

                    # ✅ Decrypt AES key using RSA private key
                    encrypted_aes_key = get_encrypted_recipient_public_key["encrypted_aes_key"]
                    try:
                        private_key_pem = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
                        aes_key = decrypt_aes_key(encrypted_aes_key, private_key_pem)

                    except:
                        #print(private_key_pem)
                        aes_key = decrypt_aes_key(encrypted_aes_key, private_key_pem)

                    # ✅ Decrypt recipient's public key using AES
                    recipient_public_key = decrypt_aes(encrypted_recipient_public_key, aes_key)
                    recipient_public_key = serialization.load_pem_public_key(recipient_public_key.encode())
                    
                    try:
                        recipient_public_key.verify(bytes.fromhex(signature), request_string.encode(), padding.PSS(mgf = padding.MGF1(hashes.SHA256()), salt_length = padding.PSS.MAX_LENGTH), hashes.SHA256())
                        print("Signature verification success.")
                        print("Press enter to continue.")
                    except InvalidSignature :
                        print("Signature verification failed, message ignored. Press enter to continue.")
                        continue

                if "message" in response:
                    print(response["message"])
                elif "encrypted_message" in response and "encrypted_aes_key" in response:
                    try:
                        print("Encrypted message received.")
                    except Exception as e:
                        print(f"[CLIENT ERROR] Decryption failed: {e}")
                elif "status" in response and response["status"] == "error":
                    print(f"[SERVER ERROR] {response.get('error', 'Unknown error')}")
                
                command = response.get("command")

                # ✅ Handle different command types
                if command == "login":
                    continue  # Skip login responses

                elif command == "check_proximity":
                    process_proximity_request(response, client_socket)

                elif command == "send_encrypted_distance":
                    handle_encrypted_distance(response)

            except json.JSONDecodeError as e:
                print(f"[CLIENT ERROR] JSON Decode Error: {e}")
            except socket.timeout:  
                pass  # ✅ Prevents blocking on recv() if no data is received
            except socket.error as e:
                print(f"[CLIENT ERROR] Socket error: {e}")
                break  # ✅ Exit loop on socket failure

    except Exception as e:
        print(f"[CLIENT ERROR] Unexpected error in receive_messages: {e}")
        traceback.print_exc()  # ✅ Print full traceback for debugging       
        
def send_request(client,request,private_key_pem=None):
    try:
        signable_request = {k: v for k, v in request.items() if k not in ["user2", "signature"]}
        request_string = json.dumps(signable_request, separators=(',', ':'))
        if private_key_pem:
            # ✅ Ensure the private key is an RSA object, not a string
            if isinstance(private_key_pem, str):
                private_key = serialization.load_pem_private_key(
                    private_key_pem.encode(),  # Convert string PEM to key object
                    password=None
                )
            elif isinstance(private_key_pem, bytes):
                private_key = serialization.load_pem_private_key(
                    private_key_pem,  # Load directly if already in bytes
                    password=None
                )
            elif isinstance(private_key_pem, rsa.RSAPrivateKey):
                private_key = private_key_pem  # ✅ Already loaded, no need to convert
            else:
                print("[CLIENT ERROR] Invalid private key format")
                return {"status": "error", "message": "Invalid private key format"}

        # ✅ Sign the entire JSON request string
            signature = private_key.sign(
                request_string.encode(),  # Convert JSON string to bytes
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # ✅ Convert signature to HEX (JSON-safe format)
            request["signature"] = signature.hex()
        else:
            request["signature"] = None
        client.sendall(json.dumps(request).encode())
        response_data = client.recv(4096)

        if not response_data:
            print("No response from server.")
            raise ValueError("No response from server")
        response = json.loads(response_data.decode())
        return response
    except json.JSONDecodeError:
        return {"status": "error", "message": "Invalid server response"}
    except Exception as e:
        return {"status": "error", "message": f"Client error: {str(e)}"}

def prompt_for_save_private_key(default_filename):
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    root.attributes('-topmost', True)  # Ensure it appears in front
    root.update()  # Force update
    
    file_path = filedialog.asksaveasfilename(
        defaultextension=".pem",
        initialfile=default_filename,
        filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
    )
    return file_path

def prompt_for_private_key():
    """Force the file dialog to the front for selecting a private key."""
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    root.attributes('-topmost', True)  # Ensure it appears in front
    root.update()  # Force update

    private_key_path = filedialog.askopenfilename(
        title="Select Private Key File",
        filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
    )

    root.destroy()  # Destroy the root window after selection
    return private_key_path

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")  # Cross-platform screen clearing

def check_proximity(username, client_socket, private_key_pem, method):
    """Encrypts and sends location to check proximity with friends."""
    global paillier_public_key, paillier_private_key

    # Load user's saved location
    save_path = f"proximity_json/{username}_location.json"
    if not os.path.exists(save_path):
        print("[ERROR] Location not found. Please update your location first.")
        return

    with open(save_path, "r") as json_file:
        location_data = json.load(json_file)

    x1, y1 = location_data["x_location"], location_data["y_location"]
    if method == "1":
        # Generate a new Paillier key pair for this session
        paillier_public_key, paillier_private_key = generate_paillier_keypair(n_length=1024)

       # Encrypt values using Paillier
        enc_x1 = paillier_public_key.encrypt(x1)
        enc_y1 =  paillier_public_key.encrypt(y1)
        enc_x1_sq = enc_x1 * x1
        enc_y1_sq = enc_y1 * y1
        # Prepare request to send encrypted values to friends
        request = {
            "command": "check_proximity",
            "username": username,
            "public_key": str(paillier_public_key.n),
            "enc_x1": str(enc_x1.ciphertext()),
            "enc_y1": str(enc_y1.ciphertext()),
            "enc_x1_sq": str(enc_x1_sq.ciphertext()),
            "enc_y1_sq": str(enc_y1_sq.ciphertext()),
            "user2": '',
            "signature": None,
            "method": method
        }
    elif method == "2":
        global keys
        keys = elgamal_generate_keys()
        a = [x1, y1]
        # Encrypt vectors
        enc_a = [elgamal_encrypt(keys['public'], val) for val in a]
        request = {
            "command": "check_proximity",
            "username": username,
            "public_key": keys['public'],
            "enc_a": enc_a,
            "user2": '',
            "signature": None,
            "method": method
        }
    send_request(client_socket, request, private_key_pem)

def update_location(uname):
    x = input("Enter X coordinate (0-99999): ").strip()
    y = input("Enter Y coordinate (0-99999): ").strip()

    if not x or not y:
        print("Error: Coordinates cannot be empty.")
    elif not x.isdigit() or not y.isdigit():
        print("Error: Please enter only numeric values for X and Y.")
    else:
        x, y = int(x), int(y)
        if 0 <= x <= 99999 and 0 <= y <= 99999:
            location_data = {
                    "username": uname,
                    "x_location": x,
                    "y_location": y
                }

            # ✅ Define save directory and ensure it exists
            save_directory = "proximity_json"
            os.makedirs(save_directory, exist_ok=True)  # Create directory if not exists

                # ✅ Save file in /proximity_json and overwrite if exists
            save_path = os.path.join(save_directory, f"{uname}_location.json")
            with open(save_path, "w") as json_file:
                json.dump(location_data, json_file, indent=4)

            print(f"Location successfully saved to: {save_path}")  # ✅ Auto-saved

        else:
            print("Error: Coordinates must be within the range 0-99999.")

        input("Press Enter to continue...")


def main():
    global end_time
    global start_time
    logged_in = False
    username = None
    
    while True:
        if not logged_in:
            clear_screen()
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

                    # First, check if user already exists using get_salt
                    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client.connect(("127.0.0.1", 5555))
                    check_response = send_request(client, {"command": "get_salt", "username": uname})
                    client.close()

                    if check_response["status"] == "success":
                        # Means user already exists
                        print("Error: User already exists. Please login instead.")
                        input("Press Enter to continue...")
                        continue

                    # If user does not exist, proceed
                    salt = generate_salt()
                    hashed_pwd = hash_password(pwd, salt)

                    # Generate RSA key pair
                    private_key_pem, public_key_pem = generate_rsa_keys()

                    print(f"\nPlease save your private key securely. This key is unique to your account.")
                    print(f"The private key for {uname} will be saved with the filename: {uname}_private.pem")
                    private_key_filename = f"{uname}_private.pem"
                    
                    # Prompt user to choose a file path for saving private key
                    private_key_path = prompt_for_save_private_key(private_key_filename)
                    if not private_key_path:
                        # If user did not pick a file, abort registration to avoid saving public key
                        print("Warning: Private key not saved. Registration aborted.")
                        input("Press Enter to continue...")
                        continue

                    # If user *did* pick a path, write the private key and proceed with registration
                    with open(private_key_path, "w") as key_file:
                        key_file.write(private_key_pem)
                    print(f"Private key saved to: {private_key_path}")

                    # Register user with public key only after confirming the private key was saved
                    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client.connect(("127.0.0.1", 5555))
                    response = send_request(client, {
                        "command": "register",
                        "username": uname,
                        "password_hash": hashed_pwd,
                        "salt": salt,
                        "public_key": public_key_pem
                    })
                    client.close()

                    print(response["message"])
                    input("Press Enter to continue...")

            
            elif choice == "2":  # Login
                uname = input("Enter username: ").strip()
                pwd = getpass.getpass("Enter password: ").strip()
                
                if not uname or not pwd:
                    print("Error: Username and password cannot be empty.")
                    input("Press Enter to continue...")
                    continue  # Return to the Welcome page
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.connect(("127.0.0.1", 5555))
                salt_response = send_request(client,{"command": "get_salt", "username": uname})

                if salt_response["status"] != "success":
                    print("[ERROR] Could not retrieve salt. Login failed.")
                    input("Press Enter to continue...")
                    continue
                salt = salt_response["salt"]
                hashed_pwd = hash_password(pwd, salt)

                # Send login request to server
                response = send_request(client,{"command": "login", "username": uname, "password_hash": hashed_pwd})

                #print("DEBUG: Server response:", response)  # This will print the entire response to check its structure

                if response["status"] == "success":
                    username = uname

                    # Ensure that the response contains "public_key"
                    if "public_key" in response:
                        public_key_pem = response["public_key"]

                        # Proceed with private key selection and verification
                        print("\nPassword accepted! Please upload the private key for authentication.")
                        private_key_path = prompt_for_private_key()
    

                        if private_key_path and os.path.exists(private_key_path):
                            with open(private_key_path, "r") as key_file:
                                private_key_pem = key_file.read()
                            print("Private key loaded successfully.")

                            # Verify the loaded private key
                            challenge = "some_random_challenge"  # Replace with actual challenge from server
                            if is_private_key_correct(private_key_pem, public_key_pem, challenge):
                                print("Private key is correct!")
                                logged_in = True
                                input("Press Enter to enter to the user control page...")
                            else:
                                print("Private key is incorrect!")
                                input("Press Enter to return to the Welcome page...")
                                logged_in = False
                        else:
                            private_key_pem = None
                            print("Warning: No private key selected. Decryption failed.")
                            input("Press Enter to return to the Welcome page...")
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
            threading.Thread(target=receive_messages, args=(client,username, private_key_pem), daemon=True).start()
            print("1. Update Location")
            print("2. Display Proximity")
            print("3. Add Friend")
            print("4. Remove Friend")
            print("5. Logout")
            choice = input("Select an option: ").strip()

            if choice == "1":  # Update Location
                update_location(username)

            elif choice == "2":  # Display Proximity
                method = input("Choose 1 for Paillier, 2 for Elgamal : ")

                start_time = time.time()
                check_proximity(username, client, private_key_pem, method)
                
                time.sleep(0.1)
                input("Press enter to continue...\n")
                
            elif choice == "3":  # Add Friend
                friend_name = input("Enter the username of the friend you want to add: ").strip()

                if not friend_name:
                    print("Error: Friend username cannot be empty.")
                    continue

                # Check if a message history exists before adding the friend
                response = send_request(client,{"command": "add_friend", "username": username, "friend": friend_name}, private_key_pem)
                # if response["status"] == "success":
                if "encrypted_message" in response:
                    encrypted_message = response["encrypted_message"]

                    # ✅ Decrypt AES key using RSA private key
                    encrypted_aes_key = response["encrypted_aes_key"]

                    # private_key_pem = serialization.load_pem_private_key(private_key_pem.encode(), password=None)

                    # ✅ Ensure private_key_pem is correctly loaded only once
                    if isinstance(private_key_pem, str):
                        private_key_pem = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
                    elif not isinstance(private_key_pem, rsa.RSAPrivateKey):
                        print("[CLIENT ERROR] Invalid private key format")

                    aes_key = decrypt_aes_key(encrypted_aes_key, private_key_pem)
                    received_hmac = bytes.fromhex(response["hmac"])
                    decrypted_message = decrypt_aes(encrypted_message, aes_key, received_hmac)

                    print(decrypted_message)
                else:
                    print(response["message"])
                input("Press Enter to continue...")
                continue

            elif choice == "4":  # Remove Friend
                friend = input("Enter friend's username to remove: ").strip()
                if not friend:
                    print("Error: Friend's username cannot be empty.")
                else:
                    response = send_request(client,{"command": "remove_friend", "username": username, "friend": friend}, private_key_pem)

                    if "encrypted_message" in response:
                        encrypted_message = response["encrypted_message"]

                        # ✅ Decrypt AES key using RSA private key
                        encrypted_aes_key = response["encrypted_aes_key"]

                        # private_key_pem = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
                        
                        # ✅ Ensure private_key_pem is correctly loaded only once
                        if isinstance(private_key_pem, str):
                            private_key_pem = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
                        elif not isinstance(private_key_pem, rsa.RSAPrivateKey):
                            print("[CLIENT ERROR] Invalid private key format")
                        aes_key = decrypt_aes_key(encrypted_aes_key, private_key_pem)

                        # ✅ Decrypt recipient's public key using AES
                        received_hmac = bytes.fromhex(response["hmac"])
                        decrypted_message = decrypt_aes(encrypted_message, aes_key, received_hmac)
                        print(decrypted_message)
                    else:
                        print(response["message"])
                        
                    input("Press Enter to continue...")
                    continue

            elif choice == "5":  # Logout
                if logged_in:  # Ensure user is logged in before logging out
                    response = send_request(client,{"command": "logout", "username": username})
                    logged_in = False
                    username = None
                    print("Logged out successfully.")
                    input("Press Enter to continue...")
                    client.close()
                else:
                    print("Error: No user logged in.")
                


if __name__ == "__main__":
    main()
