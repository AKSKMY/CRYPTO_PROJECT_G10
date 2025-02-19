import socket
import json
import getpass
import os

def send_request(request):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(("127.0.0.1", 5555))
        client.send(json.dumps(request).encode())

        response_data = client.recv(1024)
        # print(f"Raw server response: {response_data}")  # Debugging output

        if not response_data:
            raise ValueError("No response from server")

        response = json.loads(response_data.decode())
        client.close()
        return response
    except json.JSONDecodeError:
        return {"status": "error", "message": "Invalid server response"}
    except Exception as e:
        return {"status": "error", "message": f"Client error: {str(e)}"}

def clear_screen():
    os.system("cls")  # Clears the terminal on Windows

def main():
    logged_in = False
    username = None
    
    while True:
        clear_screen()
        if not logged_in:
            print("1. Register")
            print("2. Login")
            print("3. Exit")
            choice = input("Select an option: ")
            
            if choice == "1":
                uname = input("Enter username: ")
                pwd = getpass.getpass("Enter password: ")
                response = send_request({"command": "register", "username": uname, "password": pwd})
                print(response["message"])
                input("Press Enter to continue...")
            
            elif choice == "2":
                uname = input("Enter username: ")
                pwd = getpass.getpass("Enter password: ")
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
            print("1. Update Location")
            print("2. Display Proximity")
            print("3. Add Friend (only if you've messaged them before)")
            print("4. Send Message")
            print("5. View Inbox")
            print("6. Logout")
            print("7. Remove friend")
            choice = input("Select an option: ")

            if choice == "1":  # Update Location
                x = int(input("Enter X coordinate (0-99999): "))
                y = int(input("Enter Y coordinate (0-99999): "))
                response = send_request({"command": "update_location", "user": username, "x": x, "y": y})
                print(response["message"])
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
                friend = input("Enter friend's username: ")
                response = send_request({"command": "add_friend", "user": username, "friend": friend})
                print(response["message"])
                input("Press Enter to continue...")

            elif choice == "4":  # Send Message
                recipient = input("Enter recipient's username: ")
                if recipient == username:
                    print("You cannot message yourself.")
                else:
                    message = input("Enter your message: ")
                    response = send_request({"command": "send_message", "sender": username, "recipient": recipient, "message": message})
                    print(response["message"])
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

            elif choice == "6":  # Logout
                logged_in = False
                username = None
                print("Logged out successfully.")
                input("Press Enter to continue...")

            elif choice == "7":  # Remove Friend
                friend = input("Enter friend's username to remove: ")
                response = send_request({"command": "remove_friend", "user": username, "friend": friend})
                print(response["message"])
                input("Press Enter to continue...")

            else:
                print("Invalid option. Try again.")
                input("Press Enter to continue...")

            

if __name__ == "__main__":
    main()
