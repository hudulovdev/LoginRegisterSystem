import getpass
import hashlib

# Function to hash the password
def hash_password(password):
    salt = hashlib.sha256(password.encode()).hexdigest()
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
    return hashed_password, salt

# Function to verify the password
def verify_password(password, stored_password, salt):
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
    return hashed_password == stored_password

# Function to register a new user
def register():
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    hashed_password, salt = hash_password(password)

    with open('users.txt', 'a') as file:
        file.write(f"{username}:{hashed_password}:{salt}\n")

    print("Registration successful!")

# Function to log in an existing user
def login():
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")

    with open('users.txt', 'r') as file:
        for line in file:
            stored_username, stored_password, salt = line.strip().split(':')
            if stored_username == username and verify_password(password, stored_password, salt):
                print("Login successful!")
                return

    print("Invalid username or password!")

# Main menu
def main():
    while True:
        print("\n===== Welcome to the Login/Register System =====")
        print("1. Register")
        print("2. Login")
        print("3. Quit")

        choice = input("Enter your choice (1-3): ")
        if choice == '1':
            register()
        elif choice == '2':
            login()
        elif choice == '3':
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == '__main__':
    main()
