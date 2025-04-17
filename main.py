import json
import re
import random
import string

# Caesar cipher encryption and decryption functions (pre-implemented)
def caesar_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
            encrypted_text += chr(shifted)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# Password strength checker function (optional)
def is_strong_password(password):
    """
    Check if the password is strong.

    A strong password should be at least 8 characters long and include
    a mix of uppercase letters, lowercase letters, digits, and special characters.

    Args:
        password (str): The password to check.

    Returns:
        bool: True if the password is strong, False otherwise.
    """
    length_ok = len(password) >= 8
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_special = any(char in string.punctuation for char in password)

    return length_ok and has_upper and has_lower and has_digit and has_special

# Password generator function (optional)
def generate_password(length):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    return password

    
# Initialize empty lists to store encrypted passwords, websites, and usernames
encrypted_passwords = []
websites = []
usernames = []

# Function to add a new password 
def add_password():
    website = input("Enter the website: ")
    username = input("Enter the username: ")
    password = input("Enter the password: ")

    # Encrypt the password
    encrypted_password = caesar_encrypt(password, 3)

    # Store the details
    websites.append(website)
    usernames.append(username)
    encrypted_passwords.append(encrypted_password)

    print("Password added successfully!")


# Function to retrieve a password 
def get_password():
    website = input("Enter the website: ")

    if website in websites:
        index = websites.index(website)
        username = usernames[index]
        encrypted_password = encrypted_passwords[index]
        decrypted_password = caesar_decrypt(encrypted_password, 3)

        print(f"Username: {username}")
        print(f"Password: {decrypted_password}")
    else:
        print("Website not found.")

    
# Function to save passwords to a JSON file 
def save_passwords():
    data = {
        "websites": websites,
        "usernames": usernames,
        "encrypted_passwords": encrypted_passwords
    }

    with open("vault.txt", "w") as file:
        json.dump(data, file)

    print("Passwords saved successfully!")

    
# Function to load passwords from a JSON file 
def load_passwords():
    global websites, usernames, encrypted_passwords

    try:
        with open("vault.txt", "r") as file:
            data = json.load(file)
            websites = data["websites"]
            usernames = data["usernames"]
            encrypted_passwords = data["encrypted_passwords"]

        print("Passwords loaded successfully!")
    except FileNotFoundError:
        print("No saved passwords found.")

    # Main method
def main():
# implement user interface 

  while True:
    print("\nPassword Manager Menu:")
    print("1. Add Password")
    print("2. Get Password")
    print("3. Save Passwords")
    print("4. Load Passwords")
    print("5. Quit")
    
    choice = input("Enter your choice: ")
    
    if choice == "1":
        add_password()
    elif choice == "2":
        get_password()
    elif choice == "3":
        save_passwords()
    elif choice == "4":
        passwords = load_passwords()
        print("Passwords loaded successfully!")
    elif choice == "5":
        break
    else:
        print("Invalid choice. Please try again.")

# Execute the main function when the program is run
if __name__ == "__main__":
    main()
