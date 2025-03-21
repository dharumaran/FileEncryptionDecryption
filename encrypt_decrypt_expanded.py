import os
import logging
import getpass
import base64
import hashlib
import sys
import time
import pyperclip
import random
from cryptography.fernet import Fernet
from pick import pick  # File picker
from termcolor import colored  # Color-coded output

# Setup logging
LOG_FILE = "logs/encryptor.log"
os.makedirs("logs", exist_ok=True)
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Secure Key Storage
KEY_FILE = "secret_storage/secure.key"
os.makedirs("secret_storage", exist_ok=True)

# Authentication Attempts
MAX_ATTEMPTS = 3
LOCKOUT_TIME = 300  # 5 minutes

DEC0Y_TEXTS = [
    "Ghw$rg^56Fbuhj*gfdcv^vghuHvhFGhn87^89#bbb^ghj9UV2FD3",
    "3^45s67A*#567cd67#88f&rSDF&@f3456t45b#**!@*&^$#^DokjnFGHJK"
]

def derive_key(password: str) -> bytes:
    """
    Derives a key from the user's password using SHA-256.
    """
    key = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(key)

def save_key(password: str):
    """
    Generates and saves an encrypted key using the user's password.
    """
    key = Fernet.generate_key()
    encrypted_key = Fernet(derive_key(password)).encrypt(key)
    
    with open(KEY_FILE, "wb") as f:
        f.write(encrypted_key)
    
    logging.info("Encryption key generated and securely stored.")

def load_key(password: str) -> bytes:
    """
    Loads and decrypts the encryption key using the user's password.
    """
    if not os.path.exists(KEY_FILE):
        raise FileNotFoundError("Key file not found. Generate a key first.")
    
    with open(KEY_FILE, "rb") as f:
        encrypted_key = f.read()
    
    return Fernet(derive_key(password)).decrypt(encrypted_key)

def file_picker():
    """Interactive file picker for selecting a file."""
    files = [f for f in os.listdir('.') if os.path.isfile(f)]
    if not files:
        print(colored("No files found in the current directory!", "red"))
        sys.exit()
    selected_file, _ = pick(files, "Select a file:")
    return selected_file

def create_decoy_file(original_file_path: str):
    """
    Creates a decoy file with dummy content to divert attention.
    """
    decoy_file_path = original_file_path + ".decoy.txt"
    with open(decoy_file_path, "w") as f:
        f.write(random.choice(DEC0Y_TEXTS))
    logging.info(f"Decoy file created: {decoy_file_path}")
    print(colored(f"Decoy file created: {decoy_file_path}", "yellow"))

def encrypt_file(file_path: str, password: str):
    """
    Encrypts a file using Fernet encryption.
    """
    if not os.path.exists(file_path):
        print(colored("Error: File not found!", "red"))
        return
    
    key = load_key(password)
    encrypted_file_path = file_path + ".enc"
    
    with open(file_path, "rb") as f:
        file_data = f.read()
    
    try:
        cipher = Fernet(key)
        encrypted_data = cipher.encrypt(file_data)
        
        with open(encrypted_file_path, "wb") as f:
            f.write(encrypted_data)
        
        logging.info(f"Encrypted {file_path} -> {encrypted_file_path}")
        print(colored(f"File encrypted: {encrypted_file_path}", "green"))
        
        create_decoy_file(file_path)
        
        delete_original = input("Do you want to delete the original file? (y/n): ").strip().lower()
        if delete_original == 'y':
            os.remove(file_path)
            logging.info(f"Original file {file_path} deleted.")
            print(colored("Original file deleted.", "yellow"))
    except Exception as e:
        print(colored(f"Encryption failed: {e}", "red"))

def decrypt_file(encrypted_file_path: str, password: str):
    """
    Decrypts a .enc file and restores the original file using a custom password.
    """
    if not os.path.exists(encrypted_file_path):
        print(colored("Error: Encrypted file not found!", "red"))
        return
    
    key = load_key(password)
    original_file_path = encrypted_file_path.replace(".enc", "")
    
    with open(encrypted_file_path, "rb") as f:
        encrypted_data = f.read()
    
    try:
        cipher = Fernet(key)
        decrypted_data = cipher.decrypt(encrypted_data)
        
        with open(original_file_path, "wb") as f:
            f.write(decrypted_data)
        
        logging.info(f"Decrypted {encrypted_file_path} -> {original_file_path}")
        print(colored(f"File decrypted: {original_file_path}", "green"))
        os.remove(encrypted_file_path)
        print(colored("Encrypted file deleted after decryption.", "yellow"))
    except Exception as e:
        print(colored(f"Decryption failed: {e}", "red"))

if __name__ == "__main__":
    action = input("Choose action: (E)ncrypt or (D)ecrypt: ").strip().lower()
    
    if action == 'e':
        password = getpass.getpass(colored("Enter your encryption password: ", "cyan"))
        file_path = file_picker()
        encrypt_file(file_path, password)
    elif action == 'd':
        password = getpass.getpass(colored("Enter your decryption password: ", "cyan"))
        file_path = file_picker()
        decrypt_file(file_path, password)
    else:
        print(colored("Invalid choice.", "red"))
