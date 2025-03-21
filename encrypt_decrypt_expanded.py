import os
import logging
import getpass
from cryptography.fernet import Fernet
import base64
import hashlib

# Setup logging
LOG_FILE = "logs/encryptor.log"
os.makedirs("logs", exist_ok=True)
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Secure Key Storage
KEY_FILE = "secret_storage/secure.key"
os.makedirs("secret_storage", exist_ok=True)

def derive_key(password: str) -> bytes:
    """
    Derives a key from the user's password using SHA-256.
    """
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

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

def encrypt_file(file_path: str, password: str):
    """
    Encrypts a file and saves it with a .enc extension.
    """
    key = load_key(password)
    cipher = Fernet(key)
    
    with open(file_path, "rb") as f:
        file_data = f.read()
    encrypted_data = cipher.encrypt(file_data)
    
    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, "wb") as f:
        f.write(encrypted_data)
    
    logging.info(f"Encrypted {file_path} -> {encrypted_file_path}")
    print(f"File encrypted: {encrypted_file_path}")

def decrypt_file(encrypted_file_path: str, password: str):
    """
    Decrypts a .enc file and restores the original file.
    """
    key = load_key(password)
    cipher = Fernet(key)
    
    with open(encrypted_file_path, "rb") as f:
        encrypted_data = f.read()
    decrypted_data = cipher.decrypt(encrypted_data)
    
    original_file_path = encrypted_file_path.replace(".enc", "")
    with open(original_file_path, "wb") as f:
        f.write(decrypted_data)
    
    logging.info(f"Decrypted {encrypted_file_path} -> {original_file_path}")
    print(f"File decrypted: {original_file_path}")

if __name__ == "__main__":
    user_password = getpass.getpass("Enter your encryption password: ")
    
    if not os.path.exists(KEY_FILE):
        save_key(user_password)
    
    action = input("Choose action: (E)ncrypt or (D)ecrypt: ").strip().lower()
    file_path = input("Enter file path: ").strip()
    
    if action == 'e':
        encrypt_file(file_path, user_password)
    elif action == 'd':
        decrypt_file(file_path, user_password)
    else:
        print("Invalid choice.")
