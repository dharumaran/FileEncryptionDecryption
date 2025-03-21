import os
from cryptography.fernet import Fernet

def generate_key():
    """
    Generates a key and saves it into a file.
    """
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    """
    Loads the key from the current directory named `secret.key`.
    """
    return open("secret.key", "rb").read()

def encrypt_file(file_name):
    """
    Given a filename (str) and key (bytes), it encrypts the file and writes it.
    """
    key = load_key()
    f = Fernet(key)

    with open(file_name, "rb") as file:
        # read all file data
        file_data = file.read()
    # encrypt data
    encrypted_data = f.encrypt(file_data)

    # write the encrypted file
    with open(file_name, "wb") as file:
        file.write(encrypted_data)

def decrypt_file(file_name):
    """
    Given a filename (str) and key (bytes), it decrypts the file and writes it.
    """
    key = load_key()
    f = Fernet(key)

    with open(file_name, "rb") as file:
        # read the encrypted data
        encrypted_data = file.read()
    # decrypt data
    decrypted_data = f.decrypt(encrypted_data)

    # write the original file
    with open(file_name, "wb") as file:
        file.write(decrypted_data)

if __name__ == "__main__":
    generate_key()
    encrypt_file("example.txt")
    # To decrypt the file, use:
    # decrypt_file("example.txt")