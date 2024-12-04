import os
import base64
import ctypes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.fernet import Fernet


def derive_key(password, salt):
    """
    Derives a cryptographic key from the password and salt using PBKDF2-HMAC.
    """
    try:
        kdf = PBKDF2HMAC(
            algorithm=SHA256(),
            length=32,
            salt=salt,
            iterations=600_000,  # Increased iteration count
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    except Exception as e:
        raise ValueError("Error deriving key") from e


def encrypt_seed(seed, password):
    """
    Encrypts the seed using the provided password and a random salt.
    Embeds the salt into the encrypted data.
    """
    try:
        salt = os.urandom(32)  # Increased salt size for additional entropy
        key = derive_key(password, salt)
        fernet = Fernet(key)
        encrypted_seed = fernet.encrypt(seed.encode("utf-8"))
        secure_clear(key)  # Clear key from memory
        return salt + encrypted_seed  # Prepend salt to the encrypted data
    finally:
        # Securely clear sensitive data
        secure_clear(seed)
        secure_clear(password)


def save_to_file(data, filename, mode="wb"):
    """
    Saves data to a specified file.
    """
    with open(filename, mode) as file:
        file.write(data)


def secure_clear(data):
    """
    Overwrites the contents of sensitive data with zeros.
    """
    if isinstance(data, str):
        # Convert string to bytearray for secure clearing
        data = bytearray(data, "utf-8")
    if isinstance(data, (bytearray, memoryview)):
        length = len(data)
        ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(data)), 0, length)
    del data  # Hint to Python's garbage collector to remove the variable


def main():
    """
    Main program flow for encrypting a seed and saving the result.
    """
    seed = input("\n1. Enter Seed:\n")
    password = input("\n2. Enter Encryption Passphrase:\n")

    try:
        # Encrypt the seed
        encrypted_data = encrypt_seed(seed, password)

        # Save the encrypted data (with embedded salt) as a binary file
        save_to_file(encrypted_data, "encrypted_seed.bin")
        print("\n3. Encrypted Seed Saved As 'encrypted_seed.bin'")

    except Exception as e:
        print(f"\nAn error occurred: {e}")

    input("\n>>> Press Enter To Exit <<<")


if __name__ == "__main__":
    main()
