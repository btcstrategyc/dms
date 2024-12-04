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
            iterations=600_000,  # High iteration count for better security
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    except Exception as e:
        raise ValueError("Key derivation failed.") from e


def decrypt_seed(encrypted_data, password):
    """
    Decrypts the seed using the provided password.
    Extracts the salt from the encrypted data.
    """
    try:
        if len(encrypted_data) < 32:
            raise ValueError("Encrypted data is too short to contain a valid salt.")
        salt = encrypted_data[:32]  # Extract the first 32 bytes as the salt
        encrypted_seed = encrypted_data[32:]  # Remaining bytes are the encrypted seed
        key = derive_key(password, salt)
        fernet = Fernet(key)
        seed = fernet.decrypt(encrypted_seed).decode("utf-8")
        secure_clear(key)  # Clear the derived key from memory
        return seed
    except Exception as e:
        raise ValueError("Decryption failed. Ensure the passphrase is correct.") from e


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


def load_file(filename, mode="rb"):
    """
    Loads data from a specified file.
    """
    with open(filename, mode) as file:
        return file.read()


def main():
    """
    Main program flow for decrypting the encrypted seed.
    """
    encrypted_file = "encrypted_seed.bin"
    try:
        # Load encrypted data
        encrypted_data = load_file(encrypted_file)
    except FileNotFoundError:
        print(f"Error: File '{encrypted_file}' not found. Ensure it exists.")
        return
    except Exception as e:
        print(f"Error loading file: {e}")
        return

    # Ask user for password
    password = input("\nEnter Decryption Passphrase:\n")

    try:
        # Decrypt the seed
        decrypted_seed = decrypt_seed(encrypted_data, password)
        print(f"\nDecrypted Seed:\n{decrypted_seed}")

        # Securely clear sensitive data from memory
        secure_clear(decrypted_seed)
        secure_clear(password)

    except ValueError as e:
        print(f"\nDecryption Failed! {e}")
    except Exception as e:
        print(f"\nUnexpected Error: {e}")

    input("\n>>> Press Enter To Exit <<<")


if __name__ == "__main__":
    main()
