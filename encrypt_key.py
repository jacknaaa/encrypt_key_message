from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import urlsafe_b64encode, urlsafe_b64decode
from config import *


def encrypt(message, key):
    # Pad the message to be a multiple of 16 bytes
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message) + padder.finalize()

    # Create an AES cipher object
    cipher = Cipher(algorithms.AES(key), modes.ECB(),
                    backend=default_backend())

    # Encrypt the data
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Return the base64-encoded ciphertext
    return urlsafe_b64encode(ciphertext)


# Example usage with a valid key size (256 bits)
key = C_KEY
message_input = input("Enter the message to encrypt: ")
message = message_input.encode("utf-8")

# Encrypt the message
encrypted_message = encrypt(message, key)
print(f'Encrypted Message: {encrypted_message}')
