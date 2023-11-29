from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import urlsafe_b64encode, urlsafe_b64decode
from config import *


key = C_KEY
message_input = input("Enter the message to decrypt: ")
encrypted_message = message_input.encode("utf-8")


def decrypt(ciphertext, key):
    # Decode the base64-encoded ciphertext
    ciphertext = urlsafe_b64decode(ciphertext)

    # Create an AES cipher object
    cipher = Cipher(algorithms.AES(key), modes.ECB(),
                    backend=default_backend())

    # Decrypt the data
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the data
    unpadder = padding.PKCS7(128).unpadder()
    message = unpadder.update(padded_data) + unpadder.finalize()

    # Return the decrypted message
    return message


# Decrypt the message
decrypted_message = decrypt(encrypted_message, key)
print(f'Decrypted Message: {decrypted_message.decode("utf-8")}')
