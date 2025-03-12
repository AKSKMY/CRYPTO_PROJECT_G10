from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import os

SECRET_KEY = b"supersecretkey1234567890123456"

def derive_key(salt):
    """Derives a 256-bit AES key from a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    return kdf.derive(SECRET_KEY)

def encrypt_message(plaintext):
    """Encrypts a message using AES-256."""
    salt = os.urandom(16)
    key = derive_key(salt)
    iv = os.urandom(16)  # AES block size
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    padded_plaintext = plaintext + ' ' * (16 - len(plaintext) % 16)  # Pad to 16-byte blocks
    ciphertext = encryptor.update(padded_plaintext.encode()) + encryptor.finalize()

    return base64.b64encode(salt + iv + ciphertext).decode()

def decrypt_message(encrypted_text):
    """Decrypts a message using AES-256."""
    encrypted_data = base64.b64decode(encrypted_text)
    salt, iv, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    key = derive_key(salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    return decrypted_padded.rstrip().decode()  # Remove padding