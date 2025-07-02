from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from os import urandom
import base64

class AESEncryptionTool:
    def __init__(self, password: str):
        self.backend = default_backend()
        self.salt = urandom(16)  # Generate a random salt
        self.key = self._derive_key(password)

    def _derive_key(self, password: str):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # AES-256 requires a 32-byte key
            salt=self.salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(password.encode())

    def encrypt(self, plaintext: str):
        iv = urandom(16)  # Generate a random initialization vector
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        # Pad the plaintext to be a multiple of the block size
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(self.salt + iv + ciphertext).decode()

    def decrypt(self, encrypted_data: str):
        encrypted_data = base64.b64decode(encrypted_data)
        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]

        # Re-derive the key using the same salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        key = kdf.derive(password.encode())

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()

        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext.decode()

# Example usage
password = "strongpassword123"
tool = AESEncryptionTool(password)

# Encrypt
plaintext = "This is a secret message."
encrypted = tool.encrypt(plaintext)
print("Encrypted:", encrypted)

# Decrypt
decrypted = tool.decrypt(encrypted)
print("Decrypted:", decrypted)