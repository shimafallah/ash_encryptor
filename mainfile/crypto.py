from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from .constants import NONCE_SIZE, TAG_SIZE, KEY_SIZE
from .exceptions import AuthenticationError


class CryptoCore:

    def encrypt(self, plaintext: bytes, key: bytes) -> bytes:
        if len(key) != KEY_SIZE:
            raise ValueError(f"Key must be {KEY_SIZE} bytes, got {len(key)}")
        nonce = get_random_bytes(NONCE_SIZE)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return nonce + tag + ciphertext

    def decrypt(self, data: bytes, key: bytes) -> bytes:
        if len(key) != KEY_SIZE:
            raise ValueError(f"Key must be {KEY_SIZE} bytes, got {len(key)}")
        if len(data) < NONCE_SIZE + TAG_SIZE:
            raise AuthenticationError("Data too short to contain valid encryption header")
        nonce = data[:NONCE_SIZE]
        tag = data[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
        ciphertext = data[NONCE_SIZE + TAG_SIZE:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except (ValueError, KeyError):
            raise AuthenticationError("Authentication failed (wrong password or key)")
        return plaintext

    def create_encrypt_cipher(self, key: bytes, nonce: bytes = None):
        if nonce is None:
            nonce = get_random_bytes(NONCE_SIZE)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher, nonce

    def finalize_encrypt(self, cipher) -> bytes:
        return cipher.digest()

    def create_decrypt_cipher(self, key: bytes, nonce: bytes):
        return AES.new(key, AES.MODE_GCM, nonce=nonce)

    def verify_decrypt(self, cipher, tag: bytes) -> None:
        try:
            cipher.verify(tag)
        except (ValueError, KeyError):
            raise AuthenticationError("Authentication failed (wrong password or key)")
