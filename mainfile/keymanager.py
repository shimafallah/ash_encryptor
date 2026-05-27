import hashlib
import os
from pathlib import Path

from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

from .constants import KEY_SIZE
from .exceptions import KeyDerivationError


class KeyManager:

    def derive_from_password(self, password: str) -> bytes:
        """Derive a 32-byte key from a password.

        Uses the legacy v0.2.0 derivation for backward compatibility:
        password + md5(password)[:32 - len(password)]
        """
        if len(password) > KEY_SIZE:
            raise KeyDerivationError(
                f"Password cannot be more than {KEY_SIZE} characters"
            )
        if not password:
            raise KeyDerivationError("Password cannot be empty")
        password_hash = hashlib.md5(password.encode()).hexdigest()
        combined = password + password_hash[:KEY_SIZE - len(password)]
        return combined.encode()

    def generate_key_file(self, path: Path) -> None:
        path = Path(path)
        if path.exists():
            raise KeyDerivationError(
                f"Key file '{path}' already exists, will not overwrite"
            )
        key_bytes = get_random_bytes(KEY_SIZE)
        path.write_bytes(key_bytes)

    def load_key_file(self, path: Path) -> bytes:
        """Load and validate a key file (must be exactly 32 bytes).

        Raises KeyDerivationError if file is missing, unreadable, or wrong size.
        """
        path = Path(path)
        if not path.exists():
            raise KeyDerivationError(f"Key file '{path}' not found")
        if not os.access(path, os.R_OK):
            raise KeyDerivationError(f"Cannot read key file '{path}'")
        key_bytes = path.read_bytes()
        if len(key_bytes) != KEY_SIZE:
            raise KeyDerivationError(
                f"Key file must be exactly {KEY_SIZE} bytes, got {len(key_bytes)}"
            )
        return key_bytes

    def derive_combined(self, key_file_bytes: bytes, password: str) -> bytes:
        """Derive a 32-byte key from key file + password using HKDF-SHA256.

        Args:
            key_file_bytes: 32 bytes from the key file (input keying material)
            password: user-supplied password (used as salt)

        Returns:
            32-byte derived key
        """
        if not password:
            raise KeyDerivationError("Password cannot be empty for combined auth")
        return HKDF(
            master=key_file_bytes,
            salt=password.encode("utf-8"),
            key_len=KEY_SIZE,
            hashmod=SHA256,
            context=b"",
        )
