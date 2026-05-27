"""ash-encrypt — Encrypt and decrypt files and directories with AES-256-GCM."""

from .constants import VERSION
from .crypto import CryptoCore
from .keymanager import KeyManager
from .archive import ArchiveProcessor
from .stream import StreamProcessor
from .exceptions import (
    AshEncryptError,
    AuthenticationError,
    FileFormatError,
    KeyDerivationError,
)

__version__ = VERSION
__all__ = [
    "VERSION",
    "CryptoCore",
    "KeyManager",
    "ArchiveProcessor",
    "StreamProcessor",
    "AshEncryptError",
    "AuthenticationError",
    "FileFormatError",
    "KeyDerivationError",
]
