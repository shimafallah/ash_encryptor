class AshEncryptError(Exception):
    """Base exception for all ash-encrypt errors."""


class AuthenticationError(AshEncryptError):
    """GCM tag verification failed (wrong password or key)."""


class FileFormatError(AshEncryptError):
    """Invalid .ash file format or archive structure."""


class KeyDerivationError(AshEncryptError):
    """Key file invalid or key derivation failed."""
