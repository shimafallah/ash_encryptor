import logging
import os
from pathlib import Path
from typing import Callable, Optional

from .constants import CHUNK_SIZE, NONCE_SIZE, TAG_SIZE
from .crypto import CryptoCore
from .exceptions import AshEncryptError, AuthenticationError

logger = logging.getLogger("ash_encrypt")


class StreamProcessor:

    def __init__(self, chunk_size: int = CHUNK_SIZE):
        self.chunk_size = chunk_size
        self.crypto = CryptoCore()

    def encrypt_file(
        self,
        input_path: Path,
        output_path: Path,
        key: bytes,
        progress_callback: Optional[Callable[[int], None]] = None,
    ) -> None:
        input_path = Path(input_path)
        output_path = Path(output_path)
        total_size = input_path.stat().st_size

        cipher, nonce = self.crypto.create_encrypt_cipher(key)

        try:
            with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
                fout.write(nonce)
                tag_offset = fout.tell()
                fout.write(b"\x00" * TAG_SIZE)

                #? Stream encrypt in chunks
                bytes_processed = 0
                while True:
                    chunk = fin.read(self.chunk_size)
                    if not chunk:
                        break
                    encrypted_chunk = cipher.encrypt(chunk)
                    fout.write(encrypted_chunk)
                    bytes_processed += len(chunk)
                    if progress_callback:
                        progress_callback(len(chunk))

                #? Get the tag and seek back to write it
                tag = self.crypto.finalize_encrypt(cipher)
                fout.seek(tag_offset)
                fout.write(tag)

        except (IOError, OSError) as e:
            if output_path.exists():
                os.remove(output_path)
            raise AshEncryptError(f"I/O failure reading '{input_path}': {e}")

    def decrypt_file(
        self,
        input_path: Path,
        output_path: Path,
        key: bytes,
        progress_callback: Optional[Callable[[int], None]] = None,
    ) -> None:
        input_path = Path(input_path)
        output_path = Path(output_path)

        file_size = input_path.stat().st_size
        if file_size < NONCE_SIZE + TAG_SIZE:
            raise AuthenticationError("File too small to contain valid encryption header")

        ciphertext_size = file_size - NONCE_SIZE - TAG_SIZE

        try:
            with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
                nonce = fin.read(NONCE_SIZE)
                tag = fin.read(TAG_SIZE)

                cipher = self.crypto.create_decrypt_cipher(key, nonce)

                bytes_remaining = ciphertext_size
                while bytes_remaining > 0:
                    read_size = min(self.chunk_size, bytes_remaining)
                    chunk = fin.read(read_size)
                    if not chunk:
                        break
                    decrypted_chunk = cipher.decrypt(chunk)
                    fout.write(decrypted_chunk)
                    bytes_remaining -= len(chunk)
                    if progress_callback:
                        progress_callback(len(chunk))

                self.crypto.verify_decrypt(cipher, tag)

        except AuthenticationError:
            if output_path.exists():
                os.remove(output_path)
            raise
        except (IOError, OSError) as e:
            if output_path.exists():
                os.remove(output_path)
            raise AshEncryptError(f"I/O failure reading '{input_path}': {e}")
