import logging
import os
import sys
from pathlib import Path

from .cli import parse_args
from .constants import ARCHIVE_MAGIC, NONCE_SIZE, TAG_SIZE, VERSION
from .crypto import CryptoCore
from .exceptions import AshEncryptError, AuthenticationError, FileFormatError
from .keymanager import KeyManager
from .archive import ArchiveProcessor
from .stream import StreamProcessor
from .progress import ProgressReporter

logger = logging.getLogger("ash_encrypt")


def _resolve_key(args, key_manager: KeyManager) -> bytes:
    has_password = bool(args.password)
    has_keyfile = bool(args.keyfile)

    if has_keyfile and has_password:
        #? Combined auth: HKDF(key_file, password)
        key_bytes = key_manager.load_key_file(Path(args.keyfile))
        return key_manager.derive_combined(key_bytes, args.password)
    elif has_keyfile:
        return key_manager.load_key_file(Path(args.keyfile))
    elif has_password:
        return key_manager.derive_from_password(args.password)
    else:
        raise AshEncryptError("No authentication method provided")


def _is_archive(data: bytes) -> bool:
    return len(data) >= 4 and data[:4] == ARCHIVE_MAGIC

def _encrypt(args) -> None:
    key_manager = KeyManager()
    crypto = CryptoCore()
    key = _resolve_key(args, key_manager)

    input_path = Path(args.file)

    if not input_path.exists():
        raise FileFormatError(f"'{input_path}' not found")

    if input_path.is_dir():
        archive_proc = ArchiveProcessor()
        output_path = Path(f"{input_path.name}.ash")

        if output_path.exists():
            raise FileFormatError(
                f"'{output_path}' already exists, will not overwrite"
            )

        logger.debug(f"Collecting files from '{input_path}'...")
        manifest = archive_proc.collect_files(input_path)

        if not manifest.entries:
            print(
                f"Warning: no files found in '{input_path}'",
                file=sys.stderr,
            )

        logger.debug(f"Packing {len(manifest.entries)} files into archive...")
        archive_data = archive_proc.pack(manifest, input_path)

        logger.debug("Encrypting archive...")
        encrypted = crypto.encrypt(archive_data, key)

        output_path.write_bytes(encrypted)
        print(f"Directory encrypted as {output_path}", file=sys.stderr)

    else:
        if input_path.suffix == ".ash":
            raise FileFormatError("Cannot encrypt a .ash file")

        output_path = input_path.with_suffix(".ash")
        if output_path.exists():
            raise FileFormatError(
                f"'{output_path}' already exists, will not overwrite"
            )

        total_size = input_path.stat().st_size
        progress = ProgressReporter(total_size, "Encrypting")

        filename_header = f"({input_path.name})".encode("utf-8")

        if total_size > 10 * 1024 * 1024:
            #? Large file: use streaming encryption
            #? Write filename header + file content through streaming cipher
            stream = StreamProcessor()
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp.write(filename_header)
                with open(input_path, "rb") as f:
                    while True:
                        chunk = f.read(65536)
                        if not chunk:
                            break
                        tmp.write(chunk)
                tmp_path = Path(tmp.name)
            try:
                stream.encrypt_file(tmp_path, output_path, key, progress.update)
                progress.finish()
            finally:
                os.remove(tmp_path)
        else:
            #? Small file: in-memory encryption
            with open(input_path, "rb") as f:
                file_content = f.read()
                progress.update(total_size)

            plaintext = filename_header + file_content
            encrypted = crypto.encrypt(plaintext, key)
            output_path.write_bytes(encrypted)
            progress.finish()

        #? Remove original after successful encryption
        os.remove(input_path)
        print(f"File encrypted as {output_path}", file=sys.stderr)


def _decrypt(args) -> None:
    key_manager = KeyManager()
    crypto = CryptoCore()
    key = _resolve_key(args, key_manager)

    input_path = Path(args.file)

    if not input_path.exists():
        raise FileFormatError(f"'{input_path}' not found")
    if not input_path.is_file():
        raise FileFormatError(f"'{input_path}' is not a file")

    encrypted_data = input_path.read_bytes()

    plaintext = crypto.decrypt(encrypted_data, key)

    if _is_archive(plaintext):
        archive_proc = ArchiveProcessor()
        manifest, files = archive_proc.unpack(plaintext)
        output_dir = Path(".")

        archive_proc.restore(manifest, files, output_dir)
        os.remove(input_path)
        print(f"Directory decrypted as {manifest.name}/", file=sys.stderr)
    else:
        if plaintext[0:1] != b"(":
            raise FileFormatError("Invalid .ash file format")

        try:
            end_paren = plaintext.index(b")")
        except ValueError:
            raise FileFormatError("Invalid .ash file format (no filename delimiter)")

        original_filename = plaintext[1:end_paren].decode("utf-8")
        file_content = plaintext[end_paren + 1:]

        if Path(original_filename).exists():
            raise FileFormatError(
                f"'{original_filename}' already exists, will not overwrite"
            )

        with open(original_filename, "wb") as f:
            f.write(file_content)

        os.remove(input_path)
        print(f"File decrypted as {original_filename}", file=sys.stderr)


def _keygen(args) -> None:
    key_manager = KeyManager()
    output_path = Path(args.output)
    key_manager.generate_key_file(output_path)
    print(f"Key file generated: {output_path}", file=sys.stderr)


def main():
    try:
        args = parse_args()

        level = logging.DEBUG if args.verbose else logging.WARNING
        logging.basicConfig(
            level=level,
            format="%(levelname)s: %(message)s",
            stream=sys.stderr,
        )

        if args.command in ("encrypt", "e"):
            _encrypt(args)
        elif args.command in ("decrypt", "d"):
            _decrypt(args)
        elif args.command in ("keygen", "k"):
            _keygen(args)

        sys.exit(0)

    except AshEncryptError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        logger.debug("Unexpected error", exc_info=True)
        print(f"Error: unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)
