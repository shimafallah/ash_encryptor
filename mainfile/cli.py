import argparse
import sys

from .constants import VERSION


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ash-encrypt",
        description="Encrypt and decrypt files and directories with AES-256-GCM",
    )
    parser.add_argument(
        "--version", action="version", version=f"ash-encrypt {VERSION}"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable debug logging"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    encrypt_parser = subparsers.add_parser(
        "encrypt", aliases=["e"], help="Encrypt a file or directory"
    )
    encrypt_parser.add_argument(
        "-f", "--file", required=True, help="Input file or directory path"
    )
    encrypt_parser.add_argument("-p", "--password", help="Encryption password")
    encrypt_parser.add_argument("-k", "--keyfile", help="Path to key file")

    decrypt_parser = subparsers.add_parser(
        "decrypt", aliases=["d"], help="Decrypt a .ash file"
    )
    decrypt_parser.add_argument(
        "-f", "--file", required=True, help="Input .ash file path"
    )
    decrypt_parser.add_argument("-p", "--password", help="Decryption password")
    decrypt_parser.add_argument("-k", "--keyfile", help="Path to key file")

    keygen_parser = subparsers.add_parser(
        "keygen", aliases=["k"], help="Generate a random key file"
    )
    keygen_parser.add_argument(
        "-o", "--output", required=True, help="Output path for the key file"
    )

    return parser


def parse_args(args=None) -> argparse.Namespace:
    parser = build_parser()
    parsed = parser.parse_args(args)

    if parsed.command is None:
        parser.print_help(sys.stderr)
        sys.exit(1)

    if parsed.command in ("encrypt", "e", "decrypt", "d"):
        if not parsed.password and not parsed.keyfile:
            print(
                "Error: at least one of -p/--password or -k/--keyfile is required",
                file=sys.stderr,
            )
            sys.exit(1)

    return parsed
