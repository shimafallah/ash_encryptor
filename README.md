# ash-encrypt

Encrypt and decrypt files and directories with AES-256-GCM.

[![PyPI version](https://img.shields.io/pypi/v/ash-encrypt?cache=false)](https://pypi.org/project/ash-encrypt/)
[![Python versions](https://img.shields.io/pypi/pyversions/ash-encrypt)](https://pypi.org/project/ash-encrypt/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

## Features

- **AES-256-GCM encryption** — authenticated encryption with strong confidentiality and integrity guarantees
- **File and directory support** — encrypt individual files or entire directories
- **Simple CLI** — intuitive command-line interface with encrypt/decrypt modes
- **Progress bars** — visual feedback for large file operations via tqdm
- **Streaming encryption** — handles large files without loading them entirely into memory
- **Cross-platform** — works on Linux, macOS, and Windows

## Installation

```bash
pip install ash-encrypt
```

## Quick Start

### Encrypt a file

```bash
ash-encrypt e -p <password> -f <file>
```

This produces a `.ash` encrypted file. For example:

```bash
ash-encrypt e -p mysecretpass -f document.pdf
# Output: document.ash
```

### Decrypt a file

```bash
ash-encrypt d -p <password> -f <file.ash>
```

```bash
ash-encrypt d -p mysecretpass -f document.ash
# Output: document.pdf
```

### CLI Flags

| Flag | Description |
|------|-------------|
| `e`  | Encryption mode |
| `d`  | Decryption mode |
| `-p` | Password |
| `-f` | File or directory path |

## Supported Platforms

- Linux
- macOS
- Windows

## Requirements

- Python 3.8+
- [pycryptodome](https://pypi.org/project/pycryptodome/) >= 3.15
- [tqdm](https://pypi.org/project/tqdm/) >= 4.60

## Development

Clone the repository and install with dev dependencies:

```bash
git clone https://github.com/shimafallah/ash_encryptor.git
cd ash_encryptor
pip install -e ".[dev]"
```

## License

[MIT](LICENSE)

## Links

- **GitHub:** https://github.com/shimafallah/ash_encryptor
- **PyPI:** https://pypi.org/project/ash-encrypt/
