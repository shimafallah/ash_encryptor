import json
import logging
import os
import struct
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Tuple

from .constants import ARCHIVE_MAGIC, MAX_DEPTH, MAX_FILES
from .exceptions import FileFormatError

logger = logging.getLogger("ash_encrypt")


@dataclass
class FileEntry:
    path: str
    size: int


@dataclass
class DirectoryManifest:
    version: int
    name: str            
    entries: List[FileEntry]


class ArchiveProcessor:

    def collect_files(self, dir_path: Path) -> DirectoryManifest:
        """Recursively collect regular files from a directory.

        Skips symbolic links (with warning). Enforces MAX_DEPTH and MAX_FILES.
        Raises FileFormatError if path is invalid.
        """
        dir_path = Path(dir_path)
        if not dir_path.exists() or not dir_path.is_dir():
            raise FileFormatError(f"'{dir_path}' is not a valid directory")

        entries: List[FileEntry] = []
        self._collect_recursive(dir_path, dir_path, entries, depth=0)

        entries.sort(key=lambda e: e.path)

        return DirectoryManifest(
            version=1,
            name=dir_path.name,
            entries=entries,
        )

    def _collect_recursive(
        self, root: Path, current: Path, entries: List[FileEntry], depth: int
    ) -> None:
        if depth > MAX_DEPTH:
            logger.warning(f"Skipping '{current}': exceeds max depth of {MAX_DEPTH}")
            return

        try:
            items = sorted(current.iterdir())
        except PermissionError:
            logger.warning(f"Skipping '{current}': permission denied")
            return

        for item in items:
            if item.is_symlink():
                logger.warning(f"Skipping symbolic link: '{item}'")
                continue
            if item.is_file():
                if len(entries) >= MAX_FILES:
                    logger.warning(
                        f"Reached max file limit ({MAX_FILES}), skipping remaining"
                    )
                    return
                #! Use forward slash for cross-platform compatibility
                rel_path = item.relative_to(root).as_posix()
                size = item.stat().st_size
                entries.append(FileEntry(path=rel_path, size=size))
            elif item.is_dir():
                self._collect_recursive(root, item, entries, depth + 1)

    def pack(self, manifest: DirectoryManifest, dir_path: Path) -> bytes:
        """Serialize manifest + file contents into archive byte stream.

        Format: MAGIC (4B) + manifest_len (4B big-endian) + manifest JSON + file contents
        """
        dir_path = Path(dir_path)

        manifest_dict = {
            "version": manifest.version,
            "name": manifest.name,
            "entries": [asdict(e) for e in manifest.entries],
        }
        manifest_json = json.dumps(manifest_dict, ensure_ascii=False).encode("utf-8")

        parts = [
            ARCHIVE_MAGIC,
            struct.pack(">I", len(manifest_json)),
            manifest_json,
        ]

        for entry in manifest.entries:
            file_path = dir_path / entry.path.replace("/", os.sep)
            with open(file_path, "rb") as f:
                parts.append(f.read())

        return b"".join(parts)

    def unpack(self, data: bytes) -> Tuple[DirectoryManifest, Dict[str, bytes]]:

        if len(data) < 8 or data[:4] != ARCHIVE_MAGIC:
            raise FileFormatError("Invalid .ash archive format (bad magic bytes)")

        manifest_len = struct.unpack(">I", data[4:8])[0]
        if len(data) < 8 + manifest_len:
            raise FileFormatError("Invalid .ash archive format (truncated manifest)")

        manifest_json = data[8:8 + manifest_len].decode("utf-8")
        try:
            manifest_dict = json.loads(manifest_json)
        except json.JSONDecodeError as e:
            raise FileFormatError(f"Invalid archive manifest: {e}")

        manifest = DirectoryManifest(
            version=manifest_dict["version"],
            name=manifest_dict["name"],
            entries=[
                FileEntry(path=e["path"], size=e["size"])
                for e in manifest_dict["entries"]
            ],
        )

        files: Dict[str, bytes] = {}
        offset = 8 + manifest_len
        for entry in manifest.entries:
            if offset + entry.size > len(data):
                raise FileFormatError(
                    f"Invalid archive: truncated file data for '{entry.path}'"
                )
            files[entry.path] = data[offset:offset + entry.size]
            offset += entry.size

        return manifest, files

    def restore(
        self, manifest: DirectoryManifest, files: Dict[str, bytes], output_dir: Path
    ) -> None:
        output_dir = Path(output_dir)
        target = output_dir / manifest.name

        if target.exists():
            raise FileFormatError(
                f"'{target}' already exists, will not overwrite"
            )

        target.mkdir(parents=True)

        for entry in manifest.entries:
            local_path = target / entry.path.replace("/", os.sep)
            local_path.parent.mkdir(parents=True, exist_ok=True)
            with open(local_path, "wb") as f:
                f.write(files[entry.path])