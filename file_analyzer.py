#!/usr/bin/env python3
"""File Analyzer: inspect files, metadata, MIME type, and hashes."""

from __future__ import annotations

import argparse
import hashlib
import mimetypes
from pathlib import Path


def format_size(size: int) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.2f} {unit}" if unit != "B" else f"{size} B"
        value /= 1024
    return f"{size} B"


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def is_probably_text(path: Path) -> bool:
    try:
        with path.open("rb") as file:
            sample = file.read(8192)
        if b"\x00" in sample:
            return False
        sample.decode("utf-8")
        return True
    except (OSError, UnicodeDecodeError):
        return False


def analyze(path: Path) -> dict[str, object]:
    stat = path.stat()
    mime_type, _ = mimetypes.guess_type(path.name)
    return {
        "name": path.name,
        "path": str(path.resolve()),
        "size": stat.st_size,
        "size_human": format_size(stat.st_size),
        "mime": mime_type or "application/octet-stream",
        "type": "text" if is_probably_text(path) else "binary",
        "sha256": sha256_file(path),
        "modified": stat.st_mtime,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze a file and display useful metadata.")
    parser.add_argument("file", type=Path, help="File to analyze")
    args = parser.parse_args()

    path = args.file
    if not path.exists():
        parser.error(f"file not found: {path}")
    if not path.is_file():
        parser.error(f"not a regular file: {path}")

    try:
        info = analyze(path)
    except OSError as exc:
        parser.error(f"cannot analyze file: {exc}")

    print(f"Name:       {info['name']}")
    print(f"Path:       {info['path']}")
    print(f"Size:       {info['size_human']}")
    print(f"MIME type:  {info['mime']}")
    print(f"Content:    {info['type']}")
    print(f"SHA-256:    {info['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
