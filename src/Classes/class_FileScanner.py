# OOP Virus Scanner Pre-Push Hook Library
from typing import Any, Dict, List, Optional
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

try:
    import requests
except Exception:
    requests = None  # type: ignore

class FileScanner:
        """ 
    Handles per-file scanning helpers: detection of binary, hashing, and chunking.
    Example:
        scanner = FileScanner('/path/to/file')
        is_bin = scanner.is_binary
        file_hash = scanner.sha256 
    """
    def __init__(self, file_path: str):
        self._file_path = file_path
        if not os.path.exists(self._file_path):
            raise FileNotFoundError(f"File not found: {self._file_path}")
        self._sha256: Optional[str] = None
        self._is_binary: Optional[bool] = None

    @property
    def path(self) -> str:
        return self._file_path

    @property
    def is_binary(self) -> bool:
        if self._is_binary is None:
            try:
                with open(self._file_path, "rb") as f:
                    chunk = f.read(4096)
                self._is_binary = b"\x00" in chunk
            except FileNotFoundError:
                self._is_binary = False
        return self._is_binary

    @property
    def sha256(self) -> str:
        if self._sha256 is None:
            hasher = hashlib.sha256()
            with open(self._file_path, "rb") as f:
                for block in iter(lambda: f.read(1024 * 1024), b""):
                    hasher.update(block)
            self._sha256 = hasher.hexdigest()
        return self._sha256

    def chunk_for_upload(self, max_chunk_bytes: int) -> List[bytes]:
        if max_chunk_bytes <= 0:
            raise ValueError("max_chunk_bytes must be positive")
        chunks: List[bytes] = []
        with open(self._file_path, "rb") as f:
            while True:
                data = f.read(max_chunk_bytes)
                if not data:
                    break
                chunks.append(data)
        return chunks

    def __str__(self):
        return f"FileScanner(path={self._file_path})"

    def __repr__(self):
        return f"<FileScanner(path={self._file_path})>"