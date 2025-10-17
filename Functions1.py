# Functions for part 1 of the project!
import os
import hashlib


def get_staged_file_paths() -> list[str]:
    # Retrieves all file paths that are currently staged in Git.
    stream = os.popen('git diff --cached --name-only')
    output = stream.read()
    stream.close()

    staged_files = output.strip().split('\n')
    return [f for f in staged_files if f]  # Filter empty strings


def is_binary_file(file_path: str) -> bool:
    # Determines if a file is binary or text-based and returns True if file is binary, False if text
    _, ext = os.path.splitext(file_path)
    binary_extensions = {'.exe', '.dll', '.so', '.dylib', '.bin', '.dat',
                         '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.zip',
                         '.tar', '.gz', '.mp3', '.mp4', '.avi'}

    if ext.lower() in binary_extensions:
        return True

    # Read first 8KB to check for null bytes (binary indicator)
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(8192)
            return b'\x00' in chunk
    except (IOError, OSError):
        return False


def compute_file_sha256(file_path: str) -> str:
    # Computes SHA-256 hash of a file for virus scanning API submission.
    sha256_hash = hashlib.sha256()

    with open(file_path, 'rb') as f:
        # Read file in chunks to handle large files efficiently
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)

    return sha256_hash.hexdigest()


def chunk_file_for_upload(file_path: str, chunk_size_mb: int = 32) -> list[bytes]:
    # Splits a file into chunks for uploading to virus scanning API and returns List of file chunks as bytes
    chunks = []
    chunk_size_bytes = chunk_size_mb * 1024 * 1024
    file_size = os.path.getsize(file_path)
    total_chunks = 0
    bytes_processed = 0
    if file_size <= chunk_size_bytes:
        with open(file_path, 'rb') as f:
            data = f.read()
            chunks.append(data)
            total_chunks = 1
            bytes_processed = len(data)
        return chunks
    with open(file_path, 'rb') as f:
        chunk_index = 0
        while True:
            chunk = f.read(chunk_size_bytes)
            if not chunk:
                break
            chunks.append(chunk)
            chunk_index += 1
            bytes_processed += len(chunk)
            total_chunks += 1
            progress = (bytes_processed / file_size) * 100
            if chunk_index % 5 == 0:
                print(f"Processed {chunk_index} chunks ({progress:.1f}%)")
    return chunks
