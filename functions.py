from typing import Dict, Any, Optional
from pathlib import Path
import json
import requests
import os
import hashlib

def load_config(config_path: str) -> Dict[str, Any]:
    """ Load configuration from a JSON file. 
    The config is expected to include keys like api_key, base_url, timeout_s.
    """
    if not isinstance (config_path, str):
        raise TypeError("config_path must be a string.")
    
    path = Path(config_path)
    if not path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    if path.suffix.lower() != '.json':
        raise ValueError(f"Configuration file must be a JSON file.")
    try:
        with path.open('r', encoding='utf-8') as f:
            config_data = json.load(f)
    except json.JSONDecodeError:
            raise ValueError("Configuration file is not a valid JSON.")
            
    return config_data
    
def validate_config(config: Dict[str, Any]) -> None:

    """ Validate that the configuration dictionary contains required keys with correct types. """
    
    if not isinstance(config, dict):
        raise TypeError("Config must be a dictionary.")
    
    required_keys = {
        "api_key": str,
        "base_url": str,
        "timeout_s": (int, float)
    }

    for key, expected_type in required_keys.items():
        if key not in config:
            raise KeyError(f"Missing required config key: {key}")
        if not isinstance(config[key], expected_type):
            raise TypeError(f"Config key '{key}' must be of type {expected_type}.")
        
    base_url: str = config["base_url"]
    if not (base_url.startswith("http://") or base_url.startswith("https://")):
        raise ValueError("base_url must start with 'http://' or 'https://'.")
    
    print("Configuration is valid.")

def build_api_client(api_key: str, base_url: str, timeout_s: float) -> Any:
    
    if requests is None:
        raise ImportError("The 'requests' library is required to build the API client.")
    
    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    })
    setattr(session, 'base_url', base_url.rstrip('/'))
    setattr(session, 'default_timeout_s', float(timeout_s))
    return session

def detect_git_repository_root(start_dir: Optional[str] = None) -> str:
    """ Detect the root directory of a Git repository starting from start_dir or current working directory. """
    current = Path(start_dir or os.getcwd()).resolve()
    root = Path(current.root)
    while True: 
        if (current / '.git').is_dir():
            return str(current)
        if current == root:
            raise FileNotFoundError("No Git repository found in the directory.")
        current = current.parent

#Scanning Multiple Files
def scan_multiple_files():
    upload_files = input("Enter file paths to scan (comma-separated): ").strip()
    if not upload_files:
        print("No files provided for scanning.")
        return {}

    file_paths = [path.strip() for path in upload_files.split(",")]
    results = {}

    for file_path in file_paths:
        if not os.path.exists(file_path):
            results[file_path] = "Error: File not found."
            continue

        print(f"\nScanning {file_path}...")

#Supported File Extensions 
def supported_filetype(file_path):
  supported_extensions = {'.pdf', '.exe', '.js', '.py', '.png', '.jpg', '.csv', '.html', '.txt'}
  for ext in supported_extensions:
    if file_path.endswith(ext):
      return True
  return False

#Pre-Push Hook Install
import os
from virus_check import scan_multiple_files

def install_pre_push_hook():

    print("Installing simulated pre-push hook...")

    def pre_push_hook():
        print("\nPre-push hook triggered. Scanning files with VirusTotal...")

        scan_results = scan_multiple_files()

        infected_files = []
        for file_path, result in scan_results.items():
            if isinstance(result, dict) and result.get("malicious", 0) > 0:
                infected_files.append(file_path)

        if infected_files:
            print("\nPush blocked! Infected files detected:")
            for f in infected_files:
                print(f"  - {f}")
            print("\nPlease remove or clean infected files before pushing.")
            return False
        else:
            print("\nAll files are clean. Safe to push.")
            return True

    print("Pre-push hook installed successfully.") 
    return pre_push_hook

#Should Block Push
def should_block_push(scan_results):  

    for file_path, result in scan_results.items():
        if isinstance(result, dict) and result.get("malicious", 0) > 0:
            print(f"Infected file: {file_path}")
            return True
        if isinstance(result, str) and "malicious" in result.lower():
            print(f"Infected file: {file_path}")
            return True
    return False

# Git and file functions

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
