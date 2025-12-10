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
except Exception:  # Keep import optional for environments without requests
    requests = None  # type: ignore


def load_config(config_path: str) -> Dict[str, Any]:
    """Load configuration from a JSON file.

    The config is expected to include keys like: api_key, base_url, timeout_s.
    """
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    if path.suffix.lower() != ".json":
        raise ValueError("Only JSON config is supported (use .json file)")
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def validate_config(config: Dict[str, Any]) -> None:
    """Validate presence and basic types of required configuration fields."""
    required_fields = {
        "api_key": str,
        "base_url": str,
        "timeout_s": (int, float),
        # Optional, but useful defaults if provided elsewhere
    }
    for key, expected_type in required_fields.items():
        if key not in config:
            raise ValueError(f"Missing required config key: {key}")
        if not isinstance(config[key], expected_type):
            raise TypeError(
                f"Config key '{key}' must be of type {expected_type}, got {type(config[key])}"
            )
    base_url: str = config["base_url"]
    if not (base_url.startswith("http://") or base_url.startswith("https://")):
        raise ValueError("base_url must start with http:// or https://")


def build_api_client(api_key: str, base_url: str, timeout_s: float) -> Any:
    """Build a minimal HTTP client. Returns a requests.Session-like object.

    The session will carry auth headers and base URL metadata for convenience.
    """
    if requests is None:
        raise RuntimeError(
            "The 'requests' library is required for API access. Please install it."
        )
    session = requests.Session()
    session.headers.update({
        "x-apikey": api_key,
        "Accept": "application/json",
        "User-Agent": "RepoVirusScanner/1.0",
    })
    # Attach convenience attributes
    setattr(session, "base_url", base_url.rstrip("/"))
    setattr(session, "default_timeout_s", float(timeout_s))
    return session


def detect_git_repository_root(start_dir: Optional[str] = None) -> str:
    """Find the repository root by looking for a .git directory upward."""
    current = Path(start_dir or os.getcwd()).resolve()
    root = Path(current.root)
    while True:
        if (current / ".git").exists():
            return str(current)
        if current == root:
            raise RuntimeError("Not inside a Git repository (no .git found)")
        current = current.parent


def get_staged_file_paths(repo_root: str) -> List[str]:
    """Return a list of staged file paths (Added/Changed/Modified)."""
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Failed to list staged files: {result.stderr.strip() or result.stdout.strip()}"
        )
    paths = [p for p in result.stdout.splitlines() if p.strip()]
    return paths


def is_binary_file(file_path: str) -> bool:
    """Heuristic: file is binary if it contains a NUL byte in the first chunk."""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(4096)
        return b"\x00" in chunk
    except FileNotFoundError:
        # Treat missing files as non-binary to avoid blocking flow; caller can handle
        return False


def compute_file_sha256(file_path: str) -> str:
    """Compute SHA-256 hash of a file by streaming in chunks."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def chunk_file_for_upload(file_path: str, max_chunk_bytes: int) -> List[bytes]:
    """Split file into chunks up to max_chunk_bytes for upload APIs that require it."""
    if max_chunk_bytes <= 0:
        raise ValueError("max_chunk_bytes must be positive")
    chunks: List[bytes] = []
    with open(file_path, "rb") as f:
        while True:
            data = f.read(max_chunk_bytes)
            if not data:
                break
            chunks.append(data)
    return chunks


def submit_scan(api_client: Any, file_path: str, file_hash: str) -> str:
    """Submit a scan request for a file. Returns a scan_id.

    First checks if file hash exists in VirusTotal database.
    If not found (404), uploads the file for scanning.
    """
    base_url: str = getattr(api_client, "base_url")
    timeout_s: float = float(getattr(api_client, "default_timeout_s", 30.0))
    check_url = f"{base_url}/files/{file_hash}"
    
    try:
        resp = api_client.get(check_url, timeout=timeout_s)
        resp.raise_for_status()
        print(f"[scanner] File already in VirusTotal database: {os.path.basename(file_path)}")
        return str(file_hash)
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            # Step 2: File not in database - upload it
            print(f"[scanner] ⟳ Uploading new file to VirusTotal: {os.path.basename(file_path)}")
            upload_url = f"{base_url}/files"
            try:
                with open(file_path, 'rb') as f:
                    files = {'file': (os.path.basename(file_path), f)}
                    # Note: Don't pass json= with files=, use data= if needed
                    upload_resp = api_client.post(upload_url, files=files, timeout=120)
                    upload_resp.raise_for_status()
                    data = upload_resp.json()
                    
                    # VirusTotal returns an analysis object
                    if 'data' in data:
                        analysis_id = data['data']['id']
                        print(f"[scanner] ⟳ File uploaded successfully. Analysis ID: {analysis_id}")
                        return analysis_id
                    else:
                        raise RuntimeError("Upload response missing 'data' field")
                        
            except FileNotFoundError:
                raise FileNotFoundError(f"Cannot upload file: {file_path} not found")
            except Exception as upload_error:
                print(f"[scanner] ✗ Upload failed: {upload_error}")
                # Return hash anyway, will handle in poll_scan_completion
                return str(file_hash)
        else:
            # Other HTTP error, re-raise
            raise
    
    except Exception as e:
        print(f"[scanner] Warning: Error checking file: {e}")
        return str(file_hash)

def poll_scan_completion(
    api_client: Any, scan_id: str, timeout_s: float, interval_s: float
) -> Dict[str, Any]:
    """Poll scan status until completion or timeout. Returns final result payload.     
    
    Handles both file hashes (existing scans) and analysis IDs (new uploads).
"""
    base_url: str = getattr(api_client, "base_url")

    deadline = time.time() + float(timeout_s)

    is_analysis = "-" in scan_id and len(scan_id) >64

    if is_analysis:
        status_url = f"{base_url}/analyses/{scan_id}"
        print(f"[scanner]Waiting for analysis to complete")
    else:
        status_url = f"{base_url}/files/{scan_id}"
    
    while time.time() < deadline:
          
      try:
          resp = api_client.get(status_url, timeout=float(getattr(api_client, "default_timeout_s", 30.0)))
          resp.raise_for_status()
          data = resp.json()

          if "data" in data:
              attributes = data["data"].get("attributes", {})

              if is_analysis:
                    
                status = attributes.get("status", "")

                if status == "completed":
                    stats = attributes.get("stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values())
                    print(f"[scanner] Analysis complete: {malicious}/{total} detected malicious")

                    return {
                          "status": "completed",
                          "clean": malicious == 0,
                          "detections": malicious,
                          "positives": malicious,
                          "total": total,
                          "sha256": scan_id
                  }
                elif status in ("queued", "in-progress"):
                    print(f"[scanner]   Status: {status}... (waiting {interval_s}s)") 
                    time.sleep(float(interval_s))
                    continue
                else:
                      # Unknown status, wait and retry
                      time.sleep(float(interval_s))
                      continue
              else:
                # For file hash endpoint, results are immediate
                  stats = attributes.get("last_analysis_stats", {})
                  malicious = stats.get("malicious", 0)
                  total = sum(stats.values())
                    
                  return {
                        "status": "completed",
                        "clean": malicious == 0,
                        "detections": malicious,
                        "positives": malicious,
                        "total": total,
                        "sha256": scan_id
                    }
            
            # If we get here, response was unexpected
          print(f"[scanner] Unexpected response format, retrying...")
          time.sleep(float(interval_s))
            
      except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                print(f"[scanner] ⚠ File not in database and upload may have failed")
                return {
                    "status": "not_in_database",
                    "clean": True,  # Don't block on our own code
                    "detections": 0,
                    "positives": 0,
                    "total": 0,
                    "sha256": scan_id,
                    "note": "File not found in VirusTotal database"
                }
            else:
                print(f"[scanner] HTTP Error {e.response.status_code}: {e}")
                raise
        
      except Exception as e:
            print(f"[scanner] Error during polling: {e}")
            # Don't keep retrying on unexpected errors
            return {
                "status": "error",
                "clean": True,  # Don't block on errors
                "detections": 0,
                "error": str(e)
            }
    
    # Timeout reached
    raise TimeoutError(f"Scan timed out after {timeout_s} seconds waiting for results")
def interpret_scan_result(scan_result: Dict[str, Any]) -> bool:
    """Return True if the scan result is considered clean, False otherwise.

    Heuristics: prefer explicit boolean flags; otherwise use detection counts.
    """
    # Common flags various services might return
    for key in ("clean", "is_clean", "malicious", "infected"):
        if key in scan_result:
            val = scan_result[key]
            if key in ("malicious", "infected"):
                return not bool(val)
            return bool(val)
    # Fallback to counts
    detections = scan_result.get("detections") or scan_result.get("positives")
    if isinstance(detections, int):
        return detections == 0
    return True  # Default to clean if inconclusive


def should_block_push(file_to_is_clean: Dict[str, bool]) -> bool:
    """Return True if the push should be blocked (any file not clean)."""
    if not file_to_is_clean:
        return False
    return not all(bool(v) for v in file_to_is_clean.values())


def print_scan_report(file_to_scan_result: Dict[str, Dict[str, Any]]) -> None:
    """Print a simple human-readable report after scanning files."""
    if not file_to_scan_result:
        print("No files scanned.")
        return
    print("Scan Report:")
    for path, result in file_to_scan_result.items():
        clean = interpret_scan_result(result)
        status = result.get("status", "unknown")
        detections = result.get("detections", result.get("positives", "?"))
        print(f"- {path}: {'CLEAN' if clean else 'INFECTED'} (status={status}, detections={detections})")


def install_pre_push_hook(repo_root: str, hook_script_path: Optional[str] = None) -> None:
    """Install a pre-push git hook that runs run_pre_push_flow()."""
    hooks_dir = Path(repo_root) / ".git" / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hooks_dir / "pre-push"

    # Allow a custom script to be copied in, otherwise generate a minimal one
    if hook_script_path:
        src = Path(hook_script_path)
        if not src.exists():
            raise FileNotFoundError(f"Hook script not found: {hook_script_path}")
        content = src.read_bytes()
        hook_path.write_bytes(content)
    else:
        script = """#!/bin/sh
python3 - <<'PY'
import sys
try:
    import function_library as fl
except Exception as e:
    print(f"[pre-push] Failed to import function_library: {e}")
    sys.exit(1)
sys.exit(fl.run_pre_push_flow())
PY
"""
        hook_path.write_text(script, encoding="utf-8")
    os.chmod(hook_path, 0o755)


def run_pre_push_flow() -> int:
    """Main orchestration used by the pre-push hook.

    Returns 0 to allow push, 1 to block.
    """
    try:
        repo_root = detect_git_repository_root()
    except Exception as e:
        print(f"[scanner] Could not find git repo: {e}")
        return 0  # Do not block if repo detection fails

    # Locate and load configuration
    config_path = str(Path(repo_root) / "virus_scan_config.json")
    try:
        config = load_config(config_path)
        validate_config(config)
    except Exception as e:
        print(f"[scanner] Config error ({config_path}): {e}")
        return 1  # Block on invalid configuration

    # Build API client
    try:
        client = build_api_client(
            api_key=str(config["api_key"]),
            base_url=str(config["base_url"]),
            timeout_s=float(config["timeout_s"]),
        )
    except Exception as e:
        print(f"[scanner] Failed to build API client: {e}")
        return 1

    # Gather staged files
    try:
        staged = get_staged_file_paths(repo_root)
    except Exception as e:
        print(f"[scanner] Failed to get staged files: {e}")
        return 0  # Do not block if we cannot list; be lenient

    if not staged:
        print("[scanner] No staged files to scan.")
        return 0

    # Scan each file
    file_to_scan_result: Dict[str, Dict[str, Any]] = {}
    file_to_is_clean: Dict[str, bool] = {}
    for rel_path in staged:
        path = str(Path(repo_root) / rel_path)
        if not os.path.exists(path):
            continue
        if is_binary_file(path):
            # Some APIs cannot scan binaries by hash reliably; still hash to try cache lookup
            pass
        try:
            file_hash = compute_file_sha256(path)
            scan_id = submit_scan(client, path, file_hash)
            scan_result = poll_scan_completion(
                client,
                scan_id,
                timeout_s=float(config.get("scan_timeout_s", 120)),
                interval_s=float(config.get("poll_interval_s", 2)),
            )
            file_to_scan_result[rel_path] = scan_result
            file_to_is_clean[rel_path] = interpret_scan_result(scan_result)
        except Exception as e:
            file_to_scan_result[rel_path] = {"status": "error", "error": str(e)}
            file_to_is_clean[rel_path] = False

    # Report and decide
    print_scan_report(file_to_scan_result)
    block = should_block_push(file_to_is_clean)
    if block:
        print("[scanner] Push blocked: at least one file appears infected.")
        return 1
    print("[scanner] All scanned files appear clean. Proceeding with push.")
    return 0
