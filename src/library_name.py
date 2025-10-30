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

class VirusScanConfig:
    """
    Handles loading and validation of virus scan configuration.
    Example:
        config = VirusScanConfig('/path/to/virus_scan_config.json')
        print(config.api_key)
    """
    def __init__(self, config_path: str):
        self._config_path = config_path
        self._config = self._load()
        self._validate()

    @property
    def api_key(self) -> str:
        return self._config["api_key"]

    @property
    def base_url(self) -> str:
        return self._config["base_url"]

    @property
    def timeout_s(self) -> float:
        return float(self._config["timeout_s"])

    @property
    def scan_timeout_s(self) -> float:
        return float(self._config.get("scan_timeout_s", 120))

    @property
    def poll_interval_s(self) -> float:
        return float(self._config.get("poll_interval_s", 2))

    def _load(self) -> Dict[str, Any]:
        path = Path(self._config_path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {self._config_path}")
        if path.suffix.lower() != ".json":
            raise ValueError("Only JSON config is supported (use .json file)")
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)

    def _validate(self) -> None:
        required_fields = {
            "api_key": str,
            "base_url": str,
            "timeout_s": (int, float),
        }
        for key, expected_type in required_fields.items():
            if key not in self._config:
                raise ValueError(f"Missing required config key: {key}")
            if not isinstance(self._config[key], expected_type):
                raise TypeError(
                    f"Config key '{key}' must be {expected_type}, got {type(self._config[key])}")
        base_url = self._config["base_url"]
        if not (base_url.startswith("http://") or base_url.startswith("https://")):
            raise ValueError("base_url must start with http:// or https://")

    def __str__(self):
        return f"VirusScanConfig(api_key=****, base_url={self.base_url}, timeout_s={self.timeout_s})"

    def __repr__(self):
        return f"<VirusScanConfig(path={self._config_path})>"


class APIClient:
    """
    Handles API requests to the virus scanning service.
    Example:
        client = APIClient(config)
        scan_id = client.submit_scan(file_path, file_hash)
    """
    def __init__(self, config: VirusScanConfig):
        if requests is None:
            raise RuntimeError("'requests' library required for APIClient.")
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {config.api_key}",
            "Accept": "application/json",
            "User-Agent": "RepoVirusScanner/1.0"
        })
        self._base_url = config.base_url.rstrip("/")
        self._timeout_s = float(config.timeout_s)

    def submit_scan(self, file_path: str, file_hash: str) -> str:
        url = f"{self._base_url}/scan"
        payload = {
            "filename": os.path.basename(file_path),
            "sha256": file_hash
        }
        resp = self._session.post(url, json=payload, timeout=self._timeout_s)
        resp.raise_for_status()
        data = resp.json()
        scan_id = data.get("scan_id") or data.get("id")
        if not scan_id:
            raise RuntimeError("Scan submission did not return a scan_id")
        return str(scan_id)

    def poll_scan_completion(self, scan_id: str, timeout_s: float, interval_s: float) -> Dict[str, Any]:
        status_url = f"{self._base_url}/scan/{scan_id}"
        deadline = time.time() + float(timeout_s)
        while True:
            resp = self._session.get(status_url, timeout=self._timeout_s)
            resp.raise_for_status()
            data = resp.json()
            status = str(data.get("status", "")).lower()
            if status in {"done", "completed", "finished", "success"}:
                return data
            if status in {"failed", "error"}:
                return data
            if time.time() >= deadline:
                raise TimeoutError("Timed out waiting for scan to complete")
            time.sleep(max(0.1, float(interval_s)))

    def __str__(self):
        return f"APIClient(base_url={self._base_url})"

    def __repr__(self):
        return f"<APIClient(base_url={self._base_url})>"


class GitRepository:
    """
    Interacts with the local git repository and manages hook installation and staged file retrieval.
    Example:
        repo = GitRepository()
        files = repo.get_staged_files()
    """
    def __init__(self, start_dir: Optional[str] = None):
        self._repo_root = self._detect_root(start_dir)

    @property
    def root(self) -> str:
        return self._repo_root

    def get_staged_files(self) -> List[str]:
        result = subprocess.run([
            "git", "diff", "--cached", "--name-only", "--diff-filter=ACM"
        ], cwd=self._repo_root, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise RuntimeError(f"Failed to list staged files: {result.stderr.strip() or result.stdout.strip()}")
        return [p for p in result.stdout.splitlines() if p.strip()]

    def install_pre_push_hook(self, hook_script_path: Optional[str] = None) -> None:
        hooks_dir = Path(self._repo_root) / ".git" / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)
        hook_path = hooks_dir / "pre-push"
        if hook_script_path:
            src = Path(hook_script_path)
            if not src.exists():
                raise FileNotFoundError(f"Hook script not found: {hook_script_path}")
            content = src.read_bytes()
            hook_path.write_bytes(content)
        else:
            script = """#!/bin/sh\npython3 - <<'PY'\nimport sys\nfrom src.library_name import ScanOrchestrator\nsys.exit(ScanOrchestrator().run_pre_push_flow())\nPY\n"""
            hook_path.write_text(script, encoding="utf-8")
        os.chmod(hook_path, 0o755)

    def _detect_root(self, start_dir: Optional[str] = None) -> str:
        current = Path(start_dir or os.getcwd()).resolve()
        root = Path(current.root)
        while True:
            if (current / ".git").exists():
                return str(current)
            if current == root:
                raise RuntimeError("Not inside a Git repository (no .git found)")
            current = current.parent

    def __str__(self):
        return f"GitRepository(root={self._repo_root})"

    def __repr__(self):
        return f"<GitRepository(root={self._repo_root})>"


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


class ScanOrchestrator:
    """
    Coordinates scan and push logic.
    Example:
        orchestrator = ScanOrchestrator()
        orchestrator.run_pre_push_flow()
    """
    def __init__(self, config_path: Optional[str] = None, repo_start: Optional[str] = None):
        self._repo = GitRepository(repo_start)
        self._config = VirusScanConfig(config_path or str(Path(self._repo.root) / 'virus_scan_config.json'))
        self._client = APIClient(self._config)

    def interpret_scan_result(self, scan_result: Dict[str, Any]) -> bool:
        for key in ("clean", "is_clean", "malicious", "infected"):
            if key in scan_result:
                val = scan_result[key]
                if key in ("malicious", "infected"):
                    return not bool(val)
                return bool(val)
        detections = scan_result.get("detections") or scan_result.get("positives")
        if isinstance(detections, int):
            return detections == 0
        return True

    def should_block_push(self, file_to_is_clean: Dict[str, bool]) -> bool:
        if not file_to_is_clean:
            return False
        return not all(bool(v) for v in file_to_is_clean.values())

    def print_report(self, file_to_scan_result: Dict[str, Dict[str, Any]]) -> None:
        if not file_to_scan_result:
            print("No files scanned.")
            return
        print("Scan Report:")
        for path, result in file_to_scan_result.items():
            clean = self.interpret_scan_result(result)
            status = result.get("status", "unknown")
            detections = result.get("detections", result.get("positives", "?"))
            print(f"- {path}: {'CLEAN' if clean else 'INFECTED'} (status={status}, detections={detections})")

    def run_pre_push_flow(self) -> int:
        try:
            staged = self._repo.get_staged_files()
        except Exception as e:
            print(f"[scanner] Failed to get staged files: {e}")
            return 0  # Do not block if we cannot list
        if not staged:
            print("[scanner] No staged files to scan.")
            return 0
        file_to_scan_result: Dict[str, Dict[str, Any]] = {}
        file_to_is_clean: Dict[str, bool] = {}
        for rel_path in staged:
            path = str(Path(self._repo.root) / rel_path)
            if not os.path.exists(path):
                continue
            scanner = FileScanner(path)
            try:
                file_hash = scanner.sha256
                scan_id = self._client.submit_scan(path, file_hash)
                scan_result = self._client.poll_scan_completion(
                    scan_id,
                    timeout_s=self._config.scan_timeout_s,
                    interval_s=self._config.poll_interval_s,
                )
                file_to_scan_result[rel_path] = scan_result
                file_to_is_clean[rel_path] = self.interpret_scan_result(scan_result)
            except Exception as e:
                file_to_scan_result[rel_path] = {"status": "error", "error": str(e)}
                file_to_is_clean[rel_path] = False
        self.print_report(file_to_scan_result)
        block = self.should_block_push(file_to_is_clean)
        if block:
            print("[scanner] Push blocked: at least one file appears infected.")
            return 1
        print("[scanner] All scanned files appear clean. Proceeding with push.")
        return 0

    def __str__(self):
        return f"ScanOrchestrator(config={self._config}, repo={self._repo})"

    def __repr__(self):
        return f"<ScanOrchestrator(config={repr(self._config)}, repo={repr(self._repo)})>"
