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