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