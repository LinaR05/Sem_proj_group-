from typing import Any, Dict
import os
import time

def submit_scan(api_client: Any, file_path: str, file_hash: str) -> str:
    """Submit a scan request for a file. Returns a scan_id.

    This implementation posts the file hash and basic metadata.
    """
    base_url: str = getattr(api_client, "base_url")
    timeout_s: float = float(getattr(api_client, "default_timeout_s", 30.0))
    url = f"{base_url}/scan"
    payload = {
        "filename": os.path.basename(file_path),
        "sha256": file_hash,
    }
    resp = api_client.post(url, json=payload, timeout=timeout_s)
    resp.raise_for_status()
    data = resp.json()
    scan_id = data.get("scan_id") or data.get("id")
    if not scan_id:
        raise RuntimeError("Scan submission did not return a scan_id")
    return str(scan_id)


def poll_scan_completion(
    api_client: Any, scan_id: str, timeout_s: float, interval_s: float
) -> Dict[str, Any]:
    """Poll scan status until completion or timeout. Returns final result payload."""
    base_url: str = getattr(api_client, "base_url")
    deadline = time.time() + float(timeout_s)
    status_url = f"{base_url}/scan/{scan_id}"
    while True:
        resp = api_client.get(status_url, timeout=float(getattr(api_client, "default_timeout_s", 30.0)))
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