# Detailed Function Documentation — Virus Scanner Hook Library

This document provides **in-depth technical documentation** for all 15 functions implemented in `function_library.py`.

The library integrates with the VirusTotal API and Git to automatically **scan staged files for malware** before they are pushed to a remote repository.

---

## Phase 1 — Foundation

### 1 `detect_git_repository_root(start_dir: Optional[str] = None) -> str`

**Purpose:**  
Locates the root directory of the current Git repository by traversing parent directories until a `.git` folder is found.

**Detailed Behavior:**
- Starts from `start_dir` (if given) or the current working directory.
- Walks upward through directories using `Path.parent` until `.git` is found.
- Raises a `RuntimeError` if `.git` is never located, meaning the code isn’t inside a Git repository.

**Dependencies:**  
- `os` and `pathlib.Path` for filesystem navigation.

**Returns:**  
Absolute path to the Git repository root.

**Used By:**  
`get_staged_file_paths()` and `run_pre_push_flow()` to locate where Git operations should be performed.

---

### 2 `is_binary_file(file_path: str) -> bool`

**Purpose:**  
Determines whether a file is binary or text-based.

**Detailed Behavior:**
- Opens the file in binary mode (`"rb"`) and reads the first 4 KB.
- Returns `True` if any NUL (`\x00`) bytes are detected.
- Binary detection prevents unnecessary scanning of unscannable file types (like images or executables).

**Dependencies:**  
- Standard library only (`open`, `os`).

**Returns:**  
Boolean — `True` if binary, `False` if text.

**Used By:**  
`run_pre_push_flow()` to decide whether to skip certain files.

---

### 3 `compute_file_sha256(file_path: str) -> str`

**Purpose:**  
Generates a SHA-256 cryptographic hash of a file’s contents.

**Detailed Behavior:**
- Reads the file in chunks of 1 MB to handle large files efficiently.
- Feeds each chunk into a `hashlib.sha256()` hasher.
- Returns the hex digest string representing the file’s unique hash.

**Dependencies:**  
- `hashlib` and standard I/O.

**Returns:**  
String (hexadecimal representation of the hash).

**Used By:**  
`submit_scan()` for virus scanning via hash lookup.

---

### 4`load_config(config_path: str) -> Dict[str, Any]`

**Purpose:**  
Loads JSON configuration containing API credentials and connection settings.

**Detailed Behavior:**
- Reads the file located at `config_path` using `json.load()`.
- Verifies that the file exists and has a `.json` extension.
- Expects keys such as `api_key`, `base_url`, and `timeout_s`.

**Dependencies:**  
- `json`, `pathlib`.

**Returns:**  
Python dictionary containing configuration data.

**Used By:**  
`run_pre_push_flow()` and `validate_config()`.

---

## Phase 2 — Configuration & Validation

### 5 `validate_config(config: Dict[str, Any]) -> None`

**Purpose:**  
Validates the structure and data types of a loaded configuration.

**Detailed Behavior:**
- Checks that required keys exist (`api_key`, `base_url`, `timeout_s`).
- Confirms that values match the expected types (e.g., `api_key` must be a string).
- Ensures that `base_url` starts with `http://` or `https://`.

**Dependencies:**  
- None beyond standard library.

**Raises:**  
- `ValueError` if keys are missing or invalid.
- `TypeError` if a key’s type does not match.

**Used By:**  
`run_pre_push_flow()` after loading configuration.

---

### 6`build_api_client(api_key: str, base_url: str, timeout_s: float) -> Any`

**Purpose:**  
Creates and returns a configured HTTP session for communicating with the VirusTotal API.

**Detailed Behavior:**
- Instantiates a `requests.Session()` object.
- Sets default headers including:
  - `Authorization`: Bearer token for authentication.
  - `Accept`: JSON response type.
  - `User-Agent`: Custom client identifier.
- Stores `base_url` and `timeout_s` as attributes for later access.

**Dependencies:**  
- Third-party dependency: `requests`.

**Returns:**  
A configured HTTP session object.

**Used By:**  
`submit_scan()` and `poll_scan_completion()`.

---

## Phase 3 — Git Integration

### 7 `get_staged_file_paths(repo_root: str) -> List[str]`

**Purpose:**  
Fetches a list of files currently staged for commit in the specified Git repository.

**Detailed Behavior:**
- Runs `git diff --cached --name-only --diff-filter=ACM` using `subprocess.run()`.
- Captures output from Git listing added, copied, or modified files.
- Returns all staged file paths as a list of strings.

**Dependencies:**  
- `subprocess`.

**Returns:**  
List of relative file paths.

**Used By:**  
`run_pre_push_flow()` to determine which files need scanning.

---

## Phase 4 — File Processing

### 8 `chunk_file_for_upload(file_path: str, max_chunk_bytes: int) -> List[bytes]`

**Purpose:**  
Splits large files into smaller byte chunks for uploading to APIs with file size limits.

**Detailed Behavior:**
- Reads a file in binary mode.
- Appends successive byte chunks (≤ `max_chunk_bytes`) to a list.
- Returns a list of chunks.

**Dependencies:**  
- Standard library only.

**Returns:**  
List of byte objects (`List[bytes]`).

**Used By:**  
`submit_scan()` for handling large files that exceed the API’s upload limit.

---

### 9 `submit_scan(api_client: Any, file_path: str, file_hash: str) -> str`

**Purpose:**  
Submits a file (via hash or upload) to the VirusTotal API for scanning.

**Detailed Behavior:**
- Constructs a request payload containing the filename and its SHA-256 hash.
- Posts the payload to the `/scan` endpoint.
- Extracts and returns the `scan_id` from the API response.

**Dependencies:**  
- `requests`, `os`.

**Returns:**  
String — unique scan identifier.

**Used By:**  
`run_pre_push_flow()` and `poll_scan_completion()`.

---

## Phase 5 — Scan Management

### 10 `poll_scan_completion(api_client: Any, scan_id: str, timeout_s: float, interval_s: float) -> Dict[str, Any]`

**Purpose:**  
Monitors a file’s scan status until it is complete or times out.

**Detailed Behavior:**
- Polls the `/scan/{scan_id}` endpoint repeatedly.
- Checks if `status` is “done”, “error”, or “failed”.
- Sleeps between polls for `interval_s` seconds.
- Stops when the scan is complete or when the timeout expires.

**Dependencies:**  
- `time`, `requests`.

**Returns:**  
JSON dictionary representing the final scan result.

**Used By:**  
`run_pre_push_flow()` after submitting a scan.

---

### 11 `interpret_scan_result(scan_result: Dict[str, Any]) -> bool`

**Purpose:**  
Analyzes a scan result to determine if the file is clean.

**Detailed Behavior:**
- Looks for flags such as `clean`, `malicious`, or `infected`.
- If unavailable, checks numeric detection counts (`detections`, `positives`).
- Returns `True` if clean, `False` if infected or uncertain.

**Dependencies:**  
- None.

**Returns:**  
Boolean (`True` = clean, `False` = infected).

**Used By:**  
`print_scan_report()` and `run_pre_push_flow()`.

---

## Phase 6 — Decision Logic

### 12 `should_block_push(file_to_is_clean: Dict[str, bool]) -> bool`

**Purpose:**  
Determines whether the push operation should be blocked.

**Detailed Behavior:**
- Evaluates all `bool` values in the `file_to_is_clean` dictionary.
- Returns `True` if any file is infected (`False`).
- Returns `False` if all files are clean or no files were scanned.

**Dependencies:**  
- None.

**Returns:**  
Boolean — `True` = block push.

**Used By:**  
`run_pre_push_flow()`.

---

### 13 `print_scan_report(file_to_scan_result: Dict[str, Dict[str, Any]]) -> None`

**Purpose:**  
Prints a readable summary of scan results for each file.

**Detailed Behavior:**
- Iterates through the dictionary of results.
- Displays the file name, infection status, and detection count.
- Uses `interpret_scan_result()` to determine cleanliness.

**Dependencies:**  
- None (console output only).

**Returns:**  
None.

**Used By:**  
`run_pre_push_flow()` after all scans complete.

---

## Phase 7 — Integration

### 14 `install_pre_push_hook(repo_root: str, hook_script_path: Optional[str] = None) -> None`

**Purpose:**  
Installs a pre-push Git hook that runs the scanner automatically before each push.

**Detailed Behavior:**
- Creates `.git/hooks/pre-push` inside the repository.
- Writes a shell script that executes `run_pre_push_flow()`.
- If `hook_script_path` is provided, copies that custom script instead.
- Sets file permissions to executable (755).

**Dependencies:**  
- `os`, `pathlib`.

**Returns:**  
None.

**Used By:**  
Manual setup process or installation script.

---

### 15 `run_pre_push_flow() -> int`

**Purpose:**  
Acts as the main program entry point — orchestrates all other functions to perform the complete scan process.

**Detailed Behavior:**
1. Locates Git repository (`detect_git_repository_root`).
2. Loads and validates config (`load_config`, `validate_config`).
3. Builds API client (`build_api_client`).
4. Gets all staged files (`get_staged_file_paths`).
5. For each file:
   - Checks binary type (`is_binary_file`),
   - Computes hash (`compute_file_sha256`),
   - Submits to API (`submit_scan`),
   - Polls for result (`poll_scan_completion`),
   - Interprets scan (`interpret_scan_result`).
6. Prints a summary report.
7. Decides whether to block push (`should_block_push`).

**Dependencies:**  
All other functions.

**Returns:**  
Exit code (`0` = allow push, `1` = block push).

---