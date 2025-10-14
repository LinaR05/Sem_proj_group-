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