# main.py
"""
Main runner for the OOP Virus Scanner (Project 3).



This will:
    - detect  git repo
    - load the config (virus_scan_config.json)
    - scan all staged files
    - print a full report
"""

from src.Project_3 import ScanSession, PrePushHook


def main():
    print(" Virus Scanner (Project 3)")

    # Build a scan session (loads config, API client, strategies, etc.)
    session = ScanSession()

    # Run the pre-push hook logic manually
    hook = PrePushHook(session)

    print("\n[scanner] Starting scan...\n")
    exit_code = hook.run()

    if exit_code == 0:
        print("\n[scanner] All files clean. OK to push.")
    else:
        print("\n[scanner] Infection detected! Push blocked.")

    print(f"\nExit code: {exit_code}")


if __name__ == "__main__":
    main()
