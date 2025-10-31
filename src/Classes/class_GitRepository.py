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
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            cwd=self._repo_root,
            capture_output=True,
            text=True,
            check=False
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"Failed to list staged files: {result.stderr.strip() or result.stdout.strip()}"
            )
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
            script = (
                "#!/bin/sh\n"
                "python3 - <<'PY'\n"
                "import sys\n"
                "from src.library_name import ScanOrchestrator\n"
                "sys.exit(ScanOrchestrator().run_pre_push_flow())\n"
                "PY\n"
            )
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



