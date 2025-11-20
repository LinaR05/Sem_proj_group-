import os
from pathlib import Path

import pytest

from src.Project_3 import (
    ArtifactFactory,
    ManualScanHook,
    ScanArtifact,
    ScanSession,
    AbstractScanStrategy,
)


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload

    def raise_for_status(self):
        return None


class FakeClient:
    def __init__(self):
        self.base_url = "https://fake.api"
        self.default_timeout_s = 1
        self._counter = 0

    def post(self, url, json, timeout):
        self._counter += 1
        return FakeResponse({"scan_id": f"{self._counter}"})

    def get(self, url, timeout):
        return FakeResponse({"status": "completed", "clean": True})


@pytest.fixture()
def repo_root(tmp_path):
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    (root / "src").mkdir(parents=True)
    (root / "bin").mkdir(parents=True)
    (root / "src" / "main.py").write_text("print('hello')\n", encoding="utf-8")
    (root / "bin" / "app.bin").write_bytes(b"\x00\x01\x02")
    (root / "requirements.txt").write_text("requests==2.31.0\npytest>=8.0\n", encoding="utf-8")
    return root


def test_artifact_factory_creates_specialized_types(repo_root):
    factory = ArtifactFactory(str(repo_root))
    source = factory.create("src/main.py")
    binary = factory.create("bin/app.bin")
    manifest = factory.create("requirements.txt")
    assert source.artifact_type.endswith("SourceCodeArtifact")
    assert binary.metadata()["uses_chunking"] is True
    assert manifest.metadata()["declared_dependencies"] == ["requests", "pytest"]


def test_scan_session_uses_polymorphic_strategies(repo_root):
    config = {
        "api_key": "demo",
        "base_url": "https://fake.api",
        "timeout_s": 1,
        "scan_timeout_s": 5,
        "poll_interval_s": 0.01,
    }
    session = ScanSession(
        repo_root=str(repo_root),
        config_data=config,
        api_client=FakeClient(),
        staged_files_override=["src/main.py", "bin/app.bin", "requirements.txt"],
        chunk_size_bytes=1,
    )

    artifacts = session.collect_artifacts()
    results = session.scan_artifacts(artifacts)

    assert "bin/app.bin" in results
    assert results["bin/app.bin"]["chunk_count"] >= 1
    assert results["requirements.txt"]["dependency_count"] == 2
    assert session.evaluate(results) == 0


def test_manual_hook_runs_full_flow(repo_root):
    config = {
        "api_key": "demo",
        "base_url": "https://fake.api",
        "timeout_s": 1,
        "scan_timeout_s": 5,
        "poll_interval_s": 0.01,
    }
    session = ScanSession(
        repo_root=str(repo_root),
        config_data=config,
        api_client=FakeClient(),
        staged_files_override=[],
    )
    hook = ManualScanHook(session, ["src/main.py"])
    exit_code = hook.run()
    assert exit_code == 0


def test_abstract_classes_enforced(repo_root):
    with pytest.raises(TypeError):
        ScanArtifact(str(repo_root), "src/main.py")  # type: ignore[abstract]
    with pytest.raises(TypeError):
        AbstractScanStrategy(object())  # type: ignore[abstract]

#Run commandL cd, pytest
#cd /Users/linaromero/repos/Sem_proj_group && pytest tests/test_project_3.py