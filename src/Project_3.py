"""
Project 3 - Advanced OOP Virus Scanner System
---------------------------------------------

Extends the Project 1 & 2 utilities into a richer OO design that showcases
inheritance hierarchies, abstract base classes, polymorphism, and composition.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

try:  # Support running as `python src/Project_3.py` or through package imports.
    from src import library_name as primitives
except ImportError:  # pragma: no cover - fallback for direct execution.
    import library_name as primitives  # type: ignore


class ScanArtifact(ABC):
    """Abstract representation of any file-like artifact that can be scanned."""

    def __init__(self, repo_root: str, relative_path: str) -> None:
        self.repo_root = Path(repo_root)
        self.relative_path = relative_path
        self._absolute_path = (self.repo_root / relative_path).resolve()
        if not self._absolute_path.exists():
            raise FileNotFoundError(f"Artifact not found: {self._absolute_path}")
        self._sha256_cache: Optional[str] = None
        self._binary_cache: Optional[bool] = None

    @property
    def absolute_path(self) -> Path:
        return self._absolute_path

    @property
    def sha256(self) -> str:
        if self._sha256_cache is None:
            self._sha256_cache = primitives.compute_file_sha256(str(self.absolute_path))
        return self._sha256_cache

    @property
    def is_binary(self) -> bool:
        if self._binary_cache is None:
            self._binary_cache = primitives.is_binary_file(str(self.absolute_path))
        return self._binary_cache

    @property
    def size_bytes(self) -> int:
        try:
            return self.absolute_path.stat().st_size
        except OSError:
            return 0

    def metadata(self) -> Dict[str, Any]:
        base = {
            "relative_path": self.relative_path,
            "absolute_path": str(self.absolute_path),
            "size_bytes": self.size_bytes,
            "artifact_type": self.artifact_type,
            "is_binary": self.is_binary,
        }
        base.update(self._specialized_metadata())
        return base

    @property
    def artifact_type(self) -> str:
        return self.__class__.__name__

    @abstractmethod
    def preferred_strategy(self) -> str:
        """Return the strategy name that should scan this artifact."""

    @abstractmethod
    def _specialized_metadata(self) -> Dict[str, Any]:
        """Allow subclasses to provide additional metadata."""


class SourceCodeArtifact(ScanArtifact):
    """Represents text-based source files."""

    _LANG_BY_EXT = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".java": "java",
        ".cs": "csharp",
        ".go": "golang",
    }

    def preferred_strategy(self) -> str:
        return ScanStrategyRegistry.HASH

    def _specialized_metadata(self) -> Dict[str, Any]:
        ext = self.absolute_path.suffix.lower()
        language = self._LANG_BY_EXT.get(ext, "text")
        return {"language": language, "uses_chunking": False}


class BinaryArtifact(ScanArtifact):
    """Represents binary files that benefit from chunked uploads."""

    def preferred_strategy(self) -> str:
        return ScanStrategyRegistry.CHUNKED

    def _specialized_metadata(self) -> Dict[str, Any]:
        chunk_hint = max(1, self.size_bytes // (1024 * 1024))
        return {"expected_chunks": chunk_hint, "uses_chunking": True}


class ManifestArtifact(ScanArtifact):
    """Dependency manifest files that surface dependency metadata."""

    MANIFEST_NAMES = {"requirements.txt", "package.json", "pyproject.toml"}

    def preferred_strategy(self) -> str:
        return ScanStrategyRegistry.MANIFEST

    def _specialized_metadata(self) -> Dict[str, Any]:
        dependencies: List[str] = []
        try:
            with self.absolute_path.open("r", encoding="utf-8") as handle:
                for raw_line in handle:
                    line = raw_line.strip()
                    if not line or line.startswith(("#", "//")):
                        continue
                    dep = line.split("==")[0].split(">=")[0].strip()
                    if dep:
                        dependencies.append(dep)
        except OSError:
            pass
        return {"declared_dependencies": dependencies, "uses_chunking": False}


class ArtifactFactory:
    """Factory responsible for choosing the correct artifact subclass."""

    BINARY_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".zip", ".gz", ".exe", ".bin", ".dll"}

    def __init__(self, repo_root: str) -> None:
        self.repo_root = repo_root

    def create(self, relative_path: str) -> ScanArtifact:
        name = Path(relative_path).name.lower()
        suffix = Path(relative_path).suffix.lower()
        if name in ManifestArtifact.MANIFEST_NAMES:
            artifact_cls = ManifestArtifact
        elif suffix in self.BINARY_EXTENSIONS:
            artifact_cls = BinaryArtifact
        else:
            artifact_cls = SourceCodeArtifact
        return artifact_cls(self.repo_root, relative_path)


class AbstractScanStrategy(ABC):
    """Base object encapsulating how an artifact is submitted to the virus scanner."""

    name = "abstract"

    def __init__(self, session: "ScanSession") -> None:
        self.session = session

    def scan(self, artifact: ScanArtifact) -> Dict[str, Any]:
        metadata = artifact.metadata()
        response = self._submit(artifact, metadata)
        response.setdefault("artifact", metadata)
        response.setdefault("strategy", self.name)
        return response

    @abstractmethod
    def _submit(self, artifact: ScanArtifact, metadata: Dict[str, Any]) -> Dict[str, Any]:
        ...


class HashLookupStrategy(AbstractScanStrategy):
    name = "hash"

    def _submit(self, artifact: ScanArtifact, metadata: Dict[str, Any]) -> Dict[str, Any]:
        scan_id = primitives.submit_scan(self.session.api_client, str(artifact.absolute_path), artifact.sha256)
        return primitives.poll_scan_completion(
            self.session.api_client,
            scan_id,
            timeout_s=self.session.scan_timeout_s,
            interval_s=self.session.poll_interval_s,
        )


class ChunkedUploadStrategy(AbstractScanStrategy):
    name = "chunked"

    def _submit(self, artifact: ScanArtifact, metadata: Dict[str, Any]) -> Dict[str, Any]:
        chunks = primitives.chunk_file_for_upload(str(artifact.absolute_path), self.session.chunk_size_bytes)
        metadata["chunk_count"] = len(chunks)
        scan_id = primitives.submit_scan(self.session.api_client, str(artifact.absolute_path), artifact.sha256)
        result = primitives.poll_scan_completion(
            self.session.api_client,
            scan_id,
            timeout_s=self.session.scan_timeout_s,
            interval_s=self.session.poll_interval_s,
        )
        result["chunk_count"] = len(chunks)
        return result


class ManifestInsightStrategy(AbstractScanStrategy):
    name = "manifest"

    def _submit(self, artifact: ScanArtifact, metadata: Dict[str, Any]) -> Dict[str, Any]:
        # Manifests are typically small; we still leverage hashing but annotate response.
        scan_id = primitives.submit_scan(self.session.api_client, str(artifact.absolute_path), artifact.sha256)
        result = primitives.poll_scan_completion(
            self.session.api_client,
            scan_id,
            timeout_s=self.session.scan_timeout_s,
            interval_s=self.session.poll_interval_s,
        )
        result["declared_dependencies"] = metadata.get("declared_dependencies", [])
        result["dependency_count"] = len(result["declared_dependencies"])
        return result


class ScanStrategyRegistry:
    """Composition helper that keeps strategy instances and resolves them per artifact."""

    HASH = HashLookupStrategy.name
    CHUNKED = ChunkedUploadStrategy.name
    MANIFEST = ManifestInsightStrategy.name

    def __init__(self, session: "ScanSession") -> None:
        self._strategies = {
            self.HASH: HashLookupStrategy(session),
            self.CHUNKED: ChunkedUploadStrategy(session),
            self.MANIFEST: ManifestInsightStrategy(session),
        }

    def for_artifact(self, artifact: ScanArtifact) -> AbstractScanStrategy:
        return self._strategies.get(artifact.preferred_strategy(), self._strategies[self.HASH])

    def all_strategies(self) -> Iterable[AbstractScanStrategy]:
        return self._strategies.values()


@dataclass
class ScanSession:
    """High-level object that composes config, API client, artifact factory, and strategies."""

    config_path: Optional[str] = None
    repo_root: Optional[str] = None
    config_data: Optional[Dict[str, Any]] = None
    api_client: Optional[Any] = None
    staged_files_override: Optional[Sequence[str]] = None
    chunk_size_bytes: Optional[int] = None

    def __post_init__(self) -> None:
        self.repo_root = self.repo_root or primitives.detect_git_repository_root()
        resolved_config_path = self.config_path or str(Path(self.repo_root) / "virus_scan_config.json")
        self._config = self.config_data or primitives.load_config(resolved_config_path)
        primitives.validate_config(self._config)
        self.api_client = self.api_client or primitives.build_api_client(
            api_key=str(self._config["api_key"]),
            base_url=str(self._config["base_url"]),
            timeout_s=float(self._config["timeout_s"]),
        )
        self.chunk_size_bytes = int(self.chunk_size_bytes or self._config.get("max_chunk_bytes", 1024 * 1024))
        self._factory = ArtifactFactory(self.repo_root)
        self._strategies = ScanStrategyRegistry(self)

    @property
    def config(self) -> Dict[str, Any]:
        return self._config

    @property
    def scan_timeout_s(self) -> float:
        return float(self._config.get("scan_timeout_s", 120))

    @property
    def poll_interval_s(self) -> float:
        return float(self._config.get("poll_interval_s", 2))

    def collect_artifacts(self) -> List[ScanArtifact]:
        if self.staged_files_override is not None:
            candidate_paths = list(self.staged_files_override)
        else:
            candidate_paths = primitives.get_staged_file_paths(self.repo_root)
        artifacts: List[ScanArtifact] = []
        for rel_path in candidate_paths:
            try:
                artifacts.append(self._factory.create(rel_path))
            except FileNotFoundError:
                continue
        return artifacts

    def scan_artifacts(self, artifacts: Sequence[ScanArtifact]) -> Dict[str, Dict[str, Any]]:
        results: Dict[str, Dict[str, Any]] = {}
        for artifact in artifacts:
            strategy = self._strategies.for_artifact(artifact)
            results[artifact.relative_path] = strategy.scan(artifact)
        return results

    def report(self, results: Dict[str, Dict[str, Any]]) -> None:
        primitives.print_scan_report(results)

    def evaluate(self, results: Dict[str, Dict[str, Any]]) -> int:
        verdict = {path: primitives.interpret_scan_result(result) for path, result in results.items()}
        block = primitives.should_block_push(verdict)
        if block:
            print("[scanner] Push blocked by ScanSession evaluation.")
        return 1 if block else 0

    def run_full_scan(self, hook: Optional["HookBase"] = None) -> int:
        hook = hook or PrePushHook(self)
        return hook.run()


class HookBase(ABC):
    """Base class for hook workflows. Demonstrates polymorphism over hook types."""

    def __init__(self, session: ScanSession) -> None:
        self.session = session

    def run(self) -> int:
        artifacts = self.collect_artifacts()
        if not artifacts:
            print("[scanner] No artifacts to scan.")
            return 0
        results = self.session.scan_artifacts(artifacts)
        self.session.report(results)
        return self.session.evaluate(results)

    @abstractmethod
    def collect_artifacts(self) -> List[ScanArtifact]:
        ...


class PrePushHook(HookBase):
    """Collects staged files from git and scans them before push."""

    def collect_artifacts(self) -> List[ScanArtifact]:
        return self.session.collect_artifacts()


class ManualScanHook(HookBase):
    """Allows developers to scan arbitrary files. Overrides run() to decorate output."""

    def __init__(self, session: ScanSession, manual_paths: Sequence[str]) -> None:
        super().__init__(session)
        self.manual_paths = list(manual_paths)

    def run(self) -> int:
        print(f"[scanner] Running manual scan for {len(self.manual_paths)} paths.")
        return super().run()

    def collect_artifacts(self) -> List[ScanArtifact]:
        factory = ArtifactFactory(self.session.repo_root)
        artifacts: List[ScanArtifact] = []
        for path in self.manual_paths:
            try:
                artifacts.append(factory.create(path))
            except FileNotFoundError:
                print(f"[scanner] Skipping missing path: {path}")
        return artifacts


__all__ = [
    "ArtifactFactory",
    "BinaryArtifact",
    "ChunkedUploadStrategy",
    "HookBase",
    "ManualScanHook",
    "ManifestArtifact",
    "ManifestInsightStrategy",
    "PrePushHook",
    "ScanArtifact",
    "ScanSession",
    "ScanStrategyRegistry",
    "SourceCodeArtifact",
    "HashLookupStrategy",
]

