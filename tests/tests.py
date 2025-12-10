"""
Comprehensive Testing Suite for Project 4
Tests virus scanner with data persistence, API integration, and OOP design.
"""

import unittest
import json
import os
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch

# Import your modules
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from src import virus_scanner_core as primitives
from src.scanner_models import (
    ScanSession,
    PrePushHook,
    ManualScanHook,
    ArtifactFactory,
    SourceCodeArtifact,
    BinaryArtifact,
    ManifestArtifact,
    ScanStrategyRegistry,
)


# UNIT TESTS - Test individual functions and methods

class TestUnitPrimitives(unittest.TestCase):
    """Unit tests for library_name.py primitive functions."""
    
    def test_compute_file_sha256(self):
        """Test SHA-256 hash computation."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("Hello World")
            temp_path = f.name
        
        try:
            hash_result = primitives.compute_file_sha256(temp_path)
            # Known SHA-256 of "Hello World"
            expected = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
            self.assertEqual(hash_result, expected)
        finally:
            os.unlink(temp_path)
    
    def test_is_binary_file_detects_binary(self):
        """Test binary file detection."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b'\x00\x01\x02\x03')  # Binary data with null byte
            temp_path = f.name
        
        try:
            self.assertTrue(primitives.is_binary_file(temp_path))
        finally:
            os.unlink(temp_path)
    
    def test_is_binary_file_detects_text(self):
        """Test text file detection."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("This is plain text")
            temp_path = f.name
        
        try:
            self.assertFalse(primitives.is_binary_file(temp_path))
        finally:
            os.unlink(temp_path)
    
    def test_interpret_scan_result_clean(self):
        """Test scan result interpretation for clean files."""
        result = {"clean": True, "detections": 0}
        self.assertTrue(primitives.interpret_scan_result(result))
    
    def test_interpret_scan_result_infected(self):
        """Test scan result interpretation for infected files."""
        result = {"clean": False, "detections": 47}
        self.assertFalse(primitives.interpret_scan_result(result))
    
    def test_should_block_push_with_infected_file(self):
        """Test push blocking logic with infected file."""
        verdict = {"file1.py": True, "virus.exe": False}
        self.assertTrue(primitives.should_block_push(verdict))
    
    def test_should_block_push_all_clean(self):
        """Test push blocking logic with all clean files."""
        verdict = {"file1.py": True, "file2.py": True}
        self.assertFalse(primitives.should_block_push(verdict))


class TestUnitArtifacts(unittest.TestCase):
    """Unit tests for Artifact classes."""
    
    def setUp(self):
        """Create temporary test directory."""
        self.test_dir = tempfile.mkdtemp()
        self.git_dir = Path(self.test_dir) / ".git"
        self.git_dir.mkdir()
    
    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.test_dir)
    
    def test_source_code_artifact_metadata(self):
        """Test SourceCodeArtifact generates correct metadata."""
        test_file = Path(self.test_dir) / "test.py"
        test_file.write_text("print('hello')")
        
        artifact = SourceCodeArtifact(self.test_dir, "test.py")
        metadata = artifact.metadata()
        
        self.assertEqual(metadata["language"], "python")
        self.assertEqual(metadata["artifact_type"], "SourceCodeArtifact")
        self.assertFalse(metadata["uses_chunking"])
    
    def test_binary_artifact_metadata(self):
        """Test BinaryArtifact generates correct metadata."""
        test_file = Path(self.test_dir) / "test.bin"
        test_file.write_bytes(b'\x00\x01\x02\x03')
        
        artifact = BinaryArtifact(self.test_dir, "test.bin")
        metadata = artifact.metadata()
        
        self.assertEqual(metadata["artifact_type"], "BinaryArtifact")
        self.assertTrue(metadata["uses_chunking"])
    
    def test_manifest_artifact_parses_dependencies(self):
        """Test ManifestArtifact correctly parses dependencies."""
        test_file = Path(self.test_dir) / "requirements.txt"
        test_file.write_text("requests==2.31.0\npytest>=8.0\n# comment\n")
        
        artifact = ManifestArtifact(self.test_dir, "requirements.txt")
        metadata = artifact.metadata()
        
        self.assertEqual(len(metadata["declared_dependencies"]), 2)
        self.assertIn("requests", metadata["declared_dependencies"])
        self.assertIn("pytest", metadata["declared_dependencies"])


# INTEGRATION TESTS - Test classes working together (5-8 required)

class TestIntegrationArtifactFactory(unittest.TestCase):
    """Integration test: ArtifactFactory creates correct artifact types."""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        Path(self.test_dir, ".git").mkdir()
    
    def tearDown(self):
        shutil.rmtree(self.test_dir)
    
    def test_factory_creates_appropriate_artifact_types(self):
        """Test factory pattern creates correct artifact subclasses."""
        # Create test files
        py_file = Path(self.test_dir) / "script.py"
        py_file.write_text("print('test')")
        
        bin_file = Path(self.test_dir) / "app.exe"
        bin_file.write_bytes(b'\x00\x01')
        
        req_file = Path(self.test_dir) / "requirements.txt"
        req_file.write_text("flask==2.0.0")
        
        factory = ArtifactFactory(self.test_dir)
        
        # Test factory creates correct types
        py_artifact = factory.create("script.py")
        bin_artifact = factory.create("app.exe")
        req_artifact = factory.create("requirements.txt")
        
        self.assertIsInstance(py_artifact, SourceCodeArtifact)
        self.assertIsInstance(bin_artifact, BinaryArtifact)
        self.assertIsInstance(req_artifact, ManifestArtifact)


class TestIntegrationStrategyRegistry(unittest.TestCase):
    """Integration test: Strategy registry selects correct strategy for artifacts."""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        Path(self.test_dir, ".git").mkdir()
        
        # Create mock config
        self.mock_config = {
            "api_key": "test_key",
            "base_url": "https://test.api",
            "timeout_s": 10
        }
        
        # Create mock API client
        self.mock_client = Mock()
    
    def tearDown(self):
        shutil.rmtree(self.test_dir)
    
    def test_registry_assigns_correct_strategies(self):
        """Test strategy registry assigns appropriate strategies to artifacts."""
        # Create test files
        py_file = Path(self.test_dir) / "test.py"
        py_file.write_text("code")
        
        bin_file = Path(self.test_dir) / "test.exe"
        bin_file.write_bytes(b'\x00')
        
        req_file = Path(self.test_dir) / "requirements.txt"
        req_file.write_text("requests")
        
        # Create session with mock client
        session = ScanSession(
            repo_root=self.test_dir,
            config_data=self.mock_config,
            api_client=self.mock_client
        )
        
        registry = ScanStrategyRegistry(session)
        
        # Create artifacts
        py_artifact = SourceCodeArtifact(self.test_dir, "test.py")
        bin_artifact = BinaryArtifact(self.test_dir, "test.exe")
        req_artifact = ManifestArtifact(self.test_dir, "requirements.txt")
        
        # Verify correct strategies assigned
        py_strategy = registry.for_artifact(py_artifact)
        bin_strategy = registry.for_artifact(bin_artifact)
        req_strategy = registry.for_artifact(req_artifact)
        
        self.assertEqual(py_strategy.name, "hash")
        self.assertEqual(bin_strategy.name, "chunked")
        self.assertEqual(req_strategy.name, "manifest")


class TestIntegrationDataPersistence(unittest.TestCase):
    """Integration test: Data persistence saves and loads correctly."""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        Path(self.test_dir, ".git").mkdir()
        
        test_file = Path(self.test_dir) / "test.py"
        test_file.write_text("print('test')")
        
        self.mock_config = {
            "api_key": "test",
            "base_url": "https://test.api",
            "timeout_s": 10
        }
        
        self.mock_client = Mock()
    
    def tearDown(self):
        shutil.rmtree(self.test_dir)
    
    def test_save_and_load_scan_history(self):
        """Test that scan results are saved and can be loaded."""
        session = ScanSession(
            repo_root=self.test_dir,
            config_data=self.mock_config,
            api_client=self.mock_client
        )
        
        # Create mock scan results
        results = {
            "test.py": {
                "status": "completed",
                "clean": True,
                "detections": 0
            }
        }
        
        # Save results
        session._save_results(results)
        
        # Verify file was created
        history_file = Path(self.test_dir) / "scan_history.jsonl"
        self.assertTrue(history_file.exists())
        
        # Load and verify
        history = session.load_scan_history()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["file_count"], 1)
        self.assertFalse(history[0]["blocked"])


class TestIntegrationScanSessionWorkflow(unittest.TestCase):
    """Integration test: ScanSession coordinates all components."""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        Path(self.test_dir, ".git").mkdir()
        
        # Create test files
        py_file = Path(self.test_dir) / "clean.py"
        py_file.write_text("print('clean')")
        
        self.mock_config = {
            "api_key": "test",
            "base_url": "https://test.api",
            "timeout_s": 10,
            "scan_timeout_s": 30,
            "poll_interval_s": 1
        }
        
        self.mock_client = Mock()
    
    def tearDown(self):
        shutil.rmtree(self.test_dir)
    
    @patch('src.library_name.submit_scan')
    @patch('src.library_name.poll_scan_completion')
    def test_session_orchestrates_full_scan(self, mock_poll, mock_submit):
        """Test ScanSession orchestrates factory, strategies, and persistence."""
        # Setup mocks
        mock_submit.return_value = "fake_scan_id"
        mock_poll.return_value = {
            "status": "completed",
            "clean": True,
            "detections": 0
        }
        
        session = ScanSession(
            repo_root=self.test_dir,
            config_data=self.mock_config,
            api_client=self.mock_client,
            staged_files_override=["clean.py"]
        )
        
        # Run scan
        artifacts = session.collect_artifacts()
        results = session.scan_artifacts(artifacts)
        exit_code = session.evaluate(results)
        
        # Verify orchestration
        self.assertEqual(len(artifacts), 1)
        self.assertEqual(len(results), 1)
        self.assertEqual(exit_code, 0)  # Clean file = allow push
        
        # Verify history was saved
        history = session.load_scan_history()
        self.assertEqual(len(history), 1)


class TestIntegrationHookPolymorphism(unittest.TestCase):
    """Integration test: Hook classes demonstrate polymorphism."""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        Path(self.test_dir, ".git").mkdir()
        
        test_file = Path(self.test_dir) / "test.py"
        test_file.write_text("test")
        
        self.mock_config = {
            "api_key": "test",
            "base_url": "https://test.api",
            "timeout_s": 10
        }
        
        self.mock_client = Mock()
    
    def tearDown(self):
        shutil.rmtree(self.test_dir)
    
    @patch('src.library_name.submit_scan')
    @patch('src.library_name.poll_scan_completion')
    def test_different_hooks_use_same_interface(self, mock_poll, mock_submit):
        """Test PrePushHook and ManualScanHook share common interface."""
        mock_submit.return_value = "id"
        mock_poll.return_value = {"status": "completed", "clean": True, "detections": 0}
        
        session = ScanSession(
            repo_root=self.test_dir,
            config_data=self.mock_config,
            api_client=self.mock_client,
            staged_files_override=["test.py"]
        )
        
        # Test PrePushHook
        pre_push_hook = PrePushHook(session)
        exit_code_1 = pre_push_hook.run()
        
        # Test ManualScanHook
        manual_hook = ManualScanHook(session, ["test.py"])
        exit_code_2 = manual_hook.run()
        
        # Both should succeed
        self.assertEqual(exit_code_1, 0)
        self.assertEqual(exit_code_2, 0)


# SYSTEM TESTS - Test complete end-to-end workflows (3-5 required)

class TestSystemCompleteCleanScan(unittest.TestCase):
    """System test: Complete scan workflow with clean file."""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        Path(self.test_dir, ".git").mkdir()
        
        clean_file = Path(self.test_dir) / "clean_code.py"
        clean_file.write_text("def hello(): return 'world'")
        
        self.config = {
            "api_key": "test_key",
            "base_url": "https://test.api",
            "timeout_s": 10,
            "scan_timeout_s": 30,
            "poll_interval_s": 1
        }
        
        self.mock_client = Mock()
    
    def tearDown(self):
        shutil.rmtree(self.test_dir)
    
    @patch('src.library_name.submit_scan')
    @patch('src.library_name.poll_scan_completion')
    def test_end_to_end_clean_file_allowed(self, mock_poll, mock_submit):
        """System test: Clean file scans successfully and push is allowed."""
        # Mock VirusTotal returning clean result
        mock_submit.return_value = "scan_123"
        mock_poll.return_value = {
            "status": "completed",
            "clean": True,
            "detections": 0,
            "total": 70
        }
        
        # Create session and run full scan
        session = ScanSession(
            repo_root=self.test_dir,
            config_data=self.config,
            api_client=self.mock_client,
            staged_files_override=["clean_code.py"]
        )
        
        hook = PrePushHook(session)
        exit_code = hook.run()
        
        # Verify: Clean file should allow push
        self.assertEqual(exit_code, 0)
        
        # Verify: History was saved
        history = session.load_scan_history()
        self.assertEqual(len(history), 1)
        self.assertFalse(history[0]["blocked"])
        self.assertTrue(history[0]["verdict"]["clean_code.py"])


class TestSystemCompleteInfectedScan(unittest.TestCase):
    """System test: Complete scan workflow with infected file."""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        Path(self.test_dir, ".git").mkdir()
        
        infected_file = Path(self.test_dir) / "malware.exe"
        infected_file.write_bytes(b'\x00MALWARE')
        
        self.config = {
            "api_key": "test_key",
            "base_url": "https://test.api",
            "timeout_s": 10
        }
        
        self.mock_client = Mock()
    
    def tearDown(self):
        shutil.rmtree(self.test_dir)
    
    @patch('src.library_name.submit_scan')
    @patch('src.library_name.poll_scan_completion')
    def test_end_to_end_infected_file_blocked(self, mock_poll, mock_submit):
        """System test: Infected file is detected and push is blocked."""
        # Mock VirusTotal returning infected result
        mock_submit.return_value = "scan_456"
        mock_poll.return_value = {
            "status": "completed",
            "clean": False,
            "detections": 47,
            "total": 70
        }
        
        session = ScanSession(
            repo_root=self.test_dir,
            config_data=self.config,
            api_client=self.mock_client,
            staged_files_override=["malware.exe"]
        )
        
        hook = PrePushHook(session)
        exit_code = hook.run()
        
        # Verify: Infected file should block push
        self.assertEqual(exit_code, 1)
        
        # Verify: History shows blocked push
        history = session.load_scan_history()
        self.assertEqual(len(history), 1)
        self.assertTrue(history[0]["blocked"])
        self.assertFalse(history[0]["verdict"]["malware.exe"])


class TestSystemMultipleFileScan(unittest.TestCase):
    """System test: Scan multiple files with mixed results."""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        Path(self.test_dir, ".git").mkdir()
        
        # Create clean file
        clean = Path(self.test_dir) / "clean.py"
        clean.write_text("print('safe')")
        
        # Create another clean file
        clean2 = Path(self.test_dir) / "utils.py"
        clean2.write_text("def helper(): pass")
        
        # Create infected file
        infected = Path(self.test_dir) / "virus.exe"
        infected.write_bytes(b'\x00VIRUS')
        
        self.config = {
            "api_key": "test",
            "base_url": "https://test.api",
            "timeout_s": 10
        }
        
        self.mock_client = Mock()
    
    def tearDown(self):
        shutil.rmtree(self.test_dir)
    
    @patch('src.library_name.submit_scan')
    @patch('src.library_name.poll_scan_completion')
    def test_end_to_end_mixed_files_blocks_on_any_infection(self, mock_poll, mock_submit):
        """System test: Multiple files scanned, blocks if any infected."""
        mock_submit.return_value = "scan_id"
        
        # Mock responses: 2 clean, 1 infected
        def mock_poll_side_effect(*args, **kwargs):
            scan_id = args[1]
            if "virus" in str(scan_id):
                return {"status": "completed", "clean": False, "detections": 50}
            return {"status": "completed", "clean": True, "detections": 0}
        
        mock_poll.side_effect = mock_poll_side_effect
        
        session = ScanSession(
            repo_root=self.test_dir,
            config_data=self.config,
            api_client=self.mock_client,
            staged_files_override=["clean.py", "utils.py", "virus.exe"]
        )
        
        hook = PrePushHook(session)
        exit_code = hook.run()
        
        # Verify: Should block because one file is infected
        self.assertEqual(exit_code, 1)
        
        # Verify: History shows 3 files scanned, push blocked
        history = session.load_scan_history()
        self.assertEqual(history[0]["file_count"], 3)
        self.assertTrue(history[0]["blocked"])


class TestSystemPersistenceAcrossSessions(unittest.TestCase):
    """System test: Data persists across multiple scan sessions."""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        Path(self.test_dir, ".git").mkdir()
        
        test_file = Path(self.test_dir) / "app.py"
        test_file.write_text("app code")
        
        self.config = {
            "api_key": "test",
            "base_url": "https://test.api",
            "timeout_s": 10
        }
        
        self.mock_client = Mock()
    
    def tearDown(self):
        shutil.rmtree(self.test_dir)
    
    @patch('src.library_name.submit_scan')
    @patch('src.library_name.poll_scan_completion')
    def test_end_to_end_persistence_across_multiple_scans(self, mock_poll, mock_submit):
        """System test: Multiple scans accumulate in history."""
        mock_submit.return_value = "id"
        mock_poll.return_value = {"status": "completed", "clean": True, "detections": 0}
        
        # Run first scan session
        session1 = ScanSession(
            repo_root=self.test_dir,
            config_data=self.config,
            api_client=self.mock_client,
            staged_files_override=["app.py"]
        )
        hook1 = PrePushHook(session1)
        hook1.run()
        
        # Run second scan session
        session2 = ScanSession(
            repo_root=self.test_dir,
            config_data=self.config,
            api_client=self.mock_client,
            staged_files_override=["app.py"]
        )
        hook2 = PrePushHook(session2)
        hook2.run()
        
        # Run third scan session
        session3 = ScanSession(
            repo_root=self.test_dir,
            config_data=self.config,
            api_client=self.mock_client,
            staged_files_override=["app.py"]
        )
        hook3 = PrePushHook(session3)
        hook3.run()
        
        # Verify: All 3 scans are in history
        history = session3.load_scan_history()
        self.assertEqual(len(history), 3)
        
        # Verify: Most recent scan is first
        self.assertTrue(history[0]["timestamp"] > history[1]["timestamp"])
        self.assertTrue(history[1]["timestamp"] > history[2]["timestamp"])


class TestSystemDataImportExport(unittest.TestCase):
    """System test: Import config (JSON) and export history (JSONL)."""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        Path(self.test_dir, ".git").mkdir()
        
        # Create config file
        config_file = Path(self.test_dir) / "virus_scan_config.json"
        config_data = {
            "api_key": "imported_key",
            "base_url": "https://imported.api",
            "timeout_s": 15
        }
        config_file.write_text(json.dumps(config_data))
        
        test_file = Path(self.test_dir) / "code.py"
        test_file.write_text("code")
        
        self.mock_client = Mock()
    
    def tearDown(self):
        shutil.rmtree(self.test_dir)
    
    @patch('src.library_name.submit_scan')
    @patch('src.library_name.poll_scan_completion')
    def test_end_to_end_import_json_export_jsonl(self, mock_poll, mock_submit):
        """System test: Import JSON config, run scan, export JSONL history."""
        mock_submit.return_value = "id"
        mock_poll.return_value = {"status": "completed", "clean": True, "detections": 0}
        
        # Import: Load config from JSON
        session = ScanSession(
            repo_root=self.test_dir,
            api_client=self.mock_client,
            staged_files_override=["code.py"]
        )
        
        # Verify config was imported
        self.assertEqual(session.config["api_key"], "imported_key")
        
        # Run scan
        hook = PrePushHook(session)
        hook.run()
        
        # Export: Verify JSONL file was created
        history_file = Path(self.test_dir) / "scan_history.jsonl"
        self.assertTrue(history_file.exists())
        
        # Verify JSONL format
        with open(history_file, 'r') as f:
            line = f.readline()
            entry = json.loads(line)
            self.assertIn("timestamp", entry)
            self.assertIn("results", entry)
            self.assertIn("verdict", entry)


if __name__ == '__main__':
    unittest.main()