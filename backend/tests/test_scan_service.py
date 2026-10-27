"""
Test script for SentinelAI Scan Service functionality.
Tests repository discovery, metadata extraction, and tree generation.
"""

import sys
import os
import tempfile
import json
from pathlib import Path

# Add the backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.services.scan_service import ScanService
from app.schemas.scan_request import ScanRequest
def test_scan_request_schema():
    """Test ScanRequest schema validation."""
    print("Testing ScanRequest schema...")

    # Test valid GitHub request
    github_request = ScanRequest(
        source_type="github",
        repository_url="https://github.com/owner/repo",
        branch="main"
    )
    assert github_request.get_repository_identifier() == "owner/repo"
    print("✓ GitHub request validation passed")

    # Test valid ZIP request
    zip_request = ScanRequest(
        source_type="zip",
        repository_url="https://example.com/repo.zip",
        branch="develop"
    )
    assert zip_request.get_repository_identifier() == "unknown"
    print("✓ ZIP request validation passed")

    # Test owner/repo format
    direct_request = ScanRequest(
        source_type="github",
        repository_url="owner/repo",
        branch="main"
    )
    assert direct_request.get_repository_identifier() == "owner/repo"
    print("✓ Direct format request validation passed")

    print("ScanRequest schema tests passed!\n")
def test_tree_walking():
    """Test repository tree walking functionality."""
    print("Testing repository tree walking...")

    # Create a temporary test repository structure
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Create test files
        (temp_path / "README.md").write_text("# Test Repository")
        (temp_path / "main.py").write_text("def main(): pass")
        (temp_path / "app").mkdir()
        (temp_path / "app" / "__init__.py").write_text("")
        (temp_path / "app" / "utils.py").write_text("def util(): pass")
        (temp_path / "tests").mkdir()
        (temp_path / "tests" / "test_app.py").write_text("def test(): pass")
        (temp_path / "requirements.txt").write_text("fastapi==0.104.1")
        (temp_path / "Dockerfile").write_text("FROM python:3.11-slim")

        # Test tree walking
        tree_data = ScanService.walk_repository(str(temp_path))

        # Verify structure
        assert "total_files" in tree_data
        assert "files" in tree_data
        assert tree_data["total_files"] == 7

        # Check that specific files were detected
        file_paths = [file_info["path"] for file_info in tree_data["files"]]

        expected_files = {"README.md", "main.py", "app/__init__.py", "app/utils.py",
                         "tests/test_app.py", "requirements.txt", "Dockerfile"}

        for expected_file in expected_files:
            assert any(expected_file in path for path in file_paths), f"Missing file: {expected_file}"

        # Verify file types
        for file_info in tree_data["files"]:
            if file_info["path"] == "README.md":
                assert file_info["documentation_indicator"] == True
                assert file_info["language"] == "markdown"
            elif file_info["path"] == "main.py":
                assert file_info["likely_entry_point"] == True
                assert file_info["language"] == "python"
            elif file_info["path"] == "requirements.txt":
                assert file_info["dependency_manifest_indicator"] == True
                assert file_info["is_config"] == True
            elif file_info["path"].startswith("tests/"):
                assert file_info["test_indicator"] == True

        print(f"✓ Tree walking test passed: {tree_data['total_files']} files processed")

def test_file_classification():
    """Test file classification logic."""
    print("Testing file classification...")

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Create test files
        (temp_path / "README.md").write_text("# Documentation")
        (temp_path / "app.py").write_text("def app(): pass")
        (temp_path / "test_example.py").write_text("def test(): pass")
        (temp_path / "requirements.txt").write_text("requests")
        (temp_path / "Dockerfile").write_text("FROM python:3.11")
        (temp_path / "src" / "main.py").mkdir(parents=True)
        (temp_path / "src" / "main.py" / "main.py").write_text("def main(): pass")
        (temp_path / "config.json").write_text('{"key": "value"}')

        # Test tree walking
        tree_data = ScanService.walk_repository(str(temp_path))

        # Verify classifications
        classifications = {}
        for file_info in tree_data["files"]:
            classifications[file_info["path"]] = {
                "documentation": file_info["documentation_indicator"],
                "entry_point": file_info["likely_entry_point"],
                "config": file_info["likely_configuration"],
                "test": file_info["test_indicator"],
                "dependency": file_info["dependency_manifest_indicator"]
            }

        # Check specific classifications
        assert classifications["README.md"]["documentation"] == True
        assert classifications["README.md"]["entry_point"] == False
        assert classifications["README.md"]["config"] == False
        assert classifications["README.md"]["test"] == False
        assert classifications["README.md"]["dependency"] == False

        assert classifications["app.py"]["entry_point"] == True
        assert classifications["app.py"]["documentation"] == False

        assert classifications["test_example.py"]["test"] == True

        assert classifications["requirements.txt"]["dependency"] == True
        assert classifications["requirements.txt"]["config"] == True

        assert classifications["Dockerfile"]["config"] == True

        print("✓ File classification tests passed")
def test_scan_id_generation():
    """Test scan ID generation."""
    print("Testing scan ID generation...")

    scan_id = ScanService.generate_scan_id()

    # Verify format: SCAN-YYYYMMDDHHMMSS-xxxxxxxx
    assert scan_id.startswith("SCAN-")
    assert len(scan_id) > 15  # Should be longer than just prefix

    # Check timestamp pattern
    date_part = scan_id[5:19]  # Extract YYYYMMDDHHMMSS
    assert len(date_part) == 14
    for char in date_part:
        assert char.isdigit()

    # Check random suffix
    suffix = scan_id[20:]
    assert len(suffix) >= 8

    print(f"✓ Scan ID generation test passed: {scan_id}")
def test_workspace_creation():
    """Test workspace creation."""
    print("Testing workspace creation...")

    scan_id = "TEST-20240101-123456-abcdef12"
    workspace_path = ScanService.create_scan_workspace(scan_id)

    assert Path(workspace_path).exists()
    assert workspace_path.endswith(scan_id)

    print(f"✓ Workspace creation test passed: {workspace_path}")
def test_tree_metadata_saving():
    """Test tree metadata saving."""
    print("Testing tree metadata saving...")

    # Create test data
    tree_data = {
        "total_files": 5,
        "text_files": 5,
        "binary_files": 0,
        "files": [
            {
                "path": "README.md",
                "ext": "md",
                "size": 100,
                "is_binary": False,
                "is_text": True,
                "is_entry_point": False,
                "is_config": False,
                "is_test": False,
                "is_documentation": True,
                "is_dependency_manifest": False,
                "sha256": "testhash1",
                "directory": "",
                "language": "markdown",
                "likely_entry_point": False,
                "likely_configuration": False,
                "test_indicator": False,
                "documentation_indicator": True,
                "dependency_manifest_indicator": False,
            }
        ]
    }

    scan_id = "TEST-SAVE-20240101-123456-abcdef12"

    # Create workspace directory
    workspace_path = Path(__file__).resolve().parents[1] / "runtime" / "workspaces" / scan_id
    workspace_path.mkdir(parents=True, exist_ok=True)

    # Save tree metadata
    success = ScanService.save_tree_metadata(scan_id, tree_data)

    assert success

    # Verify file was created
    tree_file_path = workspace_path / "tree.json"
    assert tree_file_path.exists()

    # Verify content
    with open(tree_file_path, 'r', encoding='utf-8') as f:
        saved_data = json.load(f)

    assert saved_data["total_files"] == 5
    assert len(saved_data["files"]) == 1
    assert saved_data["files"][0]["path"] == "README.md"

    print(f"✓ Tree metadata saving test passed: {tree_file_path}")

def run_all_tests():
    """Run all tests."""
    print("=" * 60)
    print("SentinelAI Scan Service Tests")
    print("=" * 60)

    try:
        test_scan_request_schema()
        test_tree_walking()
        test_file_classification()
        test_scan_id_generation()
        test_workspace_creation()
        test_tree_metadata_saving()

        print("\n" + "=" * 60)
        print("All tests passed! ✓")
        print("=" * 60)
        return True

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
