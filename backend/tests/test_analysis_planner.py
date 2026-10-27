"""
Test script for SentinelAI Phase 2 Analysis Planner.
Tests repository tree analysis and analysis plan generation.
"""

import sys
import os
import tempfile
import json
from pathlib import Path
from unittest.mock import patch

# Add the backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.schemas.scan_request import ScanRequest
from app.services.analysis_planner import AnalysisPlanner
from app.phases.phase_2_analysis_planner import Phase2AnalysisPlanner
def test_scan_request_for_analysis():
    """Test ScanRequest for analysis planner usage."""
    print("Testing ScanRequest for analysis planning...")

    # Test GitHub request
    github_request = ScanRequest(
        source_type="github",
        repository_url="https://github.com/example/repo",
        branch="main",
        preferred_languages=["python", "javascript"],
        preferred_frameworks=["django", "react"]
    )

    assert github_request.source_type == "github"
    assert github_request.get_repository_identifier() == "example/repo"
    assert "python" in github_request.preferred_languages
    assert "django" in github_request.preferred_frameworks

    # Test ZIP request
    zip_request = ScanRequest(
        source_type="zip",
        repository_url="https://example.com/repo.zip",
        branch="develop"
    )

    assert zip_request.source_type == "zip"
    assert zip_request.get_repository_identifier() == "unknown"

    print("✓ ScanRequest tests passed")
def test_analysis_planner_initialization():
    """Test AnalysisPlanner initialization with mock tree data."""
    print("Testing AnalysisPlanner initialization...")

    # Create mock tree data
    mock_tree_data = {
        "total_files": 10,
        "files": [
            {
                "path": "README.md",
                "ext": "md",
                "size": 100,
                "is_text": True,
                "is_entry_point": False,
                "is_config": False,
                "is_test": False,
                "is_documentation": True,
                "is_dependency_manifest": False,
                "language": "markdown",
                "likely_entry_point": False,
                "likely_configuration": False,
                "test_indicator": False,
                "documentation_indicator": True,
                "dependency_manifest_indicator": False,
            },
            {
                "path": "main.py",
                "ext": "py",
                "size": 1500,
                "is_text": True,
                "is_entry_point": True,
                "is_config": False,
                "is_test": False,
                "is_documentation": False,
                "is_dependency_manifest": False,
                "language": "python",
                "likely_entry_point": True,
                "likely_configuration": False,
                "test_indicator": False,
                "documentation_indicator": False,
                "dependency_manifest_indicator": False,
            },
            {
                "path": "requirements.txt",
                "ext": "txt",
                "size": 200,
                "is_text": True,
                "is_entry_point": False,
                "is_config": True,
                "is_test": False,
                "is_documentation": False,
                "is_dependency_manifest": True,
                "language": None,
                "likely_entry_point": False,
                "likely_configuration": True,
                "test_indicator": False,
                "documentation_indicator": False,
                "dependency_manifest_indicator": True,
            },
        ]
    }

    # Create test scan request
    scan_request = ScanRequest(
        source_type="github",
        repository_url="https://github.com/test/repo",
        branch="main"
    )

    # Initialize AnalysisPlanner
    analysis_planner = AnalysisPlanner(scan_request, mock_tree_data)

    # Test language statistics
    language_stats = analysis_planner._calculate_language_statistics()
    assert "python" in language_stats
    assert language_stats["python"]["file_count"] == 1
    assert language_stats["python"]["importance"] > 0

    # Test framework candidates
    frameworks = analysis_planner._identify_framework_candidates()
    # Should find python_pip from requirements.txt
    assert any(f["framework"] == "python_pip" for f in frameworks)

    # Test security areas
    security_areas = analysis_planner._identify_security_areas()
    # Should identify configuration from requirements.txt
    assert any("configuration" in area.get("type", "") for area in security_areas)

    # Test dependency identification
    dependencies = analysis_planner._identify_dependencies()
    # Should identify python_dependency from requirements.txt
    assert any(dep["type"] == "python_dependency" for dep in dependencies)

    print("✓ AnalysisPlanner initialization tests passed")
def test_analysis_plan_generation():
    """Test complete analysis plan generation."""
    print("Testing analysis plan generation...")

    # Create mock tree data
    mock_tree_data = {
        "total_files": 15,
        "files": [
            {
                "path": "README.md",
                "ext": "md",
                "size": 100,
                "is_text": True,
                "is_entry_point": False,
                "is_config": False,
                "is_test": False,
                "is_documentation": True,
                "is_dependency_manifest": False,
                "language": "markdown",
                "likely_entry_point": False,
                "likely_configuration": False,
                "test_indicator": False,
                "documentation_indicator": True,
                "dependency_manifest_indicator": False,
            },
            {
                "path": "app.py",
                "ext": "py",
                "size": 2000,
                "is_text": True,
                "is_entry_point": True,
                "is_config": False,
                "is_test": False,
                "is_documentation": False,
                "is_dependency_manifest": False,
                "language": "python",
                "likely_entry_point": True,
                "likely_configuration": False,
                "test_indicator": False,
                "documentation_indicator": False,
                "dependency_manifest_indicator": False,
            },
            {
                "path": "package.json",
                "ext": "json",
                "size": 500,
                "is_text": True,
                "is_entry_point": False,
                "is_config": True,
                "is_test": False,
                "is_documentation": False,
                "is_dependency_manifest": True,
                "language": "json",
                "likely_entry_point": False,
                "likely_configuration": True,
                "test_indicator": False,
                "documentation_indicator": False,
                "dependency_manifest_indicator": True,
            },
            {
                "path": "Dockerfile",
                "ext": "dockerfile",
                "size": 300,
                "is_text": True,
                "is_entry_point": False,
                "is_config": True,
                "is_test": False,
                "is_documentation": False,
                "is_dependency_manifest": False,
                "language": None,
                "likely_entry_point": False,
                "likely_configuration": True,
                "test_indicator": False,
                "documentation_indicator": False,
                "dependency_manifest_indicator": False,
            },
            {
                "path": "test_example.py",
                "ext": "py",
                "size": 800,
                "is_text": True,
                "is_entry_point": False,
                "is_config": False,
                "is_test": True,
                "is_documentation": False,
                "is_dependency_manifest": False,
                "language": "python",
                "likely_entry_point": False,
                "likely_configuration": False,
                "test_indicator": True,
                "documentation_indicator": False,
                "dependency_manifest_indicator": False,
            },
        ]
    }

    # Create test scan request
    scan_request = ScanRequest(
        source_type="github",
        repository_url="https://github.com/test/repo",
        branch="main"
    )

    # Initialize and generate analysis plan
    analysis_planner = AnalysisPlanner(scan_request, mock_tree_data)
    analysis_plan = analysis_planner.generate_analysis_plan()

    # Validate analysis plan structure
    assert "scan_id" in analysis_plan
    assert "timestamp" in analysis_plan
    assert "repository_info" in analysis_plan
    assert "stack" in analysis_plan
    assert "languages" in analysis_plan
    assert "frameworks" in analysis_plan
    assert "confidence" in analysis_plan
    assert "important_files" in analysis_plan
    assert "security_sensitive_areas" in analysis_plan
    assert "dependency_queries" in analysis_plan
    assert "vulnerability_knowledge_queries" in analysis_plan
    assert "compliance_queries" in analysis_plan
    assert "required_tools" in analysis_plan
    assert "required_deterministic_checks" in analysis_plan
    assert "required_ast_checks" in analysis_plan
    assert "decision_reasons" in analysis_plan
    assert "estimated_scope" in analysis_plan
    assert "prioritization" in analysis_plan

    # Validate specific content
    assert "python" in analysis_plan["stack"]
    assert len(analysis_plan["important_files"]) > 0
    assert len(analysis_planner._identify_framework_candidates()) > 0
    assert len(analysis_planner._identify_security_areas()) > 0
    assert len(analysis_planner._identify_dependencies()) > 0

    print("✓ Analysis plan generation tests passed")
def test_phase_2_analyzer():
    """Test Phase2AnalysisPlanner integration."""
    print("Testing Phase2AnalysisPlanner integration...")

    # Create test scan request
    scan_request = ScanRequest(
        source_type="github",
        repository_url="https://github.com/test/repo",
        branch="main"
    )

    # Create test workspace
    test_scan_id = "TEST-20240101-123456-abcdef12"
    workspace_path = Path(__file__).resolve().parents[1] / "runtime" / "workspaces" / test_scan_id
    workspace_path.mkdir(parents=True, exist_ok=True)

    # Create mock tree.json
    mock_tree_data = {
        "total_files": 5,
        "files": [
            {
                "path": "README.md",
                "ext": "md",
                "size": 100,
                "is_text": True,
                "is_entry_point": False,
                "is_config": False,
                "is_test": False,
                "is_documentation": True,
                "is_dependency_manifest": False,
            },
        ]
    }

    # Write tree.json
    tree_path = workspace_path / "tree.json"
    with open(tree_path, 'w', encoding='utf-8') as f:
        json.dump(mock_tree_data, f, indent=2)

    try:
        # Test Phase2AnalysisPlanner
        phase2_analyzer = Phase2AnalysisPlanner(test_scan_id, scan_request)

        # Test tree loading
        loaded_tree = phase2_analyzer._load_tree_json()
        assert loaded_tree["total_files"] == 5

        # Test tree loading validation
        assert phase2_analyzer._load_tree_json()["total_files"] == 5

        print("✓ Phase2AnalysisPlanner integration tests passed")

    finally:
        # Clean up test workspace
        import shutil
        if workspace_path.exists():
            shutil.rmtree(workspace_path)
def test_extension_to_language_mapping():
    """Test file extension to language mapping."""
    print("Testing extension to language mapping...")

    # Create mock tree data with various extensions
    mock_tree_data = {
        "total_files": 8,
        "files": [
            {"path": "test.py", "ext": "py", "size": 100},
            {"path": "app.js", "ext": "js", "size": 200},
            {"path": "index.ts", "ext": "ts", "size": 300},
            {"path": "main.java", "ext": "java", "size": 400},
            {"path": "code.cpp", "ext": "cpp", "size": 500},
            {"path": "document.md", "ext": "md", "size": 600},
            {"path": "config.json", "ext": "json", "size": 700},
            {"path": "Dockerfile", "ext": "dockerfile", "size": 800},
        ]
    }

    # Create test scan request
    scan_request = ScanRequest(
        source_type="github",
        repository_url="https://github.com/test/repo",
        branch="main"
    )

    # Initialize AnalysisPlanner
    analysis_planner = AnalysisPlanner(scan_request, mock_tree_data)

    # Test language detection
    language_stats = analysis_planner._calculate_language_statistics()

    assert "python" in language_stats
    assert "javascript" in language_stats
    assert "typescript" in language_stats
    assert "java" in language_stats
    assert "cpp" in language_stats
    assert "markdown" in language_stats
    assert "config" in language_stats
    assert "dockerfile" in language_stats

    print("✓ Extension to language mapping tests passed")
def test_security_area_identification():
    """Test security area identification logic."""
    print("Testing security area identification...")

    # Create mock tree data with security-related files
    mock_tree_data = {
        "total_files": 6,
        "files": [
            {"path": "auth.py", "ext": "py", "name": "auth.py", "size": 100},
            {"path": "login.js", "ext": "js", "name": "login.js", "size": 200},
            {"path": "config.json", "ext": "json", "name": "config.json", "size": 300},
            {"path": "secret_key.txt", "ext": "txt", "name": "secret_key.txt", "size": 400},
            {"path": "database.sql", "ext": "sql", "name": "database.sql", "size": 500},
            {"path": "Dockerfile", "ext": "dockerfile", "name": "Dockerfile", "size": 600},
        ]
    }

    # Create test scan request
    scan_request = ScanRequest(
        source_type="github",
        repository_url="https://github.com/test/repo",
        branch="main"
    )

    # Initialize AnalysisPlanner
    analysis_planner = AnalysisPlanner(scan_request, mock_tree_data)

    # Test security area identification
    security_areas = analysis_planner._identify_security_areas()

    # Should identify various security areas
    auth_areas = [area for area in security_areas if "authentication" in area.get("type", "")]
    config_areas = [area for area in security_areas if "configuration" in area.get("type", "")]
    security_areas_list = [area for area in security_areas if "security" in area.get("type", "")]

    assert len(auth_areas) > 0
    assert len(config_areas) > 0
    assert len(security_areas_list) > 0

    print("✓ Security area identification tests passed")
def run_all_tests():
    """Run all analysis planner tests."""
    print("=" * 70)
    print("SentinelAI Phase 2 Analysis Planner Tests")
    print("=" * 70)

    try:
        test_scan_request_for_analysis()
        test_analysis_planner_initialization()
        test_analysis_plan_generation()
        test_phase_2_analyzer()
        test_extension_to_language_mapping()
        test_security_area_identification()

        print("\n" + "=" * 70)
        print("All Phase 2 Analysis Planner tests passed! ✓")
        print("=" * 70)
        return True

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
