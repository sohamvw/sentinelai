"""
Test script for SentinelAI Knowledge Retriever.
Tests Phase 5: CVE/NVD/KEV knowledge retrieval functionality.
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
from app.services.knowledge_retriever import KnowledgeRetriever
from app.phases.phase_5_knowledge_retriever import Phase5KnowledgeRetriever
def test_knowledge_retriever_initialization():
    """Test KnowledgeRetriever initialization."""
    print("Testing KnowledgeRetriever initialization...")

    # Create test workspace
    test_scan_id = "TEST-KNOWLEDGE-20240101-123456-abcdef12"
    workspace_path = Path(__file__).resolve().parents[1] / "runtime" / "workspaces" / test_scan_id
    workspace_path.mkdir(parents=True, exist_ok=True)

    try:
        # Initialize KnowledgeRetriever
        knowledge_retriever = KnowledgeRetriever(str(workspace_path))

        # Test initial state
        assert knowledge_retriever.knowledge_base == {}
        assert knowledge_retriever.last_sync is None

        print("✓ KnowledgeRetriever initialization tests passed")

    finally:
        # Clean up test workspace
        import shutil
        if workspace_path.exists():
            shutil.rmtree(workspace_path)
def test_local_knowledge_base_loading():
    """Test local knowledge base loading."""
    print("Testing local knowledge base loading...")

    # Create test workspace
    test_scan_id = "TEST-LOAD-20240101-123456-abcdef12"
    workspace_path = Path(__file__).resolve().parents[1] / "runtime" / "workspaces" / test_scan_id
    workspace_path.mkdir(parents=True, exist_ok=True)

    # Create mock knowledge base file
    kb_file = workspace_path / "knowledge_base.json"
    mock_kb = {
        "CVE-2024-12345": {
            "source": "NVD",
            "record": {
                "cve": {
                    "CVE_data_meta": {"ID": "CVE-2024-12345"},
                    "description": {"description_data": [{"value": "Test vulnerability"}]}
                }
            },
            "ingested_at": "2024-01-01T12:00:00.000Z",
            "enriched": {
                "cvss_score": 9.8,
                "cvss_severity": "CRITICAL",
                "description": "Test vulnerability",
                "cwe_ids": ["CWE-78"]
            }
        }
    }

    with open(kb_file, 'w', encoding='utf-8') as f:
        json.dump(mock_kb, f, indent=2)

    try:
        # Initialize KnowledgeRetriever
        knowledge_retriever = KnowledgeRetriever(str(workspace_path))

        # Load knowledge base
        success = knowledge_retriever.load_local_knowledge_base()
        assert success

        # Verify knowledge base was loaded
        assert len(knowledge_retriever.knowledge_base) == 1
        assert "CVE-2024-12345" in knowledge_retriever.knowledge_base

        print("✓ Local knowledge base loading tests passed")

    finally:
        # Clean up test workspace
        import shutil
        if workspace_path.exists():
            shutil.rmtree(workspace_path)
def test_enrichment_functions():
    """Test record enrichment functions."""
    print("Testing enrichment functions...")

    # Create test workspace
    test_scan_id = "TEST-ENRICH-20240101-123456-abcdef12"
    workspace_path = Path(__file__).resolve().parents[1] / "runtime" / "workspaces" / test_scan_id
    workspace_path.mkdir(parents=True, exist_ok=True)

    # Initialize KnowledgeRetriever
    knowledge_retriever = KnowledgeRetriever(str(workspace_path))

    try:
        # Test NVD record enrichment
        mock_nvd_record = {
            "cve": {
                "CVE_data_meta": {"ID": "CVE-2024-TEST1"},
                "description": {"description_data": [{"value": "Test NVD vulnerability"}]},
                "cvss": {"baseScore": 8.5, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "baseSeverity": "HIGH"},
                "problemtype": {"problemtype_data": [{"description": {"value": "CWE-78: OS Command Injection"}}]},
                "references": {"reference_data": []}
            }
        }

        enriched = knowledge_retriever._enrich_nvd_record(mock_nvd_record)
        assert enriched["cvss_score"] == 8.5
        assert enriched["cvss_severity"] == "HIGH"
        assert enriched["description"] == "Test NVD vulnerability"
        assert "CWE-78" in enriched["cwe_ids"]

        # Test KEV record enrichment
        mock_kev_record = {
            "vulnerability_id": "CVE-2024-TEST2",
            "date_added": "2024-01-01T00:00:00.000Z",
            "short_description": "Test KEV vulnerability",
            "recommended_action": "Apply patch",
            "affected_products": ["Test Product"],
            "exploit_status": "Exploited",
            "patch_availability": "Available",
            "vendor_advisory": "https://vendor.com/advisory"
        }

        enriched = knowledge_retriever._enrich_kev_record(mock_kev_record)
        assert enriched["date_added"] == "2024-01-01T00:00:00.000Z"
        assert enriched["exploit_status"] == "Exploited"
        assert enriched["recommended_action"] == "Apply patch"

        print("✓ Enrichment functions tests passed")

    finally:
        # Clean up test workspace
        import shutil
        if workspace_path.exists():
            shutil.rmtree(workspace_path)
def test_relevance_calculation():
    """Test relevance calculation functions."""
    print("Testing relevance calculation...")

    # Create test workspace
    test_scan_id = "TEST-RELEVANCE-20240101-123456-abcdef12"
    workspace_path = Path(__file__).resolve().parents[1] / "runtime" / "workspaces" / test_scan_id
    workspace_path.mkdir(parents=True, exist_ok=True)

    # Initialize KnowledgeRetriever
    knowledge_retriever = KnowledgeRetriever(str(workspace_path))

    try:
        # Test technology relevance calculation
        tech_relevance = knowledge_retriever._calculate_technology_relevance(
            "python", "python buffer overflow vulnerability", ["CWE-119"]
        )
        assert tech_relevance > 0.0

        # Test security area relevance calculation
        security_relevance = knowledge_retriever._calculate_security_area_relevance(
            "authentication", "authentication bypass vulnerability"
        )
        assert security_relevance > 0.0

        # Test file relevance calculation
        file_relevance = knowledge_retriever._calculate_file_relevance(
            "password_manager.py", "hardcoded password vulnerability"
        )
        assert file_relevance > 0.0

        print("✓ Relevance calculation tests passed")

    finally:
        # Clean up test workspace
        import shutil
        if workspace_path.exists():
            shutil.rmtree(workspace_path)
def test_vulnerability_searching():
    """Test vulnerability searching functionality."""
    print("Testing vulnerability searching...")

    # Create test workspace
    test_scan_id = "TEST-SEARCH-20240101-123456-abcdef12"
    workspace_path = Path(__file__).resolve().parents[1] / "runtime" / "workspaces" / test_scan_id
    workspace_path.mkdir(parents=True, exist_ok=True)

    # Initialize KnowledgeRetriever
    knowledge_retriever = KnowledgeRetriever(str(workspace_path))

    try:
        # Add mock vulnerabilities to knowledge base
        knowledge_retriever.knowledge_base = {
            "CVE-2024-TEST1": {
                "source": "NVD",
                "enriched": {
                    "description": "python buffer overflow vulnerability",
                    "cvss_severity": "CRITICAL",
                    "cwe_ids": ["CWE-119"]
                }
            },
            "CVE-2024-TEST2": {
                "source": "CISA KEV",
                "enriched": {
                    "description": "authentication bypass vulnerability",
                    "cvss_severity": "HIGH",
                    "cwe_ids": ["CWE-287"]
                }
            }
        }

        # Test technology-based search
        python_vulns = knowledge_retriever.search_vulnerabilities("python", "", "python")
        assert len(python_vulns) > 0
        assert any(vuln["cve_id"] == "CVE-2024-TEST1" for vuln in python_vulns)

        # Test security area-based search
        auth_vulns = knowledge_retriever.search_vulnerabilities("authentication", "", "")
        assert len(auth_vulns) > 0
        assert any(vuln["cve_id"] == "CVE-2024-TEST2" for vuln in auth_vulns)

        print("✓ Vulnerability searching tests passed")

    finally:
        # Clean up test workspace
        import shutil
        if workspace_path.exists():
            shutil.rmtree(workspace_path)
def test_phase5_analyzer_initialization():
    """Test Phase5KnowledgeRetriever initialization."""
    print("Testing Phase5KnowledgeRetriever initialization...")

    # Create test scan request
    scan_request = ScanRequest(
        source_type="github",
        repository_url="https://github.com/test/repo",
        branch="main"
    )

    # Create test workspace
    test_scan_id = "TEST-PHASE5-20240101-123456-abcdef12"
    workspace_path = Path(__file__).resolve().parents[1] / "runtime" / "workspaces" / test_scan_id
    workspace_path.mkdir(parents=True, exist_ok=True)

    try:
        # Initialize Phase5KnowledgeRetriever
        phase5_analyzer = Phase5KnowledgeRetriever(test_scan_id, scan_request, str(workspace_path))

        # Test workspace path
        assert phase5_analyzer.workspace_path == workspace_path
        assert phase5_analyzer.scan_id == test_scan_id
        assert isinstance(phase5_analyzer.scan_request, ScanRequest)

        print("✓ Phase5KnowledgeRetriever initialization tests passed")

    finally:
        # Clean up test workspace
        import shutil
        if workspace_path.exists():
            shutil.rmtree(workspace_path)
def test_phase5_analyzer_methods():
    """Test Phase5KnowledgeRetriever helper methods."""
    print("Testing Phase5KnowledgeRetriever helper methods...")

    # Create test workspace
    test_scan_id = "TEST-PHASE5-METHODS-20240101-123456-abcdef12"
    workspace_path = Path(__file__).resolve().parents[1] / "runtime" / "workspaces" / test_scan_id
    workspace_path.mkdir(parents=True, exist_ok=True)

    # Create mock analysis plan
    analysis_plan = {
        "scan_id": test_scan_id,
        "stack": ["python", "django"],
        "languages": {"python": {"file_count": 10}},
        "security_sensitive_areas": [{"type": "authentication", "area": "auth_module"}],
        "important_files": ["models.py", "views.py"]
    }

    analysis_path = workspace_path / "analysis_plan.json"
    with open(analysis_path, 'w', encoding='utf-8') as f:
        json.dump(analysis_plan, f, indent=2)

    try:
        # Create test scan request
        scan_request = ScanRequest(
            source_type="github",
            repository_url="https://github.com/test/repo",
            branch="main"
        )

        # Initialize Phase5KnowledgeRetriever
        phase5_analyzer = Phase5KnowledgeRetriever(test_scan_id, scan_request, str(workspace_path))

        # Test helper methods
        stack = phase5_analyzer._extract_stack_from_analysis_plan()
        assert stack == ["python", "django"]

        languages = phase5_analyzer._extract_languages_from_analysis_plan()
        assert "python" in languages

        security_areas = phase5_analyzer._extract_security_areas_from_analysis_plan()
        assert len(security_areas) > 0
        assert security_areas[0]["type"] == "authentication"

        important_files = phase5_analyzer._extract_important_files_from_analysis_plan()
        assert len(important_files) > 0

        print("✓ Phase5KnowledgeRetriever helper methods tests passed")

    finally:
        # Clean up test workspace
        import shutil
        if workspace_path.exists():
            shutil.rmtree(workspace_path)
def test_knowledge_report_generation():
    """Test knowledge report generation."""
    print("Testing knowledge report generation...")

    # Create test workspace
    test_scan_id = "TEST-REPORT-20240101-123456-abcdef12"
    workspace_path = Path(__file__).resolve().parents[1] / "runtime" / "workspaces" / test_scan_id
    workspace_path.mkdir(parents=True, exist_ok=True)

    # Initialize KnowledgeRetriever
    knowledge_retriever = KnowledgeRetriever(str(workspace_path))

    # Add mock data to knowledge base
    knowledge_retriever.knowledge_base = {
        "CVE-2024-TEST1": {
            "source": "NVD",
            "enriched": {
                "cvss_severity": "CRITICAL",
                "cwe_ids": ["CWE-78", "CWE-79"]
            }
        },
        "CVE-2024-TEST2": {
            "source": "CISA KEV",
            "enriched": {
                "cvss_severity": "HIGH",
                "cwe_ids": ["CWE-287"]
            }
        }
    }
    knowledge_retriever.last_sync = datetime.now()

    try:
        # Generate knowledge report
        report = knowledge_retriever.generate_knowledge_report()

        # Validate report structure
        assert "total_knowledge_records" in report
        assert "source_distribution" in report
        assert "severity_distribution" in report
        assert "cwe_distribution" in report
        assert "ecosystem_distribution" in report
        assert "last_sync" in report

        # Validate report content
        assert report["total_knowledge_records"] == 2
        assert report["ecosystem_distribution"]["NVD"] == 1
        assert report["ecosystem_distribution"]["CISA KEV"] == 1
        assert report["severity_distribution"]["CRITICAL"] == 1
        assert report["severity_distribution"]["HIGH"] == 1

        print("✓ Knowledge report generation tests passed")

    finally:
        # Clean up test workspace
        import shutil
        if workspace_path.exists():
            shutil.rmtree(workspace_path)
def run_all_tests():
    """Run all knowledge retriever tests."""
    print("=" * 70)
    print("SentinelAI Knowledge Retriever Tests")
    print("=" * 70)

    try:
        test_knowledge_retriever_initialization()
        test_local_knowledge_base_loading()
        test_enrichment_functions()
        test_relevance_calculation()
        test_vulnerability_searching()
        test_phase5_analyzer_initialization()
        test_phase5_analyzer_methods()
        test_knowledge_report_generation()

        print("\n" + "=" * 70)
        print("All knowledge retriever tests passed! ✓")
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
