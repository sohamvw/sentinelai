"""
Test script for SentinelAI AST Analyzer.
Tests AST/structural analysis functionality.
"""

import sys
import os
import tempfile
import json
from pathlib import Path

# Add the backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.services.ast_analyzer import ASTAnalyzer
def test_ast_analyzer_initialization():
    """Test ASTAnalyzer initialization."""
    print("Testing ASTAnalyzer initialization...")

    # Create test workspace
    test_scan_id = "TEST-20240101-123456-abcdef12"
    workspace_path = Path(__file__).resolve().parents[1] / "runtime" / "workspaces" / test_scan_id
    workspace_path.mkdir(parents=True, exist_ok=True)

    try:
        # Initialize ASTAnalyzer
        ast_analyzer = ASTAnalyzer(test_scan_id, str(workspace_path))

        # Test repository path detection
        assert ast_analyzer.repository_path.exists()
        assert str(ast_analyzer.repository_path) == str(workspace_path)

        print("✓ ASTAnalyzer initialization tests passed")

    finally:
        # Clean up test workspace
        import shutil
        if workspace_path.exists():
            shutil.rmtree(workspace_path)
def test_python_ast_analysis():
    """Test Python AST analysis functionality."""
    print("Testing Python AST analysis...")

    # Create test workspace
    test_scan_id = "TEST-PYTHON-20240101-123456-abcdef12"
    workspace_path = Path(__file__).resolve().parents[1] / "runtime" / "workspaces" / test_scan_id
    workspace_path.mkdir(parents=True, exist_ok=True)

    # Create test Python file
    repo_path = workspace_path / "repository"
    repo_path.mkdir(exist_ok=True)

    test_py_content = '''#!/usr/bin/env python3
import pickle
import subprocess
from flask import Flask, request

app = Flask(__name__)

def main():
    # This should trigger insecure deserialization finding
    data = pickle.loads(b'')
    # This should trigger code injection finding
    eval("print('test')")
    # This should trigger database query finding
    query = "SELECT * FROM users WHERE id = %s"
    # This should trigger hardcoded secrets finding
    password = 'secret123'

@app.route('/api/test')
def api_test():
    return "test"

if __name__ == '__main__':
    main()
'''

    test_py_path = repo_path / "app.py"
    test_py_path.write_text(test_py_content)

    try:
        # Initialize ASTAnalyzer
        ast_analyzer = ASTAnalyzer(test_scan_id, str(workspace_path))

        # Run AST analysis
        results = ast_analyzer.run_ast_analysis()

        # Validate results structure
        assert "scan_id" in results
        assert results["scan_id"] == test_scan_id
        assert "findings" in results
        assert "route_analysis" in results
        assert "dependency_analysis" in results
        assert "function_analysis" in results
        assert "class_analysis" in results
        assert "security_patterns" in results
        assert "data_flow_analysis" in results

        # Check that findings were generated
        findings = results["findings"]
        assert len(findings) > 0

        # Check for specific findings
        finding_titles = [f["title"] for f in findings]
        assert any("pickle" in title.lower() for title in finding_titles)
        assert any("eval" in title.lower() for title in finding_titles)
        assert any("database" in title.lower() or "sql" in title.lower() for title in finding_titles)
        assert any("hardcoded" in title.lower() for title in finding_titles)

        print("✓ Python AST analysis tests passed")

    finally:
        # Clean up test workspace
        import shutil
        if workspace_path.exists():
            shutil.rmtree(workspace_path)
def test_javascript_ast_analysis():
    """Test JavaScript AST analysis functionality."""
    print("Testing JavaScript AST analysis...")

    # Create test workspace
    test_scan_id = "TEST-JS-20240101-123456-abcdef12"
    workspace_path = Path(__file__).resolve().parents[1] / "runtime" / "workspaces" / test_scan_id
    workspace_path.mkdir(parents=True, exist_ok=True)

    # Create test JavaScript file
    repo_path = workspace_path / "repository"
    repo_path.mkdir(exist_ok=True)

    test_js_content = '''// JavaScript file with security issues
const data = eval("console.log('test')");  // Should trigger eval finding

function maliciousFunction() {
    // Should trigger function injection finding
    const maliciousCode = Function('return "malicious"');
    return maliciousCode();
}

// DOM clobbering test
if (window.userInput) {
    document.body.innerHTML = window.userInput;  // Should trigger DOM clobbering finding
}

// XSS test
const userInput = "<script>alert('XSS')</script>";
document.getElementById('content').innerHTML = userInput;  // Should trigger XSS finding
'''

    test_js_path = repo_path / "app.js"
    test_js_path.write_text(test_js_content)

    try:
        # Initialize ASTAnalyzer
        ast_analyzer = ASTAnalyzer(test_scan_id, str(workspace_path))

        # Run AST analysis
        results = ast_analyzer.run_ast_analysis()

        # Check that JavaScript findings were generated
        findings = results["findings"]
        assert len(findings) > 0

        # Check for JavaScript-specific findings
        finding_titles = [f["title"] for f in findings]
        assert any("eval" in title.lower() for title in finding_titles)
        assert any("injection" in title.lower() for title in finding_titles)
        assert any("clobbering" in title.lower() for title in finding_titles)
        assert any("xss" in title.lower() for title in finding_titles)

        print("✓ JavaScript AST analysis tests passed")

    finally:
        # Clean up test workspace
        import shutil
        if workspace_path.exists():
            shutil.rmtree(workspace_path)
def test_html_ast_analysis():
    """Test HTML AST analysis functionality."""
    print("Testing HTML AST analysis...")

    # Create test workspace
    test_scan_id = "TEST-HTML-20240101-123456-abcdef12"
    workspace_path = Path(__file__).resolve().parents[1] / "runtime" / "workspaces" / test_scan_id
    workspace_path.mkdir(parents=True, exist_ok=True)

    # Create test HTML file
    repo_path = workspace_path / "repository"
    repo_path.mkdir(exist_ok=True)

    test_html_content = '''<!DOCTYPE html>
<html>
<head>
    <title>Test Page</title>
</head>
<body>
    <h1>Test Application</h1>

    <!-- XSS pattern - should trigger finding -->
    <div id="content">{{userInput}}</div>

    <!-- Form without CSRF protection -->
    <form method="POST">
        <input type="text" name="username">
        <input type="password" name="password">
        <button type="submit">Submit</button>
    </form>

    <script>
        // XSS vulnerability
        const maliciousScript = "<script>alert('XSS')</script>";
        document.body.innerHTML = maliciousScript;
    </script>
</body>
</html>
'''

    test_html_path = repo_path / "index.html"
    test_html_path.write_text(test_html_content)

    try:
        # Initialize ASTAnalyzer
        ast_analyzer = ASTAnalyzer(test_scan_id, str(workspace_path))

        # Run AST analysis
        results = ast_analyzer.run_ast_analysis()

        # Check that HTML findings were generated
        findings = results["findings"]
        assert len(findings) > 0

        # Check for HTML-specific findings
        finding_titles = [f["title"] for f in findings]
        assert any("xss" in title.lower() for title in finding_titles)

        print("✓ HTML AST analysis tests passed")

    finally:
        # Clean up test workspace
        import shutil
        if workspace_path.exists():
            shutil.rmtree(workspace_path)
def test_ast_helper_methods():
    """Test AST helper methods."""
    print("Testing AST helper methods...")

    # Create test workspace
    test_scan_id = "TEST-HELPERS-20240101-123456-abcdef12"
    workspace_path = Path(__file__).resolve().parents[1] / "runtime" / "workspaces" / test_scan_id
    workspace_path.mkdir(parents=True, exist_ok=True)

    # Create test Python file with various patterns
    repo_path = workspace_path / "repository"
    repo_path.mkdir(exist_ok=True)

    test_py_content = '''import pickle
import subprocess

def test_function():
    pass

class TestClass:
    pass
'''

    test_py_path = repo_path / "test.py"
    test_py_path.write_text(test_py_content)

    try:
        # Initialize ASTAnalyzer
        ast_analyzer = ASTAnalyzer(test_scan_id, str(workspace_path))

        # Test helper methods
        assert ast_analyzer._contains_import(test_py_content, "pickle") == True
        assert ast_analyzer._contains_import(test_py_content, "nonexistent") == False

        assert ast_analyzer._contains_function_definition(test_py_content, "test_function") == True
        assert ast_analyzer._contains_function_definition(test_py_content, "nonexistent") == False

        assert ast_analyzer._contains_hardcoded_secrets(test_py_content) == False

        print("✓ AST helper methods tests passed")

    finally:
        # Clean up test workspace
        import shutil
        if workspace_path.exists():
            shutil.rmtree(workspace_path)
def test_ast_finding_creation():
    """Test AST finding creation."""
    print("Testing AST finding creation...")

    # Create test workspace
    test_scan_id = "TEST-FINDING-20240101-123456-abcdef12"
    workspace_path = Path(__file__).resolve().parents[1] / "runtime" / "workspaces" / test_scan_id
    workspace_path.mkdir(parents=True, exist_ok=True)

    # Initialize ASTAnalyzer
    ast_analyzer = ASTAnalyzer(test_scan_id, str(workspace_path))

    # Test finding creation
    finding = ast_analyzer._create_ast_finding(
        "test.py",
        "test_category",
        "high",
        "Test finding title",
        ["Evidence 1", "Evidence 2"],
        "ast_analysis"
    )

    # Validate finding structure
    assert "finding_id" in finding
    assert finding["source"] == "ast_analysis"
    assert finding["title"] == "Test finding title"
    assert finding["severity"] == "high"
    assert finding["category"] == "test_category"
    assert len(finding["evidence"]) == 2
    assert "timestamp" in finding

    print("✓ AST finding creation tests passed")
def run_all_tests():
    """Run all AST analyzer tests."""
    print("=" * 70)
    print("SentinelAI AST Analyzer Tests")
    print("=" * 70)

    try:
        test_ast_analyzer_initialization()
        test_python_ast_analysis()
        test_javascript_ast_analysis()
        test_html_ast_analysis()
        test_ast_helper_methods()
        test_ast_finding_creation()

        print("\n" + "=" * 70)
        print("All AST analyzer tests passed! ✓")
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
