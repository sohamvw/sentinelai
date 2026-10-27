"""
Deterministic Analysis Engine for SentinelAI.

This module implements the deterministic analysis phase (Phase 3):
- Framework/language specific security checklists
- Tool selection and execution
- Structured evidence generation
- Normalized finding schema

The deterministic engine follows predefined framework/language/security checklists
and routes tool execution accordingly, ensuring reproducible analysis results.
"""

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

from app.core.logger import get_logger
from app.schemas.scan_request import ScanRequest

logger = get_logger(__name__)
class DeterministicEngine:
    """Implements deterministic security analysis for repositories."""

    def __init__(self, scan_id: str, scan_request: ScanRequest, workspace_path: str):
        self.scan_id = scan_id
        self.scan_request = scan_request
        self.workspace_path = Path(workspace_path)
        self.repository_path = self._get_repository_path()
        self.analysis_plan = self._load_analysis_plan()
        self.findings = []
        self.framework_checklists = self._load_framework_checklists()
        self.language_checklists = self._load_language_checklists()

    def _get_repository_path(self) -> Path:
        """Get the repository path from workspace."""
        # Look for extracted repository in workspace
        for item in self.workspace_path.iterdir():
            if item.is_dir() and item.name not in ['logs', 'runtime']:
                return item

        # If not found, try common repository names
        possible_repos = ['repository', 'repo', 'extracted_repository', 'cloned_repo']
        for repo_name in possible_repos:
            repo_path = self.workspace_path / repo_name
            if repo_path.exists():
                return repo_path

        raise Exception(f"Repository not found in workspace {self.scan_id}")

    def _load_analysis_plan(self) -> Dict[str, Any]:
        """Load analysis plan from workspace."""
        plan_path = self.workspace_path / "analysis_plan.json"
        if plan_path.exists():
            try:
                with open(plan_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load analysis plan: {e}")

        # Return empty analysis plan if not found
        return {}

    def _load_framework_checklists(self) -> Dict[str, Any]:
        """Load framework-specific security checklists."""
        return {
            "fastapi": {
                "name": "FastAPI Security Checklist",
                "version": "1.0",
                "checks": [
                    {
                        "id": "fastapi_auth_001",
                        "name": "Authentication Configuration",
                        "description": "Verify FastAPI authentication setup",
                        "category": "authentication",
                        "severity": "high",
                        "files": ["*.py"],
                        "detection_method": "manual",
                        "framework_specific": True,
                    },
                    {
                        "id": "fastapi_auth_002",
                        "name": "OAuth2 Scheme",
                        "description": "Verify OAuth2 scheme implementation",
                        "category": "authentication",
                        "severity": "high",
                        "files": ["*.py"],
                        "detection_method": "ast",
                        "framework_specific": True,
                    },
                    {
                        "id": "fastapi_auth_003",
                        "name": "JWT Token Validation",
                        "description": "Verify JWT token validation and security",
                        "category": "authentication",
                        "severity": "high",
                        "files": ["*.py"],
                        "detection_method": "ast",
                        "framework_specific": True,
                    },
                    {
                        "id": "fastapi_auth_004",
                        "name": "Permission Dependency",
                        "description": "Verify permission dependency injection",
                        "category": "authorization",
                        "severity": "medium",
                        "files": ["*.py"],
                        "detection_method": "ast",
                        "framework_specific": True,
                    },
                    {
                        "id": "fastapi_req_001",
                        "name": "Request Validation",
                        "description": "Verify Pydantic request validation",
                        "category": "input_validation",
                        "severity": "medium",
                        "files": ["*.py"],
                        "detection_method": "ast",
                        "framework_specific": True,
                    },
                    {
                        "id": "fastapi_file_001",
                        "name": "File Upload Security",
                        "description": "Verify secure file upload implementation",
                        "category": "file_operations",
                        "severity": "high",
                        "files": ["*.py"],
                        "detection_method": "manual",
                        "framework_specific": True,
                    },
                    {
                        "id": "fastapi_db_001",
                        "name": "Database Security",
                        "description": "Verify secure database connection and queries",
                        "category": "database",
                        "severity": "high",
                        "files": ["*.py"],
                        "detection_method": "manual",
                        "framework_specific": True,
                    },
                    {
                        "id": "fastapi_config_001",
                        "name": "Security Configuration",
                        "description": "Verify security-related configuration",
                        "category": "configuration",
                        "severity": "medium",
                        "files": ["*.py", "*.ini", "*.env"],
                        "detection_method": "manual",
                        "framework_specific": True,
                    },
                    {
                        "id": "fastapi_dep_001",
                        "name": "Dependency Security",
                        "description": "Verify third-party dependency security",
                        "category": "dependencies",
                        "severity": "medium",
                        "files": ["*.py"],
                        "detection_method": "manual",
                        "framework_specific": True,
                    },
                ]
            },
            "django": {
                "name": "Django Security Checklist",
                "version": "1.0",
                "checks": [
                    {
                        "id": "django_auth_001",
                        "name": "Authentication System",
                        "description": "Verify Django authentication setup",
                        "category": "authentication",
                        "severity": "high",
                        "files": ["*.py"],
                        "detection_method": "manual",
                        "framework_specific": True,
                    },
                    {
                        "id": "django_auth_002",
                        "name": "Authorization Middleware",
                        "description": "Verify Django authorization middleware",
                        "category": "authorization",
                        "severity": "high",
                        "files": ["*.py"],
                        "detection_method": "ast",
                        "framework_specific": True,
                    },
                    {
                        "id": "django_db_001",
                        "name": "ORM Security",
                        "description": "Verify Django ORM security",
                        "category": "database",
                        "severity": "medium",
                        "files": ["*.py"],
                        "detection_method": "manual",
                        "framework_specific": True,
                    },
                    {
                        "id": "django_config_001",
                        "name": "Security Settings",
                        "description": "Verify Django security settings",
                        "category": "configuration",
                        "severity": "medium",
                        "files": ["settings.py", "*.py"],
                        "detection_method": "manual",
                        "framework_specific": True,
                    },
                ]
            },
            "express": {
                "name": "Express.js Security Checklist",
                "version": "1.0",
                "checks": [
                    {
                        "id": "express_auth_001",
                        "name": "Authentication Middleware",
                        "description": "Verify Express authentication middleware",
                        "category": "authentication",
                        "severity": "high",
                        "files": ["*.js", "*.ts"],
                        "detection_method": "manual",
                        "framework_specific": True,
                    },
                    {
                        "id": "express_auth_002",
                        "name": "Session Management",
                        "description": "Verify Express session security",
                        "category": "session",
                        "severity": "medium",
                        "files": ["*.js", "*.ts"],
                        "detection_method": "manual",
                        "framework_specific": True,
                    },
                    {
                        "id": "express_route_001",
                        "name": "Route Security",
                        "description": "Verify Express route security",
                        "category": "routing",
                        "severity": "medium",
                        "files": ["*.js", "*.ts"],
                        "detection_method": "ast",
                        "framework_specific": True,
                    },
                ]
            },
            "spring": {
                "name": "Spring Boot Security Checklist",
                "version": "1.0",
                "checks": [
                    {
                        "id": "spring_auth_001",
                        "name": "Spring Security Configuration",
                        "description": "Verify Spring Security configuration",
                        "category": "authentication",
                        "severity": "high",
                        "files": ["*.java", "*.xml"],
                        "detection_method": "manual",
                        "framework_specific": True,
                    },
                    {
                        "id": "spring_auth_002",
                        "name": "JWT Authentication",
                        "description": "Verify Spring JWT authentication",
                        "category": "authentication",
                        "severity": "high",
                        "files": ["*.java", "*.yml", "*.yaml"],
                        "detection_method": "manual",
                        "framework_specific": True,
                    },
                ]
            },
        }

    def _load_language_checklists(self) -> Dict[str, Any]:
        """Load language-specific security checklists."""
        return {
            "python": {
                "name": "Python Security Checklist",
                "version": "1.0",
                "checks": [
                    {
                        "id": "python_bandit_001",
                        "name": "Bandit Security Scan",
                        "description": "Run Bandit security scan for Python",
                        "category": "static_analysis",
                        "severity": "high",
                        "files": ["*.py"],
                        "detection_method": "tool",
                        "language_specific": True,
                        "tool": "bandit",
                    },
                    {
                        "id": "python_semgrep_001",
                        "name": "Semgrep Security Scan",
                        "description": "Run Semgrep security scan for Python",
                        "category": "static_analysis",
                        "severity": "high",
                        "files": ["*.py"],
                        "detection_method": "tool",
                        "language_specific": True,
                        "tool": "semgrep",
                    },
                    {
                        "id": "python_pickle_001",
                        "name": "Pickle Deserialization",
                        "description": "Check for insecure pickle deserialization",
                        "category": "serialization",
                        "severity": "high",
                        "files": ["*.py"],
                        "detection_method": "ast",
                        "language_specific": True,
                    },
                    {
                        "id": "python_eval_001",
                        "name": "eval() Usage",
                        "description": "Check for dangerous eval() usage",
                        "category": "code_execution",
                        "severity": "medium",
                        "files": ["*.py"],
                        "detection_method": "ast",
                        "language_specific": True,
                    },
                ]
            },
            "javascript": {
                "name": "JavaScript Security Checklist",
                "version": "1.0",
                "checks": [
                    {
                        "id": "javascript_semgrep_001",
                        "name": "Semgrep Security Scan",
                        "description": "Run Semgrep security scan for JavaScript",
                        "category": "static_analysis",
                        "severity": "high",
                        "files": ["*.js", "*.ts", "*.jsx", "*.tsx"],
                        "detection_method": "tool",
                        "language_specific": True,
                        "tool": "semgrep",
                    },
                    {
                        "id": "javascript_dom_001",
                        "name": "DOM Clobbering",
                        "description": "Check for DOM clobbering vulnerabilities",
                        "category": "client_side",
                        "severity": "medium",
                        "files": ["*.js", "*.ts", "*.html"],
                        "detection_method": "manual",
                        "language_specific": True,
                    },
                ]
            },
            "java": {
                "name": "Java Security Checklist",
                "version": "1.0",
                "checks": [
                    {
                        "id": "java_spotbugs_001",
                        "name": "SpotBugs Security Scan",
                        "description": "Run SpotBugs security scan for Java",
                        "category": "static_analysis",
                        "severity": "high",
                        "files": ["*.java"],
                        "detection_method": "tool",
                        "language_specific": True,
                        "tool": "spotbugs",
                    },
                    {
                        "id": "java_semgrep_001",
                        "name": "Semgrep Security Scan",
                        "description": "Run Semgrep security scan for Java",
                        "category": "static_analysis",
                        "severity": "high",
                        "files": ["*.java"],
                        "detection_method": "tool",
                        "language_specific": True,
                        "tool": "semgrep",
                    },
                ]
            },
        }

    def run_deterministic_analysis(self) -> Dict[str, Any]:
        """Run deterministic analysis using framework and language checklists."""
        logger.info(f"Starting deterministic analysis for scan {self.scan_id}")

        # Get analysis plan
        stack = self.analysis_plan.get("stack", [])
        languages = self.analysis_plan.get("languages", {})

        # Select applicable checklists
        applicable_frameworks = self._select_frameworks(stack)
        applicable_languages = self._select_languages(languages.keys())

        # Run checks for each applicable framework and language
        all_findings = []
        framework_findings = []
        language_findings = []

        for framework in applicable_frameworks:
            framework_findings.extend(self._run_framework_checks(framework))

        for language in applicable_languages:
            language_findings.extend(self._run_language_checks(language))

        all_findings = framework_findings + language_findings

        # Convert findings to normalized schema
        normalized_findings = self._convert_to_normalized_schema(all_findings)

        # Save findings
        self._save_findings(normalized_findings)

        return {
            "scan_id": self.scan_id,
            "findings_count": len(normalized_findings),
            "framework_findings": len(framework_findings),
            "language_findings": len(language_findings),
            "status": "completed",
            "findings_file": str(self.workspace_path / "stage2_deterministic.json"),
        }

    def _select_frameworks(self, stack: List[str]) -> List[str]:
        """Select applicable frameworks from analysis plan."""
        frameworks = []

        for framework in stack:
            # Map stack entries to framework names
            framework_mapping = {
                "fastapi": "fastapi",
                "django": "django",
                "flask": "fastapi",  # Treat Flask similarly to FastAPI
                "express": "express",
                "spring": "spring",
                "node": "express",
                "nodejs": "express",
                "angular": "express",  # Backend perspective
                "react": "express",    # Backend perspective
                "vue": "express",      # Backend perspective
            }

            mapped_framework = framework_mapping.get(framework.lower(), framework.lower())
            if mapped_framework in self.framework_checklists:
                frameworks.append(mapped_framework)

        return frameworks

    def _select_languages(self, languages: List[str]) -> List[str]:
        """Select applicable languages from analysis plan."""
        applicable_languages = []

        for language in languages:
            # Normalize language names
            normalized_language = language.lower()
            if normalized_language in ['python', 'py']:
                applicable_languages.append('python')
            elif normalized_language in ['javascript', 'js']:
                applicable_languages.append('javascript')
            elif normalized_language in ['typescript', 'ts']:
                applicable_languages.append('typescript')
            elif normalized_language in ['java', 'javaee', 'springboot']:
                applicable_languages.append('java')
            elif normalized_language in ['cpp', 'c++', 'c++11', 'c++14']:
                applicable_languages.append('cpp')
            elif normalized_language in ['csharp', 'dotnet', '.net']:
                applicable_languages.append('csharp')
            elif normalized_language in ['php']:
                applicable_languages.append('php')
            elif normalized_language in ['ruby']:
                applicable_languages.append('ruby')
            elif normalized_language in ['go']:
                applicable_languages.append('go')
            elif normalized_language in ['rust']:
                applicable_languages.append('rust')
            elif normalized_language in ['swift']:
                applicable_languages.append('swift')
            elif normalized_language in ['kotlin']:
                applicable_languages.append('kotlin')
            elif normalized_language in ['scala']:
                applicable_languages.append('scala')
            elif normalized_language in ['r']:
                applicable_languages.append('r')
            elif normalized_language in ['sql']:
                applicable_languages.append('sql')

        return applicable_languages

    def _run_framework_checks(self, framework: str) -> List[Dict[str, Any]]:
        """Run framework-specific security checks."""
        logger.info(f"Running framework checks for {framework}")

        if framework not in self.framework_checklists:
            return []

        framework_config = self.framework_checklists[framework]
        findings = []

        for check in framework_config["checks"]:
            try:
                finding = self._run_single_check(check)
                if finding:
                    findings.append(finding)
            except Exception as e:
                logger.warning(f"Failed to run check {check['id']}: {e}")

        return findings

    def _run_language_checks(self, language: str) -> List[Dict[str, Any]]:
        """Run language-specific security checks."""
        logger.info(f"Running language checks for {language}")

        if language not in self.language_checklists:
            return []

        language_config = self.language_checklists[language]
        findings = []

        for check in language_config["checks"]:
            try:
                finding = self._run_single_check(check)
                if finding:
                    findings.append(finding)
            except Exception as e:
                logger.warning(f"Failed to run check {check['id']}: {e}")

        return findings

    def _run_single_check(self, check: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Run a single security check and return findings if any are found."""
        check_id = check.get("id", "unknown")
        check_name = check.get("name", "Unknown Check")
        category = check.get("category", "unknown")
        severity = check.get("severity", "medium")
        detection_method = check.get("detection_method", "manual")
        files_pattern = check.get("files", ["*.py"])
        framework_specific = check.get("framework_specific", False)
        language_specific = check.get("language_specific", False)
        tool = check.get("tool", None)

        # Find files matching the pattern
        matching_files = self._find_files_by_pattern(files_pattern)

        if not matching_files:
            logger.debug(f"No files found for check {check_id}")
            return None

        # Run the check based on detection method
        if detection_method == "tool" and tool:
            return self._run_tool_based_check(check, matching_files)
        elif detection_method == "ast":
            return self._run_ast_based_check(check, matching_files)
        elif detection_method == "manual":
            return self._run_manual_check(check, matching_files)
        else:
            logger.warning(f"Unknown detection method: {detection_method} for check {check_id}")
            return None

    def _find_files_by_pattern(self, patterns: List[str]) -> List[Path]:
        """Find files matching patterns in repository."""
        matching_files = []

        for pattern in patterns:
            if pattern.startswith("*.py"):
                matching_files.extend(self.repository_path.rglob("*.py"))
            elif pattern.startswith("*.js"):
                matching_files.extend(self.repository_path.rglob("*.js"))
                matching_files.extend(self.repository_path.rglob("*.jsx"))
                matching_files.extend(self.repository_path.rglob("*.tsx"))
            elif pattern.startswith("*.ts"):
                matching_files.extend(self.repository_path.rglob("*.ts"))
            elif pattern.startswith("*.java"):
                matching_files.extend(self.repository_path.rglob("*.java"))
            elif pattern.startswith("*.cpp"):
                matching_files.extend(self.repository_path.rglob("*.cpp"))
                matching_files.extend(self.repository_path.rglob("*.cc"))
                matching_files.extend(self.repository_path.rglob("*.cxx"))
            elif pattern.startswith("*.c"):
                matching_files.extend(self.repository_path.rglob("*.c"))
            elif pattern.startswith("*.h"):
                matching_files.extend(self.repository_path.rglob("*.h"))
            elif pattern.startswith("*.html"):
                matching_files.extend(self.repository_path.rglob("*.html"))
            elif pattern.startswith("*.json"):
                matching_files.extend(self.repository_path.rglob("*.json"))
            elif pattern.startswith("*.yml") or pattern.startswith("*.yaml"):
                matching_files.extend(self.repository_path.rglob("*.yml"))
                matching_files.extend(self.repository_path.rglob("*.yaml"))
            elif pattern == "Dockerfile":
                matching_files.extend(self.repository_path.rglob("Dockerfile"))

        # Remove duplicates and return absolute paths
        return list(set(matching_files))

    def _run_tool_based_check(self, check: Dict[str, Any], files: List[Path]) -> Optional[Dict[str, Any]]:
        """Run a tool-based security check."""
        tool = check.get("tool")
        check_id = check.get("id", "unknown")

        if not tool:
            return None

        # Create temporary script for tool execution
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as script:
            script.write(f"#!/bin/bash\n")
            script.write(f"echo 'Running {tool} check...\n')")
            script.write(f"for file in {' '.join(str(f) for f in files)}; do\n")
            script.write(f"    echo 'Processing: $file'\n")
            script.write(f"    # Tool-specific execution would go here\n")
            script.write(f"done\n")
            script_path = script.name

        try:
            # Make script executable
            os.chmod(script_path, 0o755)

            # Execute the script (placeholder for actual tool execution)
            logger.info(f"Would execute {tool} on {len(files)} files for check {check_id}")

            # This legacy engine has no implementation for external tool
            # execution. It must never manufacture a finding.
            return None

        except Exception as e:
            logger.warning(f"Tool-based check failed for {check_id}: {e}")
        finally:
            # Clean up temporary script
            try:
                os.unlink(script_path)
            except:
                pass

        return None

    def _run_ast_based_check(self, check: Dict[str, Any], files: List[Path]) -> Optional[Dict[str, Any]]:
        """Run an AST-based security check."""
        check_id = check.get("id", "unknown")
        check_name = check.get("name", "Unknown Check")
        category = check.get("category", "unknown")
        severity = check.get("severity", "medium")

        # Analyze Python files with basic AST parsing.
        if check_id == "python_pickle_001":
            for file_path in files:
                if file_path.suffix == '.py':
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()

                        # Simple detection of pickle usage
                        if 'pickle' in content.lower() and ('load(' in content or 'loads(' in content):
                            return self._create_finding(
                                check_id, check_name, category, severity,
                                str(file_path), "python", "ast_based",
                                evidence=["pickle.load() detected", "Insecure deserialization risk"]
                            )
                    except Exception as e:
                        logger.warning(f"Failed to analyze file {file_path} for {check_id}: {e}")

        elif check_id == "python_eval_001":
            for file_path in files:
                if file_path.suffix == '.py':
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()

                        # Simple detection of eval usage
                        if 'eval(' in content:
                            return self._create_finding(
                                check_id, check_name, category, severity,
                                str(file_path), "python", "ast_based",
                                evidence=["eval() function detected", "Code injection risk"]
                            )
                    except Exception as e:
                        logger.warning(f"Failed to analyze file {file_path} for {check_id}: {e}")

        return None

    def _run_manual_check(self, check: Dict[str, Any], files: List[Path]) -> Optional[Dict[str, Any]]:
        """Run a manual security check."""
        check_id = check.get("id", "unknown")
        check_name = check.get("name", "Unknown Check")
        category = check.get("category", "unknown")
        severity = check.get("severity", "medium")

        # Perform basic manual checks.
        for file_path in files:
            try:
                if file_path.suffix == '.py':
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()

                    # Check for hardcoded secrets
                    if 'password' in content.lower() and ('=' in content and "'" in content):
                        return self._create_finding(
                            check_id, check_name, category, severity,
                            str(file_path), "python", "manual",
                            evidence=["Potential hardcoded password found", "Security risk"]
                        )

                    # Check for insecure imports
                    if 'import socket' in content and 'socket.create_connection' in content:
                        return self._create_finding(
                            check_id, check_name, category, severity,
                            str(file_path), "python", "manual",
                            evidence=["Raw socket connection detected", "Network security risk"]
                        )

            except Exception as e:
                logger.warning(f"Failed to manually analyze file {file_path} for {check_id}: {e}")

        return None

    def _create_finding(self, check_id: str, title: str, category: str,
                           severity: str, file_path: str, language: str,
                           detection_method: str, evidence: List[str] = None) -> Dict[str, Any]:
        """Create a finding backed by an observed repository signal."""
        if evidence is None:
            evidence = ["Potential security issue detected"]

        finding_id = f"{self.scan_id}_{check_id.replace('_', '_')}"

        return {
            "finding_id": finding_id,
            "source": "deterministic_engine",
            "rule_id": check_id,
            "file_path": file_path,
            "line_number": 0,  # Would be populated by actual analysis
            "title": title,
            "severity": severity,
            "severity_summary": self._get_severity_summary(severity),
            "evidence": evidence,
            "cve": {},
            "status": "UNVERIFIED",
            "check_category": category,
            "detection_method": detection_method,
            "language": language,
            "framework": self._get_framework_from_file(file_path),
            "timestamp": datetime.now().isoformat(),
        }

    def _get_severity_summary(self, severity: str) -> str:
        """Get human-readable severity summary."""
        severity_map = {
            "critical": "Critical security vulnerability",
            "high": "High severity security issue",
            "medium": "Medium severity security issue",
            "low": "Low severity security issue",
            "info": "Informational security finding",
        }
        return severity_map.get(severity.lower(), severity)

    def _get_framework_from_file(self, file_path: str) -> str:
        """Extract framework from file path for analysis."""
        path_lower = file_path.lower()

        if "django" in path_lower:
            return "django"
        elif "flask" in path_lower:
            return "flask"
        elif "fastapi" in path_lower:
            return "fastapi"
        elif "express" in path_lower:
            return "express"
        elif "spring" in path_lower:
            return "spring"
        elif "node" in path_lower:
            return "express"
        else:
            return "generic"

    def _convert_to_normalized_schema(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Convert findings to normalized schema for stage2_deterministic.json."""
        normalized = []

        for finding in findings:
            normalized_finding = {
                "finding_id": finding.get("finding_id", f"{self.scan_id}_{len(normalized)}_finding"),
                "source": finding.get("source", "unknown"),
                "rule_id": finding.get("rule_id", ""),
                "file_path": finding.get("file_path", ""),
                "line_number": finding.get("line_number", 0),
                "title": finding.get("title", ""),
                "severity": finding.get("severity", "medium"),
                "severity_summary": finding.get("severity_summary", ""),
                "evidence": finding.get("evidence", []),
                "cve": finding.get("cve", {}),
                "status": finding.get("status", "UNVERIFIED"),
                "check_category": finding.get("check_category", "unknown"),
                "detection_method": finding.get("detection_method", "unknown"),
                "language": finding.get("language", "unknown"),
                "framework": finding.get("framework", "unknown"),
                "timestamp": finding.get("timestamp", datetime.now().isoformat()),
            }

            normalized.append(normalized_finding)

        return normalized

    def _save_findings(self, findings: List[Dict[str, Any]]) -> None:
        """Save findings to stage2_deterministic.json."""
        try:
            findings_file = self.workspace_path / "stage2_deterministic.json"

            with open(findings_file, 'w', encoding='utf-8') as f:
                json.dump(findings, f, indent=2, ensure_ascii=False)

            logger.info(f"Saved {len(findings)} findings to {findings_file}")

        except Exception as e:
            logger.error(f"Failed to save findings: {e}")
            raise

    def get_deterministic_findings(self) -> Dict[str, Any]:
        """Get deterministic findings from analysis."""
        findings_path = self.workspace_path / "stage2_deterministic.json"

        if not findings_path.exists():
            return {
                "scan_id": self.scan_id,
                "findings": [],
                "message": "No deterministic findings available. Run deterministic analysis first.",
                "status": "not_run"
            }

        try:
            with open(findings_path, 'r', encoding='utf-8') as f:
                findings = json.load(f)

            return {
                "scan_id": self.scan_id,
                "findings": findings,
                "findings_count": len(findings),
                "status": "completed",
                "generated_at": datetime.now().isoformat(),
            }

        except Exception as e:
            logger.error(f"Failed to load deterministic findings: {e}")
            return {
                "scan_id": self.scan_id,
                "findings": [],
                "error": str(e),
                "status": "error"
            }
