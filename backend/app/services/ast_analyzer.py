"""
AST/Structural Analysis Engine for SentinelAI.

This module implements the AST/structural analysis phase (Phase 4):
- AST parsing for source code analysis
- Structural analysis for security patterns
- Route detection and analysis
- Dependency and import analysis
- Security-sensitive data flow detection
- Normalized finding schema generation

The AST analysis is separate from Semgrep and focuses on code structure
rather than pattern matching.
"""

import ast
import json
import os
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

from app.core.logger import get_logger

logger = get_logger(__name__)
class ASTAnalyzer:
    """Implements AST-based structural analysis for security vulnerabilities."""

    def __init__(self, scan_id: str, workspace_path: str):
        self.scan_id = scan_id
        self.workspace_path = Path(workspace_path)
        self.repository_path = self._get_repository_path()
        self.findings = []
        self.route_analysis = {}
        self.dependency_analysis = {}
        self.function_analysis = {}
        self.class_analysis = {}

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

    def run_ast_analysis(self) -> Dict[str, Any]:
        """Run complete AST-based structural analysis."""
        logger.info(f"Starting AST analysis for scan {self.scan_id}")

        # Analyze different file types
        python_files = list(self.repository_path.rglob("*.py"))
        javascript_files = list(self.repository_path.rglob("*.js"))
        typescript_files = list(self.repository_path.rglob("*.ts"))
        html_files = list(self.repository_path.rglob("*.html"))

        # Analyze Python files
        python_findings = []
        if python_files:
            logger.info(f"Analyzing {len(python_files)} Python files")
            python_findings = self._analyze_python_files(python_files)

        # Analyze JavaScript/TypeScript files
        js_findings = []
        if javascript_files or typescript_files:
            logger.info(f"Analyzing JavaScript/TypeScript files: {len(javascript_files)} JS, {len(typescript_files)} TS")
            js_findings = self._analyze_javascript_files(javascript_files, typescript_files)

        # Analyze HTML files
        html_findings = []
        if html_files:
            logger.info(f"Analyzing {len(html_files)} HTML files")
            html_findings = self._analyze_html_files(html_files)

        # Combine all findings
        all_findings = python_findings + js_findings + html_findings

        # Create comprehensive analysis results
        analysis_results = {
            "scan_id": self.scan_id,
            "analysis_type": "AST_Structural_Analysis",
            "timestamp": datetime.now().isoformat(),
            "files_analyzed": {
                "python": len(python_files),
                "javascript": len(javascript_files),
                "typescript": len(typescript_files),
                "html": len(html_files),
                "total": len(python_files) + len(javascript_files) + len(typescript_files) + len(html_files)
            },
            "findings": all_findings,
            "route_analysis": self.route_analysis,
            "dependency_analysis": self.dependency_analysis,
            "function_analysis": self.function_analysis,
            "class_analysis": self.class_analysis,
            "security_patterns": self._extract_security_patterns(all_findings),
            "data_flow_analysis": self._analyze_data_flow_patterns(all_findings),
        }

        # Save results
        self._save_ast_results(analysis_results)

        return analysis_results

    def _analyze_python_files(self, python_files: List[Path]) -> List[Dict[str, Any]]:
        """Analyze Python files for security vulnerabilities."""
        findings = []

        for file_path in python_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    tree = ast.parse(content)

                # Analyze the AST
                file_findings = self._analyze_python_ast(file_path, tree, content)
                findings.extend(file_findings)

            except SyntaxError as e:
                logger.warning(f"Syntax error in {file_path}: {e}")
                # Create finding for syntax error
                findings.append(self._create_ast_finding(
                    str(file_path), "syntax_error", "low", "Python syntax error",
                    [f"Syntax error: {e}"], "ast_analysis"
                ))
            except Exception as e:
                logger.warning(f"Failed to analyze Python file {file_path}: {e}")

        return findings

    def _analyze_python_ast(self, file_path: Path, tree: ast.AST, content: str) -> List[Dict[str, Any]]:
        """Analyze Python AST for security patterns."""
        findings = []
        relative_path = file_path.relative_to(self.repository_path)
        file_name = file_path.name.lower()

        # Check for various security patterns
        if self._contains_import(tree, "pickle"):
            findings.append(self._create_ast_finding(
                str(relative_path), "insecure_deserialization", "high",
                "Insecure pickle deserialization detected",
                ["pickle.load() or pickle.loads() found", "Allows arbitrary code execution"],
                "ast_analysis"
            ))

        if self._contains_import(tree, "eval"):
            findings.append(self._create_ast_finding(
                str(relative_path), "code_injection", "high",
                "eval() function detected - potential code injection",
                ["eval() function found", "Can execute arbitrary code"],
                "ast_analysis"
            ))

        if self._contains_import(tree, "exec"):
            findings.append(self._create_ast_finding(
                str(relative_path), "code_execution", "medium",
                "exec() function detected - potential code execution",
                ["exec() function found", "Can execute arbitrary code"],
                "ast_analysis"
            ))

        if self._contains_function_definition(tree, "__import__"):
            findings.append(self._create_ast_finding(
                str(relative_path), "dynamic_import", "medium",
                "Dynamic import detected",
                ["__import__() found", "Allows dynamic module loading"],
                "ast_analysis"
            ))

        if self._contains_function_definition(tree, "open"):
            findings.append(self._create_ast_finding(
                str(relative_path), "file_operations", "medium",
                "File operation detected - verify security",
                ["open() function found", "File system access"],
                "ast_analysis"
            ))

        if self._contains_function_definition(tree, "socket"):
            findings.append(self._create_ast_finding(
                str(relative_path), "network_operations", "high",
                "Network socket operations detected",
                ["socket operations found", "Potential network security risk"],
                "ast_analysis"
            ))

        # Check for hardcoded secrets
        if self._contains_hardcoded_secrets(content):
            findings.append(self._create_ast_finding(
                str(relative_path), "hardcoded_secrets", "high",
                "Potential hardcoded secrets detected",
                ["Hardcoded passwords/keys found in source code"],
                "ast_analysis"
            ))

        # Check for Flask/Django security issues
        if "flask" in file_name or "django" in file_name:
            if self._contains_insecure_flask_config(tree):
                findings.append(self._create_ast_finding(
                    str(relative_path), "insecure_flask_config", "medium",
                    "Potential insecure Flask configuration",
                    ["Flask app with potential security misconfiguration"],
                    "ast_analysis"
                ))

        # Check for database queries
        if self._contains_sql_queries(tree):
            findings.append(self._create_ast_finding(
                str(relative_path), "sql_queries", "medium",
                "SQL queries detected - verify SQL injection protection",
                ["SQL query found", "Potential SQL injection risk"],
                "ast_analysis"
            ))

        # Analyze functions and classes for security relevance
        functions = self._extract_functions_from_ast(tree)
        classes = self._extract_classes_from_ast(tree)

        for func_name, func_node in functions.items():
            if self._is_suspicious_function(func_name, func_node):
                findings.append(self._create_ast_finding(
                    str(relative_path), "suspicious_function", "low",
                    f"Suspicious function: {func_name}",
                    [f"Function '{func_name}' may have security implications"],
                    "ast_analysis"
                ))

        # Track route analysis for web frameworks
        routes = self._extract_routes_from_python(tree)
        if routes:
            self.route_analysis[str(relative_path)] = routes

        # Track dependencies
        dependencies = self._extract_dependencies_from_python(tree)
        if dependencies:
            self.dependency_analysis[str(relative_path)] = dependencies

        # Track function analysis
        if functions:
            self.function_analysis[str(relative_path)] = functions

        # Track class analysis
        if classes:
            self.class_analysis[str(relative_path)] = classes

        return findings

    def _analyze_javascript_files(self, js_files: List[Path], ts_files: List[Path]) -> List[Dict[str, Any]]:
        """Analyze JavaScript and TypeScript files for security patterns."""
        findings = []

        # For JavaScript files, we would use esprima or babel parser
        # For this implementation, we'll use simple text analysis

        for file_path in js_files + ts_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                relative_path = file_path.relative_to(self.repository_path)

                # Check for JavaScript security patterns
                if self._contains_eval_usage(content):
                    findings.append(self._create_ast_finding(
                        str(relative_path), "javascript_eval", "high",
                        "eval() function detected - potential code injection",
                        ["eval() function found", "Can execute arbitrary code"],
                        "ast_analysis"
                    ))

                if self._contains_function_injection(content):
                    findings.append(self._create_ast_finding(
                        str(relative_path), "javascript_injection", "high",
                        "Function injection detected",
                        ["Function injection detected", "Can execute malicious code"],
                        "ast_analysis"
                    ))

                if self._contains_dom_clobbering(content):
                    findings.append(self._create_ast_finding(
                        str(relative_path), "dom_clobbering", "medium",
                        "DOM clobbering vulnerability detected",
                        ["DOM clobbering pattern detected", "Can manipulate DOM elements"],
                        "ast_analysis"
                    ))

                if self._contains_xss_risk(content):
                    findings.append(self._create_ast_finding(
                        str(relative_path), "xss_risk", "high",
                        "XSS vulnerability risk detected",
                        ["Potential XSS vulnerability", "User input not properly escaped"],
                        "ast_analysis"
                    ))

                # Check for Node.js security issues
                if file_name.endswith('.js') and ('require(' in content and ('child_process' in content or 'fs' in content)):
                    findings.append(self._create_ast_finding(
                        str(relative_path), "nodejs_security_risk", "high",
                        "Node.js security risk detected",
                        ["Node.js file with child_process or fs require", "Potential command execution"],
                        "ast_analysis"
                    ))

            except Exception as e:
                logger.warning(f"Failed to analyze JavaScript file {file_path}: {e}")

        return findings

    def _analyze_html_files(self, html_files: List[Path]) -> List[Dict[str, Any]]:
        """Analyze HTML files for security patterns."n        """
        findings = []

        for file_path in html_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                relative_path = file_path.relative_to(self.repository_path)

                # Check for XSS patterns
                if self._contains_xss_patterns(content):
                    findings.append(self._create_ast_finding(
                        str(relative_path), "xss_patterns", "high",
                        "XSS vulnerability patterns detected",
                        ["Inline JavaScript with user input", "Missing proper escaping"],
                        "html_analysis"
                    ))

                # Check for insecure form handling
                if self._contains_insecure_forms(content):
                    findings.append(self._create_ast_finding(
                        str(relative_path), "insecure_forms", "medium",
                        "Insecure form handling detected",
                        ["Form without CSRF protection", "Missing input validation"],
                        "html_analysis"
                    ))

            except Exception as e:
                logger.warning(f"Failed to analyze HTML file {file_path}: {e}")

        return findings

    # Helper methods for Python AST analysis

    def _contains_import(self, tree: ast.AST, module_name: str) -> bool:
        """Check if AST contains import of specific module."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == module_name:
                        return True
            elif isinstance(node, ast.ImportFrom):
                if node.module == module_name or node.module and node.module.startswith(module_name):
                    return True
        return False

    def _contains_function_definition(self, tree: ast.AST, func_name: str) -> bool:
        """Check if AST contains function definition with specific name."""
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == func_name:
                return True
        return False

    def _contains_hardcoded_secrets(self, content: str) -> bool:
        """Check for hardcoded secrets in content."""
        patterns = [
            r'password\s*=\s*[\'"]',
            r'api_key\s*=\s*[\'"]',
            r'secret\s*=\s*[\'"]',
            r'token\s*=\s*[\'"]',
            r'key\s*=\s*[\'"]',
        ]

        for pattern in patterns:
            import re
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False

    def _contains_insecure_flask_config(self, tree: ast.AST) -> bool:
        """Check for insecure Flask configuration."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == 'app':
                        # Check if this is Flask app creation
                        if isinstance(node.value, ast.Call):
                            func = node.value.func
                            if isinstance(func, ast.Name) and func.id == 'Flask':
                                # Check for insecure configuration
                                for keyword in node.value.keywords:
                                    if keyword.arg == 'secret_key':
                                        return True
        return False

    def _contains_sql_queries(self, tree: ast.AST) -> bool:
        """Check for SQL query patterns in AST."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Check for database query patterns
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ['execute', 'query', 'fetch', 'fetchone', 'fetchall']:
                        return True
        return False

    def _extract_functions_from_ast(self, tree: ast.AST) -> Dict[str, Any]:
        """Extract function definitions from AST."""
        functions = {}

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                func_info = {
                    "name": node.name,
                    "line_number": node.lineno,
                    "args_count": len(node.args.args) + len(node.args.kwonlyargs) + len(node.args.posonlyargs),
                    "docstring": ast.get_docstring(node),
                    "is_async": isinstance(node, ast.AsyncFunctionDef),
                }

                functions[node.name] = func_info

        return functions

    def _extract_classes_from_ast(self, tree: ast.AST) -> Dict[str, Any]:
        """Extract class definitions from AST."""
        classes = {}

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                class_info = {
                    "name": node.name,
                    "line_number": node.lineno,
                    "bases": [base.id if isinstance(base, ast.Name) else str(base) for base in node.bases],
                    "methods": [],
                    "docstring": ast.get_docstring(node),
                }

                # Extract methods from class
                for item in node.body:
                    if isinstance(item, ast.FunctionDef):
                        class_info["methods"].append({
                            "name": item.name,
                            "line_number": item.lineno,
                            "is_async": isinstance(item, ast.AsyncFunctionDef),
                        })

                classes[node.name] = class_info

        return classes

    def _extract_routes_from_python(self, tree: ast.AST) -> List[Dict[str, Any]]:
        """Extract route definitions from Python AST."""
        routes = []

        for node in ast.walk(tree):
            # Check for Flask/Django route decorators
            if isinstance(node, ast.FunctionDef):
                decorators = []
                for decorator in node.decorator_list:
                    if isinstance(decorator, ast.Name):
                        decorators.append(decorator.id)
                    elif isinstance(decorator, ast.Attribute):
                        decorators.append(f"{decorator.value.id}.{decorator.attr}")

                # Check for route patterns
                route_patterns = []
                for decorator in decorators:
                    if 'route' in decorator or 'get' in decorator or 'post' in decorator:
                        route_patterns.append(decorator)

                if route_patterns:
                    routes.append({
                        "function_name": node.name,
                        "line_number": node.lineno,
                        "decorators": decorators,
                        "route_patterns": route_patterns,
                        "parameters": len(node.args.args) if node.args else 0,
                    })

        return routes

    def _extract_dependencies_from_python(self, tree: ast.AST) -> List[str]:
        """Extract external dependencies from Python AST."""
        dependencies = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    dependencies.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    dependencies.append(node.module)

        return list(set(dependencies))

    def _is_suspicious_function(self, func_name: str, func_node: Any) -> bool:
        """Check if a function is suspicious from security perspective."""
        suspicious_patterns = [
            'eval', 'exec', 'compile', 'open', 'input', 'raw_input',
            'socket', 'urllib', 'requests', 'subprocess', 'system',
            'os.system', 'os.popen', 'commands.getoutput'
        ]

        func_name_lower = func_name.lower()
        return any(pattern in func_name_lower for pattern in suspicious_patterns)

    def _extract_security_patterns(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract security patterns from findings."""
        patterns = {
            "authentication_issues": [],
            "authorization_issues": [],
            "input_validation_issues": [],
            "output_encoding_issues": [],
            "session_management_issues": [],
            "cryptography_issues": [],
            "network_security_issues": [],
            "file_system_issues": [],
            "database_security_issues": [],
            "dependency_security_issues": [],
        }

        for finding in findings:
            finding_category = finding.get("category", "")
            finding_severity = finding.get("severity", "")

            # Map finding categories to pattern types
            if finding_severity == "high":
                if "authentication" in finding_category:
                    patterns["authentication_issues"].append(finding)
                elif "authorization" in finding_category:
                    patterns["authorization_issues"].append(finding)
                elif "code_injection" in finding_category:
                    patterns["input_validation_issues"].append(finding)
                elif "network" in finding_category:
                    patterns["network_security_issues"].append(finding)
                elif "file_operations" in finding_category:
                    patterns["file_system_issues"].append(finding)
                elif "database" in finding_category:
                    patterns["database_security_issues"].append(finding)

        return patterns

    def _analyze_data_flow_patterns(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze data flow patterns from findings."""
        data_flow = {
            "user_input_sources": [],
            "data_processing_steps": [],
            "output_targets": [],
            "potential_exposure_points": [],
        }

        # Analyze findings for data flow patterns
        for finding in findings:
            if finding.get("severity") == "high":
                data_flow["potential_exposure_points"].append({
                    "finding": finding,
                    "type": "high_risk_data_flow",
                    "recommendation": "Implement proper validation and sanitization"
                })

        return data_flow

    def _create_ast_finding(self, file_path: str, category: str, severity: str,
                           title: str, evidence: List[str], detection_method: str) -> Dict[str, Any]:
        """Create an AST finding with normalized schema."""
        finding_id = f"AST_{self.scan_id}_{len(self.findings) + 1}"

        return {
            "finding_id": finding_id,
            "source": "ast_analysis",
            "rule_id": f"AST_{category.upper()}",
            "file_path": file_path,
            "line_number": 0,  # AST doesn't provide line numbers for structural issues
            "title": title,
            "severity": severity,
            "severity_summary": self._get_severity_summary(severity),
            "evidence": evidence,
            "cve": {},
            "status": "UNVERIFIED",
            "detection_method": detection_method,
            "analysis_type": "ast",
            "timestamp": datetime.now().isoformat(),
        }

    def _get_severity_summary(self, severity: str) -> str:
        """Get human-readable severity summary."""
        severity_map = {
            "critical": "Critical security vulnerability",
            "high": "High severity structural issue",
            "medium": "Medium severity structural issue",
            "low": "Low severity structural issue",
        }
        return severity_map.get(severity.lower(), severity)

    # JavaScript/TypeScript helper methods

    def _contains_eval_usage(self, content: str) -> bool:
        """Check for eval() usage in JavaScript content."""
        return 'eval(' in content

    def _contains_function_injection(self, content: str) -> bool:
        """Check for function injection patterns."""
        return 'Function(' in content and 'eval(' in content

    def _contains_dom_clobbering(self, content: str) -> bool:
        """Check for DOM clobbering patterns."""
        return 'document.' in content and 'window.' in content

    def _contains_xss_risk(self, content: str) -> bool:
        """Check for XSS risk patterns."""
        return 'innerHTML' in content or 'outerHTML' in content or 'eval(' in content

    # HTML helper methods

    def _contains_xss_patterns(self, content: str) -> bool:
        """Check for XSS patterns in HTML."""
        return '<script>' in content.lower() and 'onerror=' in content.lower()

    def _contains_insecure_forms(self, content: str) -> bool:
        """Check for insecure form patterns."""
        return '<form' in content.lower() and 'method=' in content.lower()

    # File analysis methods

    def _save_ast_results(self, analysis_results: Dict[str, Any]) -> None:
        """Save AST analysis results to stage2_ast.json."""
        try:
            results_file = self.workspace_path / "stage2_ast.json"

            with open(results_file, 'w', encoding='utf-8') as f:
                json.dump(analysis_results, f, indent=2, ensure_ascii=False)

            logger.info(f"Saved AST analysis results to {results_file}")

        except Exception as e:
            logger.error(f"Failed to save AST results: {e}")
            raise

    def get_ast_findings(self) -> Dict[str, Any]:
        """Get AST findings from analysis."""
        findings_path = self.workspace_path / "stage2_ast.json"

        if not findings_path.exists():
            return {
                "scan_id": self.scan_id,
                "findings": [],
                "message": "No AST findings available. Run AST analysis first.",
                "status": "not_run"
            }

        try:
            with open(findings_path, 'r', encoding='utf-8') as f:
                findings = json.load(f)

            return {
                "scan_id": self.scan_id,
                "findings": findings.get("findings", []),
                "findings_count": len(findings.get("findings", [])),
                "status": "completed",
                "generated_at": findings.get("timestamp"),
            }

        except Exception as e:
            logger.error(f"Failed to load AST findings: {e}")
            return {
                "scan_id": self.scan_id,
                "findings": [],
                "error": str(e),
                "status": "error"
            }