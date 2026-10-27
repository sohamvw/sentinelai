"""
Analysis planner for SentinelAI repository discovery.
This module generates analysis plans from repository tree metadata.
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, List, Set
from app.core.logger import get_logger
from app.schemas.scan_request import ScanRequest

logger = get_logger(__name__)
class AnalysisPlanner:
    """Generates analysis plans from repository tree metadata."""

    def __init__(self, scan_request: ScanRequest, tree_data: Dict[str, Any]):
        self.scan_request = scan_request
        self.tree_data = tree_data
        self.analysis_plan = None
        self.language_stats = self._calculate_language_statistics()
        self.framework_candidates = self._identify_framework_candidates()
        self.security_areas = self._identify_security_areas()
        self.dependencies = self._identify_dependencies()
        self.compliance_needs = self._identify_compliance_needs()

    def generate_analysis_plan(self) -> Dict[str, Any]:
        """Generate complete analysis plan."""
        logger.info("Generating analysis plan from repository tree")

        analysis_plan = {
            "scan_id": self._generate_scan_id(),
            "timestamp": self._get_timestamp(),
            "repository_info": self._extract_repository_info(),
            "stack": self._determine_tech_stack(),
            "languages": self._extract_languages(),
            "frameworks": self._extract_frameworks(),
            "confidence": self._calculate_overall_confidence(),
            "important_files": self._identify_important_files(),
            "security_sensitive_areas": self._get_security_sensitive_areas(),
            "dependency_queries": self._generate_dependency_queries(),
            "vulnerability_knowledge_queries": self._generate_vulnerability_queries(),
            "compliance_queries": self._generate_compliance_queries(),
            "required_tools": self._determine_required_tools(),
            "required_deterministic_checks": self._generate_deterministic_checks(),
            "required_ast_checks": self._generate_ast_checks(),
            "decision_reasons": self._provide_decision_reasons(),
            "estimated_scope": self._estimate_analysis_scope(),
            "prioritization": self._determine_prioritization(),
        }

        self.analysis_plan = analysis_plan
        return analysis_plan

    def _calculate_language_statistics(self) -> Dict[str, Any]:
        """Calculate language statistics from tree data."""
        languages = {}
        total_files = 0

        for file_info in self.tree_data.get("files", []):
            ext = file_info.get("ext", "")
            if ext:
                language = self._extension_to_language(ext)
                if language not in languages:
                    languages[language] = {
                        "file_count": 0,
                        "total_size": 0,
                        "extensions": set(),
                        "importance": 0,
                    }

                lang_info = languages[language]
                lang_info["file_count"] += 1
                lang_info["extensions"].add(ext)

            total_files += 1

        # Convert sets to lists and calculate metrics
        for lang_info in languages.values():
            lang_info["extensions"] = list(lang_info["extensions"])
            lang_info["importance"] = self._calculate_language_importance(lang_info)
            if lang_info["file_count"] > 0:
                lang_info["percentage"] = (lang_info["file_count"] / total_files) * 100

        return languages

    def _extension_to_language(self, ext: str) -> str:
        """Convert file extension to programming language."""
        extension_map = {
            # Python
            'py': 'python',
            'pyw': 'python',
            # JavaScript
            'js': 'javascript',
            'jsx': 'javascript-react',
            'mjs': 'javascript-esm',
            'cjs': 'javascript-commonjs',
            # TypeScript
            'ts': 'typescript',
            'tsx': 'typescript-react',
            'mts': 'typescript-esm',
            'cts': 'typescript-commonjs',
            # Java
            'java': 'java',
            'jsp': 'java-server-pages',
            # C/C++
            'cpp': 'cpp',
            'cc': 'cpp',
            'cxx': 'cpp',
            'c': 'c',
            'h': 'c-header',
            'hpp': 'cpp-header',
            # C#
            'cs': 'csharp',
            # PHP
            'php': 'php',
            # Ruby
            'rb': 'ruby',
            # Go
            'go': 'go',
            # Rust
            'rs': 'rust',
            # Swift
            'swift': 'swift',
            # Kotlin
            'kt': 'kotlin',
            'kts': 'kotlin-script',
            # Scala
            'scala': 'scala',
            # R
            'r': 'r',
            'R': 'r',
            # SQL
            'sql': 'sql',
            # HTML
            'html': 'html',
            'htm': 'html',
            # CSS
            'css': 'css',
            'scss': 'scss',
            'sass': 'sass',
            'less': 'less',
            # Shell
            'sh': 'bash',
            'bash': 'bash',
            'zsh': 'zsh',
            'fish': 'fish',
            'ps1': 'powershell',
            # Configuration
            'json': 'config',
            'yaml': 'config',
            'yml': 'config',
            'toml': 'config',
            'ini': 'config',
            'cfg': 'config',
            'conf': 'config',
            'xml': 'config',
            # Documentation
            'md': 'markdown',
            'rst': 'restructuredtext',
            'txt': 'text',
        }

        return extension_map.get(ext.lower(), 'unknown')

    def _calculate_language_importance(self, lang_info: Dict[str, Any]) -> float:
        """Calculate importance score for a language."""
        importance = 0.0

        # File count importance
        importance += min(lang_info["file_count"] / 10.0, 3.0)

        # Extension diversity importance
        ext_count = len(lang_info["extensions"])
        importance += min(ext_count * 0.5, 2.0)

        return min(importance, 5.0)

    def _identify_framework_candidates(self) -> List[Dict[str, Any]]:
        """Identify potential frameworks from repository structure."""
        frameworks = []

        # Check for dependency manifests
        for file_info in self.tree_data.get("files", []):
            path = file_info.get("path", "")
            name = file_info.get("name", "")

            # Python frameworks
            if name == 'requirements.txt':
                frameworks.append({
                    "framework": "python_pip",
                    "confidence": 0.9,
                    "evidence": ["requirements.txt"],
                    "detection_method": "dependency_manifest",
                })
            elif name == 'setup.py':
                frameworks.append({
                    "framework": "python_setuptools",
                    "confidence": 0.8,
                    "evidence": ["setup.py"],
                    "detection_method": "dependency_manifest",
                })
            elif name == 'pyproject.toml':
                frameworks.append({
                    "framework": "python_modern",
                    "confidence": 0.9,
                    "evidence": ["pyproject.toml"],
                    "detection_method": "dependency_manifest",
                })

            # Node.js frameworks
            elif name == 'package.json':
                frameworks.append({
                    "framework": "node_js",
                    "confidence": 0.9,
                    "evidence": ["package.json"],
                    "detection_method": "dependency_manifest",
                })

            # Java frameworks
            elif name == 'pom.xml':
                frameworks.append({
                    "framework": "java_maven",
                    "confidence": 0.9,
                    "evidence": ["pom.xml"],
                    "detection_method": "dependency_manifest",
                })
            elif name == 'build.gradle':
                frameworks.append({
                    "framework": "java_gradle",
                    "confidence": 0.8,
                    "evidence": ["build.gradle"],
                    "detection_method": "dependency_manifest",
                })

            # Ruby frameworks
            elif name == 'Gemfile':
                frameworks.append({
                    "framework": "ruby_on_rails",
                    "confidence": 0.8,
                    "evidence": ["Gemfile"],
                    "detection_method": "dependency_manifest",
                })

            # PHP frameworks
            elif name == 'composer.json':
                frameworks.append({
                    "framework": "php_laravel",
                    "confidence": 0.8,
                    "evidence": ["composer.json"],
                    "detection_method": "dependency_manifest",
                })

            # Go frameworks
            elif name == 'go.mod':
                frameworks.append({
                    "framework": "go_mod",
                    "confidence": 0.9,
                    "evidence": ["go.mod"],
                    "detection_method": "dependency_manifest",
                })

            # Rust frameworks
            elif name == 'Cargo.toml':
                frameworks.append({
                    "framework": "rust_cargo",
                    "confidence": 0.9,
                    "evidence": ["Cargo.toml"],
                    "detection_method": "dependency_manifest",
                })

            # Containerization
            elif name == 'Dockerfile':
                frameworks.append({
                    "framework": "docker",
                    "confidence": 0.9,
                    "evidence": ["Dockerfile"],
                    "detection_method": "container_file",
                })
            elif 'docker-compose' in name.lower():
                frameworks.append({
                    "framework": "docker_compose",
                    "confidence": 0.8,
                    "evidence": [name],
                    "detection_method": "container_compose",
                })

        return frameworks

    def _identify_security_areas(self) -> List[Dict[str, Any]]:
        """Identify security-sensitive areas."""
        security_areas = []

        for file_info in self.tree_data.get("files", []):
            path = file_info.get("path", "")
            name = file_info.get("name", "")
            ext = file_info.get("ext", "")

            # Authentication-related files
            auth_patterns = ['auth', 'login', 'register', 'session', 'token', 'jwt', 'oauth']
            if any(pattern in name.lower() for pattern in auth_patterns):
                security_areas.append({
                    "area": f"authentication_{name.lower()}",
                    "type": "authentication",
                    "severity": "high",
                    "evidence": [path],
                    "risk_level": self._calculate_auth_risk_level(name),
                    "detection_method": "filename_pattern",
                })

            # Authorization-related files
            authz_patterns = ['permission', 'authorize', 'access', 'role', 'privilege']
            if any(pattern in name.lower() for pattern in authz_patterns):
                security_areas.append({
                    "area": f"authorization_{name.lower()}",
                    "type": "authorization",
                    "severity": "high",
                    "evidence": [path],
                    "risk_level": self._calculate_authz_risk_level(name),
                    "detection_method": "filename_pattern",
                })

            # Configuration files
            config_extensions = ['json', 'yaml', 'yml', 'ini', 'cfg', 'conf']
            config_patterns = ['config', 'settings', 'env', '.env', 'secrets']
            if ext.lower() in config_extensions or any(pattern in name.lower() for pattern in config_patterns):
                security_areas.append({
                    "area": f"configuration_{name}",
                    "type": "configuration",
                    "severity": "medium",
                    "evidence": [path],
                    "risk_level": self._calculate_config_risk_level(name),
                    "detection_method": "extension_and_pattern",
                })

            # Database files
            db_extensions = ['sql', 'db', 'sqlite', 'mdb', 'accdb']
            db_patterns = ['schema', 'migration', 'seed', 'database', 'db']
            if ext.lower() in db_extensions or any(pattern in name.lower() for pattern in db_patterns):
                security_areas.append({
                    "area": f"database_{name}",
                    "type": "database",
                    "severity": "medium",
                    "evidence": [path],
                    "risk_level": self._calculate_db_risk_level(name),
                    "detection_method": "extension_and_pattern",
                })

            # Security-related files
            security_patterns = ['key', 'cert', 'pem', 'crt', 'ssl', 'tls', 'encrypt', 'decrypt']
            if any(pattern in name.lower() for pattern in security_patterns):
                security_areas.append({
                    "area": f"security_{name.lower()}",
                    "type": "security",
                    "severity": "high",
                    "evidence": [path],
                    "risk_level": self._calculate_security_risk_level(name),
                    "detection_method": "filename_pattern",
                })

            # API-related files
            api_patterns = ['api', 'endpoint', 'route', 'controller', 'service']
            if any(pattern in name.lower() for pattern in api_patterns):
                security_areas.append({
                    "area": f"api_{name.lower()}",
                    "type": "api",
                    "severity": "medium",
                    "evidence": [path],
                    "risk_level": self._calculate_api_risk_level(name),
                    "detection_method": "filename_pattern",
                })

        return security_areas

    def _identify_dependencies(self) -> List[Dict[str, Any]]:
        """Identify dependencies from repository structure."""
        dependencies = []

        for file_info in self.tree_data.get("files", []):
            name = file_info.get("name", "")
            path = file_info.get("path", "")

            # Language ecosystem dependencies
            if name == 'requirements.txt':
                dependencies.append({
                    "type": "python_dependency",
                    "ecosystem": "pip",
                    "manifest_file": path,
                    "detection_method": "dependency_manifest",
                    "impact": "medium",
                })
            elif name == 'package.json':
                dependencies.append({
                    "type": "javascript_dependency",
                    "ecosystem": "npm",
                    "manifest_file": path,
                    "detection_method": "dependency_manifest",
                    "impact": "high",
                })
            elif name == 'Gemfile':
                dependencies.append({
                    "type": "ruby_dependency",
                    "ecosystem": "rubygems",
                    "manifest_file": path,
                    "detection_method": "dependency_manifest",
                    "impact": "medium",
                })
            elif name == 'composer.json':
                dependencies.append({
                    "type": "php_dependency",
                    "ecosystem": "composer",
                    "manifest_file": path,
                    "detection_method": "dependency_manifest",
                    "impact": "medium",
                })
            elif name == 'go.mod':
                dependencies.append({
                    "type": "go_dependency",
                    "ecosystem": "go_modules",
                    "manifest_file": path,
                    "detection_method": "dependency_manifest",
                    "impact": "high",
                })
            elif name == 'Cargo.toml':
                dependencies.append({
                    "type": "rust_dependency",
                    "ecosystem": "cargo",
                    "manifest_file": path,
                    "detection_method": "dependency_manifest",
                    "impact": "medium",
                })
            elif name == 'pom.xml':
                dependencies.append({
                    "type": "java_dependency",
                    "ecosystem": "maven",
                    "manifest_file": path,
                    "detection_method": "dependency_manifest",
                    "impact": "high",
                })
            elif name == 'build.gradle':
                dependencies.append({
                    "type": "java_dependency",
                    "ecosystem": "gradle",
                    "manifest_file": path,
                    "detection_method": "dependency_manifest",
                    "impact": "high",
                })

        return dependencies

    def _identify_compliance_needs(self) -> List[Dict[str, Any]]:
        """Identify compliance requirements."""
        compliance_needs = []

        # Determine compliance needs based on repository characteristics
        repo_type = self._determine_repository_type()
        language_stats = self._calculate_language_statistics()

        # Industry-specific compliance
        if repo_type in ['financial', 'banking', 'healthcare', 'pharma']:
            compliance_needs.extend([
                {
                    "framework": "PCI DSS",
                    "requirement": "Payment Card Industry Data Security Standard",
                    "applicability": "high",
                    "evidence_needed": ["encryption", "access_control", "logging"],
                    "detection_method": "industry_keyword",
                },
                {
                    "framework": "HIPAA",
                    "requirement": "Health Insurance Portability and Accountability Act",
                    "applicability": "high",
                    "evidence_needed": ["patient_data_protection", "access_logs"],
                    "detection_method": "industry_keyword",
                },
            ])

        # Data protection regulations
        if any(lang in language_stats for lang in ['python', 'javascript', 'java']):
            compliance_needs.extend([
                {
                    "framework": "GDPR",
                    "requirement": "General Data Protection Regulation",
                    "applicability": "medium",
                    "evidence_needed": ["data_processing", "user_consent", "data_deletion"],
                    "detection_method": "data_processing_indicator",
                },
                {
                    "framework": "CCPA",
                    "requirement": "California Consumer Privacy Act",
                    "applicability": "medium",
                    "evidence_needed": ["user_data_rights", "opt_out_mechanisms"],
                    "detection_method": "data_processing_indicator",
                },
            ])

        # Security frameworks
        security_frameworks = self._identify_security_frameworks()
        for framework in security_frameworks:
            compliance_needs.append({
                "framework": framework,
                "requirement": f"{framework} security controls",
                "applicability": "high",
                "evidence_needed": self._get_framework_evidence(framework),
                "detection_method": "framework_indicator",
            })

        # OWASP ASVS (Application Security Verification Standards)
        if any(lang in language_stats for lang in ['python', 'javascript', 'java', 'php']):
            compliance_needs.extend([
                {
                    "framework": "OWASP ASVS",
                    "requirement": "Application Security Verification Standards",
                    "applicability": "high",
                    "evidence_needed": ["authentication", "authorization", "input_validation"],
                    "detection_method": "web_application_indicator",
                },
            ])

        return compliance_needs

    def _determine_required_tools(self) -> List[Dict[str, Any]]:
        """Determine required analysis tools."""
        tools = []

        language_stats = self._calculate_language_statistics()
        frameworks = self._identify_framework_candidates()
        security_areas = self._identify_security_areas()

        # Static analysis tools
        if any(lang in language_stats for lang in ['python', 'java', 'javascript']):
            tools.extend([
                {
                    "tool": "semgrep",
                    "category": "static_analysis",
                    "purpose": "Security vulnerability detection",
                    "compatibility": ["python", "java", "javascript"],
                    "priority": "high",
                    "detection_method": "language_compatibility",
                },
                {
                    "tool": "bandit",
                    "category": "static_analysis",
                    "purpose": "Python security analysis",
                    "compatibility": ["python"],
                    "priority": "medium",
                    "detection_method": "language_compatibility",
                },
            ])

        # Container security
        if any(f["framework"] in ["docker", "docker_compose"] for f in frameworks):
            tools.append({
                "tool": "trivy",
                "category": "container_security",
                "purpose": "Container image vulnerability scanning",
                "compatibility": ["docker"],
                "priority": "high",
                "detection_method": "framework_indicator",
            })

        # Dependency analysis
        if any(lang in language_stats for lang in ['python', 'javascript', 'go', 'rust']):
            tools.extend([
                {
                    "tool": "pip-audit",
                    "category": "dependency_analysis",
                    "purpose": "Python dependency vulnerability scanning",
                    "compatibility": ["python"],
                    "priority": "high",
                    "detection_method": "language_compatibility",
                },
                {
                    "tool": "npm audit",
                    "category": "dependency_analysis",
                    "purpose": "JavaScript/NPM dependency vulnerability scanning",
                    "compatibility": ["javascript"],
                    "priority": "high",
                    "detection_method": "language_compatibility",
                },
            ])

        # Infrastructure as Code analysis
        iac_files = [f for f in self.tree_data.get("files", []) if f.get("name", "").endswith(('terraform', 'tf', 'tf.json', 'yaml', 'yml'))]
        if iac_files:
            tools.append({
                "tool": "tfsec",
                "category": "iac_security",
                "purpose": "Infrastructure as Code security scanning",
                "compatibility": ["terraform", "kubernetes"],
                "priority": "medium",
                "detection_method": "iac_file_detection",
            })

        # Secret detection
        secret_files = [f for f in self.tree_data.get("files", []) if any(secret in f.get("name", "").lower() for secret in ['env', 'secret', 'key', 'cert'])]
        if secret_files:
            tools.append({
                "tool": "gitleaks",
                "category": "secret_detection",
                "purpose": "Secret and credential detection",
                "compatibility": ["all"],
                "priority": "high",
                "detection_method": "secret_file_detection",
            })

        return tools

    def _generate_deterministic_checks(self) -> List[Dict[str, Any]]:
        """Generate deterministic security checks."""
        checks = []

        language_stats = self._calculate_language_statistics()
        frameworks = self._identify_framework_candidates()

        # Framework-specific checks
        for framework in frameworks:
            fw_name = framework["framework"]
            if fw_name == "django":
                checks.extend([
                    {
                        "check": "django_authentication",
                        "type": "authentication",
                        "severity": "high",
                        "description": "Verify Django authentication mechanisms",
                        "file_patterns": ["*.py"],
                        "framework_specific": True,
                    },
                    {
                        "check": "django_authorization",
                        "type": "authorization",
                        "severity": "high",
                        "description": "Verify Django authorization mechanisms",
                        "file_patterns": ["*.py"],
                        "framework_specific": True,
                    },
                ])
            elif fw_name == "flask":
                checks.extend([
                    {
                        "check": "flask_authentication",
                        "type": "authentication",
                        "severity": "medium",
                        "description": "Verify Flask authentication mechanisms",
                        "file_patterns": ["app.py", "*.py"],
                        "framework_specific": True,
                    },
                ])
            elif fw_name == "express":
                checks.extend([
                    {
                        "check": "express_middleware",
                        "type": "middleware",
                        "severity": "medium",
                        "description": "Verify Express.js middleware security",
                        "file_patterns": ["*.js", "*.ts"],
                        "framework_specific": True,
                    },
                ])
            elif fw_name == "spring":
                checks.extend([
                    {
                        "check": "spring_security",
                        "type": "authentication",
                        "severity": "high",
                        "description": "Verify Spring Security configuration",
                        "file_patterns": ["*.java", "*.xml"],
                        "framework_specific": True,
                    },
                ])

        # Language-agnostic checks
        checks.extend([
            {
                "check": "input_validation",
                "type": "input_validation",
                "severity": "medium",
                "description": "Verify input validation and sanitization",
                "file_patterns": ["*.py", "*.js", "*.ts", "*.php", "*.java"],
                "framework_specific": False,
            },
            {
                "check": "sql_injection",
                "type": "injection",
                "severity": "high",
                "description": "Detect SQL injection vulnerabilities",
                "file_patterns": ["*.py", "*.java", "*.php", "*.sql"],
                "framework_specific": False,
            },
            {
                "check": "command_injection",
                "type": "injection",
                "severity": "high",
                "description": "Detect command injection vulnerabilities",
                "file_patterns": ["*.py", "*.js", "*.sh"],
                "framework_specific": False,
            },
            {
                "check": "file_upload",
                "type": "file_operations",
                "severity": "medium",
                "description": "Verify secure file upload handling",
                "file_patterns": ["*.py", "*.js", "*.php"],
                "framework_specific": False,
            },
        ])

        return checks

    def _generate_ast_checks(self) -> List[Dict[str, Any]]:
        """Generate AST/structural analysis checks."""
        checks = []

        language_stats = self._calculate_language_statistics()

        # Language-specific AST checks
        for language in language_stats.keys():
            if language == "python":
                checks.extend([
                    {
                        "check": "python_decorator_analysis",
                        "type": "structural",
                        "severity": "low",
                        "description": "Analyze Python decorators for security implications",
                        "file_patterns": ["*.py"],
                        "language_specific": True,
                        "parser": "ast",
                    },
                    {
                        "check": "python_import_analysis",
                        "type": "structural",
                        "severity": "medium",
                        "description": "Analyze Python imports for security risks",
                        "file_patterns": ["*.py"],
                        "language_specific": True,
                        "parser": "ast",
                    },
                ])
            elif language == "javascript":
                checks.extend([
                    {
                        "check": "javascript_function_analysis",
                        "type": "structural",
                        "severity": "medium",
                        "description": "Analyze JavaScript functions for security implications",
                        "file_patterns": ["*.js", "*.ts", "*.jsx", "*.tsx"],
                        "language_specific": True,
                        "parser": "esprima",
                    },
                    {
                        "check": "javascript_callback_analysis",
                        "type": "structural",
                        "severity": "low",
                        "description": "Analyze JavaScript callbacks for potential vulnerabilities",
                        "file_patterns": ["*.js", "*.ts"],
                        "language_specific": True,
                        "parser": "babel",
                    },
                ])
            elif language == "java":
                checks.extend([
                    {
                        "check": "java_method_analysis",
                        "type": "structural",
                        "severity": "medium",
                        "description": "Analyze Java methods for security implications",
                        "file_patterns": ["*.java"],
                        "language_specific": True,
                        "parser": "javaparser",
                    },
                ])

        return checks

    def _generate_dependency_queries(self) -> List[Dict[str, Any]]:
        """Generate dependency vulnerability queries."""
        queries = []

        dependencies = self._identify_dependencies()

        for dep in dependencies:
            ecosystem = dep["ecosystem"]
            if ecosystem == "pip":
                queries.extend([
                    {
                        "query": "pypi_cve",
                        "source": "PyPI",
                        "ecosystem": "python",
                        "description": "Check PyPI packages for known CVEs",
                        "priority": "high",
                        "frequency": "daily",
                    },
                    {
                        "query": "github_advisory",
                        "source": "GitHub Advisory Database",
                        "ecosystem": "python",
                        "description": "Check GitHub repository for security advisories",
                        "priority": "medium",
                        "frequency": "weekly",
                    },
                ])
            elif ecosystem == "npm":
                queries.extend([
                    {
                        "query": "npm_vulnerability",
                        "source": "NPM Registry",
                        "ecosystem": "javascript",
                        "description": "Check NPM packages for known vulnerabilities",
                        "priority": "high",
                        "frequency": "daily",
                    },
                    {
                        "query": "oss_index",
                        "source": "OSS Index",
                        "ecosystem": "javascript",
                        "description": "Check OSS Index for package vulnerabilities",
                        "priority": "medium",
                        "frequency": "weekly",
                    },
                ])
            elif ecosystem == "rubygems":
                queries.extend([
                    {
                        "query": "rubygems_security",
                        "source": "RubyGems Security",
                        "ecosystem": "ruby",
                        "description": "Check RubyGems packages for security issues",
                        "priority": "medium",
                        "frequency": "weekly",
                    },
                ])
            elif ecosystem == "composer":
                queries.extend([
                    {
                        "query": "packagist_security",
                        "source": "Packagist Security Advisories",
                        "ecosystem": "php",
                        "description": "Check Packagist packages for security issues",
                        "priority": "medium",
                        "frequency": "weekly",
                    },
                ])
            elif ecosystem == "go_modules":
                queries.extend([
                    {
                        "query": "go_vulnerability_db",
                        "source": "Go Vulnerability Database",
                        "ecosystem": "go",
                        "description": "Check Go modules for known vulnerabilities",
                        "priority": "high",
                        "frequency": "daily",
                    },
                ])
            elif ecosystem == "rust_cargo":
                queries.extend([
                    {
                        "query": "rust_advisory_db",
                        "source": "Rust Advisory Database",
                        "ecosystem": "rust",
                        "description": "Check Rust crates for security advisories",
                        "priority": "high",
                        "frequency": "daily",
                    },
                ])
            elif ecosystem == "maven":
                queries.extend([
                    {
                        "query": "owasp_dependency_check",
                        "source": "OWASP Dependency Check",
                        "ecosystem": "java",
                        "description": "Check Maven dependencies for known vulnerabilities",
                        "priority": "high",
                        "frequency": "daily",
                    },
                ])
            elif ecosystem == "gradle":
                queries.extend([
                    {
                        "query": "owasp_dependency_check",
                        "source": "OWASP Dependency Check",
                        "ecosystem": "java",
                        "description": "Check Gradle dependencies for known vulnerabilities",
                        "priority": "high",
                        "frequency": "daily",
                    },
                ])

        return queries

    def _generate_vulnerability_queries(self) -> List[Dict[str, Any]]:
        """Generate vulnerability knowledge queries."""
        queries = []

        # CVE/NVD queries
        queries.extend([
            {
                "query": "cve_nvd_latest",
                "source": "NVD",
                "description": "Get latest CVE entries from National Vulnerability Database",
                "priority": "high",
                "frequency": "hourly",
                "filters": {"severity": ["critical", "high"], "published": True},
            },
            {
                "query": "cve_cisa_kev",
                "source": "CISA KEV",
                "description": "Get known exploited vulnerabilities from CISA",
                "priority": "high",
                "frequency": "daily",
                "filters": {"exploited": True},
            },
            {
                "query": "cve_cwe_associations",
                "source": "CWE",
                "description": "Get Common Weakness Enumeration associations",
                "priority": "medium",
                "frequency": "weekly",
                "filters": {"category": "software"},
            },
        ])

        # Framework-specific vulnerability queries
        frameworks = self._identify_framework_candidates()
        for framework in frameworks:
            fw_name = framework["framework"]
            if fw_name == "django":
                queries.extend([
                    {
                        "query": "django_security_issues",
                        "source": "Django Security Team",
                        "description": "Check Django security advisories and patches",
                        "priority": "high",
                        "frequency": "weekly",
                        "framework_specific": True,
                    },
                ])
            elif fw_name == "flask":
                queries.extend([
                    {
                        "query": "flask_security_issues",
                        "source": "Flask Security Team",
                        "description": "Check Flask security advisories and patches",
                        "priority": "medium",
                        "frequency": "weekly",
                        "framework_specific": True,
                    },
                ])

        return queries

    def _generate_compliance_queries(self) -> List[Dict[str, Any]]:
        """Generate compliance-related queries."""
        queries = []

        compliance_needs = self._identify_compliance_needs()

        for need in compliance_needs:
            framework = need["framework"]
            if framework == "OWASP ASVS":
                queries.append({
                    "query": "owasp_asvs_level_1",
                    "source": "OWASP ASVS Level 1",
                    "description": "Application security verification - Authentication",
                    "priority": "high",
                    "frequency": "static",
                    "compliance_framework": "OWASP ASVS",
                })
            elif framework == "PCI DSS":
                queries.append({
                    "query": "pci_dss_requirement_2",
                    "source": "PCI DSS Council",
                    "description": "Requirement 2: Secure Configuration",
                    "priority": "high",
                    "frequency": "static",
                    "compliance_framework": "PCI DSS",
                })
            elif framework == "HIPAA":
                queries.append({
                    "query": "hipaa_security_rule",
                    "source": "HHS Office for Civil Rights",
                    "description": "Administrative, Technical, and Physical Safeguards",
                    "priority": "high",
                    "frequency": "static",
                    "compliance_framework": "HIPAA",
                })
            elif framework == "GDPR":
                queries.append({
                    "query": "gdpr_article_32",
                    "source": "EU GDPR",
                    "description": "Security of processing - Article 32",
                    "priority": "medium",
                    "frequency": "dynamic",
                    "compliance_framework": "GDPR",
                })

        return queries

    # Helper methods

    def _determine_repository_type(self) -> str:
        """Determine repository type based on characteristics."""
        language_stats = self._calculate_language_statistics()
        file_count = len(self.tree_data.get("files", []))

        # Check for specific repository indicators
        indicators = {
            'web_application': ['html', 'css', 'javascript', 'php', 'python'],
            'mobile_app': ['swift', 'kotlin', 'java', 'javascript'],
            'desktop_app': ['c', 'cpp', 'csharp', 'rust'],
            'data_science': ['python', 'r', 'sql', 'jupyter'],
            'devops': ['yaml', 'terraform', 'docker', 'bash'],
            'api_service': ['java', 'python', 'javascript', 'go'],
        }

        for repo_type, lang_list in indicators.items():
            if any(lang in language_stats for lang in lang_list):
                return repo_type

        # Determine based on file count and complexity
        if file_count > 1000:
            return "large_scale"
        elif file_count > 100:
            return "medium_scale"
        else:
            return "small_scale"

    def _identify_security_frameworks(self) -> List[str]:
        """Identify security frameworks relevant to the repository."""
        frameworks = []

        # Add frameworks based on repository characteristics
        if any(lang in self._calculate_language_statistics() for lang in ['python', 'javascript', 'java']):
            frameworks.extend(["OWASP ASVS", "OWASP Top 10"])

        if any('authentication' in area for area in [s["area"] for s in self._identify_security_areas()]):
            frameworks.append("NIST SP 800-63B")

        if any('configuration' in area for area in [s["area"] for s in self._identify_security_areas()]):
            frameworks.extend(["CIS Benchmarks", "NIST SP 800-53"])

        return frameworks

    def _get_framework_evidence(self, framework: str) -> List[str]:
        """Get evidence requirements for a security framework."""
        evidence_map = {
            "OWASP ASVS": ["authentication", "authorization", "input_validation", "session_management"],
            "OWASP Top 10": ["injection", "broken_authentication", "sensitive_data_exposure"],
            "NIST SP 800-63B": ["authentication", "password_policy", "session_management"],
            "CIS Benchmarks": ["file_permissions", "network_configuration", "audit_logging"],
            "NIST SP 800-53": ["access_control", "incident_response", "contingency_planning"],
        }

        return evidence_map.get(framework, [])

    def _calculate_auth_risk_level(self, filename: str) -> str:
        """Calculate authentication risk level based on filename."""
        filename_lower = filename.lower()
        high_risk = ['password', 'auth_token', 'secret', 'key', 'cert', 'ssl', 'tls']
        medium_risk = ['login', 'session', 'oauth', 'jwt', 'bearer']

        if any(word in filename_lower for word in high_risk):
            return "high"
        elif any(word in filename_lower for word in medium_risk):
            return "medium"
        else:
            return "low"

    def _calculate_authz_risk_level(self, filename: str) -> str:
        """Calculate authorization risk level based on filename."""
        filename_lower = filename.lower()
        high_risk = ['permission', 'privilege', 'access_control', 'rbac']
        medium_risk = ['role', 'authorization', 'scope']

        if any(word in filename_lower for word in high_risk):
            return "high"
        elif any(word in filename_lower for word in medium_risk):
            return "medium"
        else:
            return "low"

    def _calculate_config_risk_level(self, filename: str) -> str:
        """Calculate configuration risk level based on filename."""
        filename_lower = filename.lower()
        high_risk = ['.env', 'secret', 'credential', 'api_key', 'password']
        medium_risk = ['config', 'settings', 'env', 'configuration']

        if any(word in filename_lower for word in high_risk):
            return "high"
        elif any(word in filename_lower for word in medium_risk):
            return "medium"
        else:
            return "low"

    def _calculate_db_risk_level(self, filename: str) -> str:
        """Calculate database risk level based on filename."""
        filename_lower = filename.lower()
        high_risk = ['schema', 'migration', 'production', 'live', 'backup']
        medium_risk = ['database', 'db', 'sql', 'query']

        if any(word in filename_lower for word in high_risk):
            return "high"
        elif any(word in filename_lower for word in medium_risk):
            return "medium"
        else:
            return "low"

    def _calculate_security_risk_level(self, filename: str) -> str:
        """Calculate security-related risk level."""
        filename_lower = filename.lower()
        high_risk = ['private_key', 'secret_key', 'certificate', 'ssl_key', 'encryption_key']
        medium_risk = ['public_key', 'cert', 'ssl_cert', 'encryption']

        if any(word in filename_lower for word in high_risk):
            return "high"
        elif any(word in filename_lower for word in medium_risk):
            return "medium"
        else:
            return "low"

    def _calculate_api_risk_level(self, filename: str) -> str:
        """Calculate API-related risk level."""
        filename_lower = filename.lower()
        high_risk = ['endpoint', 'api_key', 'authentication', 'authorization']
        medium_risk = ['controller', 'service', 'route', 'endpoint']

        if any(word in filename_lower for word in high_risk):
            return "high"
        elif any(word in filename_lower for word in medium_risk):
            return "medium"
        else:
            return "low"

    def _generate_scan_id(self) -> str:
        """Generate a unique scan ID."""
        import uuid
        from datetime import datetime

        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        random_suffix = str(uuid.uuid4())[:8]
        return f"SCAN-{timestamp}-{random_suffix}"

    def _get_timestamp(self) -> str:
        """Get current timestamp."""
        from datetime import datetime
        return datetime.now().isoformat()

    def _extract_repository_info(self) -> Dict[str, Any]:
        """Extract basic repository information."""
        return {
            "name": Path(self.scan_request.repository_url).name if self.scan_request.repository_url else "unknown",
            "source_type": self.scan_request.source_type,
            "branch": self.scan_request.branch,
            "file_count": len(self.tree_data.get("files", [])),
            "size_estimate": self._calculate_size_estimate(),
        }

    def _calculate_size_estimate(self) -> int:
        """Calculate estimated repository size."""
        total_size = 0
        for file_info in self.tree_data.get("files", []):
            total_size += file_info.get("size", 0)
        return total_size

    def _determine_tech_stack(self) -> List[str]:
        """Determine technology stack from analysis."""
        stack = []
        language_stats = self._calculate_language_statistics()

        for language in language_stats.keys():
            if language != "unknown":
                stack.append(language)

        return stack

    def _extract_languages(self) -> Dict[str, Any]:
        """Extract language statistics for analysis plan."""
        return self._calculate_language_statistics()

    def _extract_frameworks(self) -> List[Dict[str, Any]]:
        """Extract framework information for analysis plan."""
        return self._identify_framework_candidates()

    def _calculate_overall_confidence(self) -> Dict[str, Any]:
        """Calculate overall confidence scores."""
        confidence = {
            "technical_stack_confidence": self._calculate_stack_confidence(),
            "security_assessment_confidence": self._calculate_security_confidence(),
            "dependency_analysis_confidence": self._calculate_dependency_confidence(),
            "compliance_assessment_confidence": self._calculate_compliance_confidence(),
        }

        return confidence

    def _calculate_stack_confidence(self) -> float:
        """Calculate confidence in technical stack identification."""
        language_stats = self._calculate_language_statistics()
        if not language_stats:
            return 0.0

        # Confidence based on language diversity and file count
        confidence = min(len(language_stats) * 0.2, 1.0)  # Up to 1.0 for multiple languages
        if len(self.tree_data.get("files", [])) > 100:
            confidence += 0.3

        return min(confidence, 1.0)

    def _calculate_security_confidence(self) -> float:
        """Calculate confidence in security assessment."""
        security_areas = self._identify_security_areas()
        if not security_areas:
            return 0.0

        # Confidence based on number of security areas identified
        confidence = min(len(security_areas) * 0.1, 1.0)

        # Higher confidence for critical areas
        critical_count = sum(1 for area in security_areas if area.get("severity") == "high")
        confidence += critical_count * 0.2

        return min(confidence, 1.0)

    def _calculate_dependency_confidence(self) -> float:
        """Calculate confidence in dependency analysis."""
        dependencies = self._identify_dependencies()
        if not dependencies:
            return 0.0

        # Confidence based on number and diversity of dependencies
        confidence = min(len(dependencies) * 0.15, 1.0)

        # Higher confidence for high-impact dependencies
        high_impact = sum(1 for dep in dependencies if dep.get("impact") == "high")
        confidence += high_impact * 0.1

        return min(confidence, 1.0)

    def _calculate_compliance_confidence(self) -> float:
        """Calculate confidence in compliance assessment."""
        compliance_needs = self._identify_compliance_needs()
        if not compliance_needs:
            return 0.0

        # Confidence based on number of compliance requirements
        confidence = min(len(compliance_needs) * 0.1, 1.0)

        return confidence

    def _identify_important_files(self) -> List[Dict[str, Any]]:
        """Identify important files for analysis."""
        important_files = []

        for file_info in self.tree_data.get("files", []):
            path = file_info.get("path", "")
            name = file_info.get("name", "")
            ext = file_info.get("ext", "")

            # Determine importance based on various factors
            importance_score = 0

            # Source code files are important
            if ext in ['py', 'js', 'ts', 'java', 'cpp', 'php', 'rb', 'go', 'rs']:
                importance_score += 3

            # Entry points are very important
            entry_point_patterns = ['main.py', 'app.py', 'index.py', 'server.py', 'api.py']
            if name in entry_point_patterns:
                importance_score += 5

            # Configuration files are important
            if ext in ['json', 'yaml', 'yml', 'ini', 'cfg']:
                importance_score += 2

            # Security-related files are important
            security_patterns = ['auth', 'login', 'session', 'token', 'key']
            if any(pattern in name.lower() for pattern in security_patterns):
                importance_score += 4

            # Database files are important
            db_patterns = ['database', 'db', 'sql', 'schema']
            if any(pattern in name.lower() for pattern in db_patterns):
                importance_score += 3

            # Test files are important for analysis
            test_patterns = ['test_', '_test', 'tests']
            if any(pattern in name.lower() for pattern in test_patterns):
                importance_score += 2

            if importance_score > 0:
                important_files.append({
                    "file": path,
                    "name": name,
                    "importance_score": importance_score,
                    "reason": self._get_importance_reason(path, name, ext),
                })

        # Sort by importance score (descending)
        important_files.sort(key=lambda x: x["importance_score"], reverse=True)

        return important_files

    def _get_importance_reason(self, path: str, name: str, ext: str) -> str:
        """Get reason why a file is important."""
        reasons = []

        if ext in ['py', 'js', 'ts', 'java', 'cpp', 'php', 'rb', 'go', 'rs']:
            reasons.append("Source code")

        entry_point_patterns = ['main.py', 'app.py', 'index.py', 'server.py', 'api.py']
        if name in entry_point_patterns:
            reasons.append("Entry point")

        if ext in ['json', 'yaml', 'yml', 'ini', 'cfg']:
            reasons.append("Configuration")

        security_patterns = ['auth', 'login', 'session', 'token', 'key']
        if any(pattern in name.lower() for pattern in security_patterns):
            reasons.append("Security-related")

        db_patterns = ['database', 'db', 'sql', 'schema']
        if any(pattern in name.lower() for pattern in db_patterns):
            reasons.append("Database")

        test_patterns = ['test_', '_test', 'tests']
        if any(pattern in name.lower() for pattern in test_patterns):
            reasons.append("Test file")

        if reasons:
            return " and ".join(reasons)
        else:
            return "File in repository"

    def _get_security_sensitive_areas(self) -> List[Dict[str, Any]]:
        """Get formatted security sensitive areas for analysis plan."""
        return self._identify_security_areas()

    def _estimate_analysis_scope(self) -> Dict[str, Any]:
        """Estimate the scope of analysis."""
        file_count = len(self.tree_data.get("files", []))

        if file_count < 50:
            scope = "small"
            complexity = "low"
        elif file_count < 500:
            scope = "medium"
            complexity = "medium"
        else:
            scope = "large"
            complexity = "high"

        return {
            "scope": scope,
            "file_count": file_count,
            "complexity": complexity,
            "estimated_effort": self._estimate_effort(scope, complexity),
        }

    def _estimate_effort(self, scope: str, complexity: str) -> str:
        """Estimate effort required for analysis."""
        effort_map = {
            ("small", "low"): "quick",
            ("small", "medium"): "standard",
            ("small", "high"): "thorough",
            ("medium", "low"): "standard",
            ("medium", "medium"): "detailed",
            ("medium", "high"): "comprehensive",
            ("large", "low"): "detailed",
            ("large", "medium"): "comprehensive",
            ("large", "high"): "extensive",
        }

        return effort_map.get((scope, complexity), "standard")

    def _determine_prioritization(self) -> Dict[str, Any]:
        """Determine prioritization strategy for analysis."""
        return {
            "primary_focus": "vulnerabilities",
            "secondary_focus": "compliance",
            "tertiary_focus": "configuration",
            "method": "risk_based",
            "schedule": "phase_based",
        }

    def _provide_decision_reasons(self) -> List[Dict[str, Any]]:
        """Provide reasons for key decisions in the analysis plan."""
        reasons = []

        # Reason for framework identification
        frameworks = self._identify_framework_candidates()
        if frameworks:
            reasons.append({
                "decision": "Framework Identification",
                "rationale": f"Identified {len(frameworks)} potential frameworks based on dependency manifests and configuration files",
                "evidence": [f["framework"] for f in frameworks],
                "impact": "high",
            })

        # Reason for security area identification
        security_areas = self._identify_security_areas()
        if security_areas:
            reasons.append({
                "decision": "Security Area Identification",
                "rationale": f"Identified {len(security_areas)} security-sensitive areas based on file patterns and extensions",
                "evidence": [area["area"] for area in security_areas],
                "impact": "high",
            })

        # Reason for tool selection
        tools = self._determine_required_tools()
        if tools:
            reasons.append({
                "decision": "Tool Selection",
                "rationale": f"Selected {len(tools)} tools based on repository language and framework compatibility",
                "evidence": [tool["tool"] for tool in tools],
                "impact": "medium",
            })

        # Reason for dependency identification
        dependencies = self._identify_dependencies()
        if dependencies:
            reasons.append({
                "decision": "Dependency Analysis",
                "rationale": f"Identified {len(dependencies)} dependencies across multiple ecosystems",
                "evidence": [dep["ecosystem"] for dep in dependencies],
                "impact": "high",
            })

        return reasons

    def analyze_repository_tree(self) -> Dict[str, Any]:
        """Perform complete repository tree analysis for analysis planning."""
        logger.info("Starting LLM #1 analysis of repository tree")

        # Generate analysis plan
        analysis_plan = self.generate_analysis_plan()

        # Log key findings
        logger.info(f"Analysis plan generated:")
        logger.info(f"  - Scan ID: {analysis_plan['scan_id']}")
        logger.info(f"  - Technology stack: {', '.join(analysis_plan['stack'])}")
        logger.info(f"  - Languages: {list(analysis_plan['languages'].keys())}")
        logger.info(f"  - Frameworks: {len(analysis_plan['frameworks'])} identified")
        logger.info(f"  - Security areas: {len(analysis_plan['security_sensitive_areas'])} identified")
        logger.info(f"  - Tools required: {len(analysis_plan['required_tools'])} tools")
        logger.info(f"  - Deterministic checks: {len(analysis_plan['required_deterministic_checks'])} checks")
        logger.info(f"  - AST checks: {len(analysis_plan['required_ast_checks'])} checks")

        return analysis_plan

    def save_analysis_plan(self, scan_id: str) -> bool:
        """Save analysis plan to workspace."""
        try:
            workspace_path = Path(__file__).resolve().parents[2] / "runtime" / "workspaces" / scan_id
            plan_path = workspace_path / "analysis_plan.json"

            # Write analysis plan with pretty formatting
            with open(plan_path, 'w', encoding='utf-8') as f:
                json.dump(self.analysis_plan, f, indent=2, ensure_ascii=False)

            logger.info(f"Analysis plan saved to {plan_path}")
            return True

        except Exception as e:
            logger.error(f"Error saving analysis plan for scan {scan_id}: {e}")
            return False
