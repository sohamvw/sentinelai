"""
Repository tree analyzer for SentinelAI.
This module handles repository tree analysis and metadata extraction.
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, List
from app.core.logger import get_logger

logger = get_logger(__name__)
class TreeAnalyzer:
    """Analyzes repository trees and extracts metadata."""

    def __init__(self, repository_path: str):
        self.repository_path = Path(repository_path)
        self.tree_data = None
        self.metadata = {}

    def analyze(self) -> Dict[str, Any]:
        """Perform complete tree analysis."""
        logger.info(f"Starting tree analysis for repository: {self.repository_path}")

        # Walk the repository
        tree_structure = self._walk_repository()

        # Extract metadata
        metadata = self._extract_metadata(tree_structure)

        # Build final analysis result
        analysis_result = {
            "repository_path": str(self.repository_path),
            "analysis_timestamp": self._get_timestamp(),
            "total_files": tree_structure.get("total_files", 0),
            "directory_structure": tree_structure.get("directory_structure", []),
            "file_metadata": tree_structure.get("file_metadata", []),
            "language_distribution": metadata.get("language_distribution", {}),
            "framework_candidates": metadata.get("framework_candidates", []),
            "important_files": metadata.get("important_files", []),
            "security_sensitive_areas": metadata.get("security_sensitive_areas", []),
            "dependency_manifests": metadata.get("dependency_manifests", []),
            "entry_points": metadata.get("entry_points", []),
            "configuration_files": metadata.get("configuration_files", []),
            "test_files": metadata.get("test_files", []),
            "documentation_files": metadata.get("documentation_files", []),
            "has_docker": metadata.get("has_docker", False),
            "has_compose": metadata.get("has_compose", False),
            "has_package_json": metadata.get("has_package_json", False),
            "has_requirements": metadata.get("has_requirements", False),
            "has_setup_py": metadata.get("has_setup_py", False),
            "has_cargo_toml": metadata.get("has_cargo_toml", False),
            "has_go_mod": metadata.get("has_go_mod", False),
            "has_composer_json": metadata.get("has_composer_json", False),
            "has_gemfile": metadata.get("has_gemfile", False),
            "has_pom_xml": metadata.get("has_pom_xml", False),
            "has_build_gradle": metadata.get("has_build_gradle", False),
            "has_pyproject_toml": metadata.get("has_pyproject_toml", False),
        }

        self.tree_data = analysis_result
        self.metadata = metadata

        logger.info(f"Tree analysis completed: {analysis_result['total_files']} files analyzed")
        return analysis_result

    def _walk_repository(self) -> Dict[str, Any]:
        """Walk repository and collect file information."""
        total_files = 0
        directory_structure = []
        file_metadata = []

        for root, dirs, files in os.walk(self.repository_path):
            # Skip hidden directories and build artifacts
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in
                      ['__pycache__', '.git', '.venv', 'venv', '.env', 'node_modules',
                       'build', 'dist', '.pytest_cache', '.mypy_cache', 'target', 'bin',
                       'obj', '.DS_Store', 'Thumbs.db']]

            # Process directory
            rel_root = Path(root).relative_to(self.repository_path)
            directory_structure.append({
                "path": str(rel_root).replace('\\', '/'),
                "name": Path(root).name,
                "is_hidden": Path(root).name.startswith('.'),
                "file_count": len(files),
                "subdirectory_count": len(dirs)
            })

            # Process files
            for file in files:
                file_path = Path(root) / file
                rel_path = file_path.relative_to(self.repository_path)

                file_info = {
                    "path": str(rel_path).replace('\\', '/'),
                    "name": file,
                    "size": file_path.stat().st_size,
                    "extension": file_path.suffix.lower()[1:] if file_path.suffix else '',
                    "is_binary": self._is_binary_file(file_path),
                    "is_text": not self._is_binary_file(file_path),
                    "is_hidden": file.startswith('.'),
                    "parent_directory": str(rel_path.parent).replace('\\', '/'),
                    "depth": len(rel_path.parents),
                    "last_modified": file_path.stat().st_mtime,
                }

                file_metadata.append(file_info)
                total_files += 1

        return {
            "total_files": total_files,
            "directory_structure": directory_structure,
            "file_metadata": file_metadata
        }

    def _is_binary_file(self, file_path: Path) -> bool:
        """Check if file is binary based on extension and content."""
        # Common binary file extensions
        binary_extensions = {
            'exe', 'dll', 'so', 'dylib', 'bin', 'pyc', 'pyd', 'dat', 'db',
            'jpg', 'jpeg', 'png', 'gif', 'bmp', 'ico', 'svg', 'webp', 'mp4',
            'avi', 'mov', 'wmv', 'flv', 'mp3', 'wav', 'flac', 'aac', 'ogg',
            'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'pdf', 'doc', 'docx',
            'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odg', 'odp', 'ttf',
            'otf', 'woff', 'woff2'
        }

        ext = file_path.suffix.lower()
        if ext:
            ext = ext[1:]  # Remove leading dot
            if ext in binary_extensions:
                return True

        # Check file content for null bytes (indicator of binary files)
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                if b'\x00' in chunk:
                    return True
        except (OSError, IOError):
            pass

        return False

    def _extract_metadata(self, tree_structure: Dict[str, Any]) -> Dict[str, Any]:
        """Extract additional metadata from tree structure."""
        files = tree_structure.get("file_metadata", [])
        language_distribution = {}
        framework_candidates = []
        important_files = []
        security_sensitive_areas = []
        dependency_manifests = []
        entry_points = []
        configuration_files = []
        test_files = []
        documentation_files = []

        # Flags for different types of files
        flags = {
            'has_docker': False,
            'has_compose': False,
            'has_package_json': False,
            'has_requirements': False,
            'has_setup_py': False,
            'has_cargo_toml': False,
            'has_go_mod': False,
            'has_composer_json': False,
            'has_gemfile': False,
            'has_pom_xml': False,
            'has_build_gradle': False,
            'has_pyproject_toml': False,
        }

        for file_info in files:
            path = file_info["path"]
            name = file_info["name"]
            ext = file_info["extension"]
            is_text = file_info["is_text"]

            if not is_text:
                continue

            # Language distribution
            if ext:
                language_distribution[ext] = language_distribution.get(ext, 0) + 1

            # Framework and configuration detection
            if name.lower() in ['dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
                              'docker-compose.dev.yml', 'docker-compose.prod.yml']:
                flags[f"has_{name.lower().replace('.', '_').replace('-', '_')}"] = True
                framework_candidates.append({"type": "containerization", "file": path})

            if name.lower() == 'package.json':
                flags["has_package_json"] = True
                framework_candidates.append({"type": "node_js", "file": path})

            if name.lower() == 'requirements.txt':
                flags["has_requirements"] = True
                framework_candidates.append({"type": "python_pip", "file": path})

            if name.lower() == 'setup.py':
                flags["has_setup_py"] = True
                framework_candidates.append({"type": "python_setuptools", "file": path})

            if name.lower() == 'pyproject.toml':
                flags["has_pyproject_toml"] = True
                framework_candidates.append({"type": "python_modern", "file": path})

            if name.lower() == 'Cargo.toml':
                flags["has_cargo_toml"] = True
                framework_candidates.append({"type": "rust", "file": path})

            if name.lower() == 'go.mod':
                flags["has_go_mod"] = True
                framework_candidates.append({"type": "go", "file": path})

            if name.lower() == 'composer.json':
                flags["has_composer_json"] = True
                framework_candidates.append({"type": "php", "file": path})

            if name.lower() == 'Gemfile':
                flags["has_gemfile"] = True
                framework_candidates.append({"type": "ruby", "file": path})

            if name.lower() == 'pom.xml':
                flags["has_pom_xml"] = True
                framework_candidates.append({"type": "java_maven", "file": path})

            if name.lower() == 'build.gradle' or name.lower() == 'build.gradle.kts':
                flags["has_build_gradle"] = True
                framework_candidates.append({"type": "java_gradle", "file": path})

            # Classify files
            if self._is_entry_point_file(path, name, ext):
                entry_points.append(path)

            if self._is_configuration_file(path, name, ext):
                configuration_files.append(path)
                security_sensitive_areas.append({
                    "file": path,
                    "type": "configuration",
                    "severity": "medium",
                    "reason": "Configuration file may contain sensitive information"
                })

            if self._is_test_file(path, name, ext):
                test_files.append(path)

            if self._is_documentation_file(path, name, ext):
                documentation_files.append(path)

            if self._is_dependency_manifest(path, name, ext):
                dependency_manifests.append(path)

            # Security-sensitive areas
            if self._is_security_sensitive(path, name, ext):
                security_sensitive_areas.append({
                    "file": path,
                    "type": "security_critical",
                    "severity": "high",
                    "reason": "File may contain authentication, authorization, or sensitive data"
                })

            # Important files for analysis
            if self._is_important_file(path, name, ext):
                important_files.append(path)

        return {
            "language_distribution": language_distribution,
            "framework_candidates": framework_candidates,
            "important_files": important_files,
            "security_sensitive_areas": security_sensitive_areas,
            "dependency_manifests": dependency_manifests,
            "entry_points": entry_points,
            "configuration_files": configuration_files,
            "test_files": test_files,
            "documentation_files": documentation_files,
            **flags
        }

    def _is_entry_point_file(self, path: str, name: str, ext: str) -> bool:
        """Check if file is likely an entry point."""
        name_lower = name.lower()
        ext_lower = ext.lower()

        entry_point_patterns = [
            'main.py', 'main.js', 'main.ts', 'main.jsx', 'main.tsx',
            'app.py', 'app.js', 'app.ts', 'app.jsx', 'app.tsx',
            'index.py', 'index.js', 'index.ts',
            'server.py', 'server.js', 'server.ts',
            'api.py', 'api.js', 'api.ts',
            '__main__.py'
        ]

        if name_lower in entry_point_patterns:
            return True

        # Check common entry point directory patterns
        path_parts = path.split('/')
        if len(path_parts) >= 2:
            parent_dir = path_parts[-2]
            if parent_dir in ['backend', 'src', 'app'] and name_lower in entry_point_patterns:
                return True

        return False

    def _is_configuration_file(self, path: str, name: str, ext: str) -> bool:
        """Check if file is likely a configuration file."""
        name_lower = name.lower()
        ext_lower = ext.lower()

        config_patterns = [
            'config.py', 'configuration.py', 'settings.py', 'appsettings.py',
            'django_settings.py', 'flask_app.py',
            '.env', '.env.local', '.env.development', '.env.production',
            'dockerfile', 'docker-compose.yml', 'docker-compose.yaml'
        ]

        config_extensions = ['json', 'yaml', 'yml', 'ini', 'cfg', 'conf', 'xml']

        if name_lower in config_patterns:
            return True

        if ext_lower in config_extensions:
            return True

        # Check common config directory patterns
        path_parts = path.split('/')
        if len(path_parts) >= 2:
            parent_dir = path_parts[-2]
            if parent_dir in ['config', 'conf', 'settings', 'envs', '.config']:
                return True

        return False

    def _is_test_file(self, path: str, name: str, ext: str) -> bool:
        """Check if file is likely a test file."""
        name_lower = name.lower()

        test_patterns = [
            'test_', '_test', 'tests', 'test.py', 'test.js', 'test.ts',
            'spec.js', 'spec.ts', 'spec.jsx', 'spec.tsx'
        ]

        # Check if file name matches test patterns
        for pattern in test_patterns:
            if pattern in name_lower:
                return True

        # Check test directory patterns
        path_parts = path.split('/')
        for part in path_parts:
            if part.lower() in ['test', 'tests', 'spec', 'specs']:
                return True

        return False

    def _is_documentation_file(self, path: str, name: str, ext: str) -> bool:
        """Check if file is likely documentation."""
        name_lower = name.lower()
        ext_lower = ext.lower()

        doc_extensions = ['md', 'rst', 'txt', 'adoc', 'mdwn', 'mkdn']

        # Check file extension
        if ext_lower in doc_extensions:
            return True

        # Check file name patterns
        doc_patterns = [
            'readme', 'license', 'changelog', 'contributing', 'authors',
            'history', 'news', 'todo', 'roadmap', 'documentation'
        ]

        for pattern in doc_patterns:
            if pattern in name_lower:
                return True

        return False

    def _is_dependency_manifest(self, path: str, name: str, ext: str) -> bool:
        """Check if file is a dependency management manifest."""
        name_lower = name.lower()

        dependency_manifests = [
            'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
            'requirements.txt', 'requirements-dev.txt', 'Pipfile', 'Pipfile.lock',
            'poetry.lock', 'poetry.toml', 'pyproject.toml', 'setup.py', 'setup.cfg',
            'Gemfile', 'Gemfile.lock', 'composer.json', 'composer.lock',
            'go.mod', 'go.sum', 'Cargo.toml', 'Cargo.lock', 'vcpkg.json',
            'conanfile.py', 'conanfile.txt', 'maven.xml', 'pom.xml', 'build.gradle',
            'build.gradle.kts'
        ]

        return name_lower in dependency_manifests

    def _is_security_sensitive(self, path: str, name: str, ext: str) -> bool:
        """Check if file is security-sensitive."""
        name_lower = name.lower()
        ext_lower = ext.lower()

        # Security-sensitive file patterns
        security_patterns = [
            'auth', 'authorization', 'permission', 'security', 'ssl', 'tls',
            'crypt', 'encrypt', 'decrypt', 'key', 'cert', 'password',
            'secret', 'token', 'credential', 'jwt', 'oauth', 'saml'
        ]

        security_extensions = ['pem', 'key', 'crt', 'cer', 'p12', 'pfx']

        # Check file name
        for pattern in security_patterns:
            if pattern in name_lower:
                return True

        # Check file extension
        if ext_lower in security_extensions:
            return True

        # Check security-related directory patterns
        path_parts = path.split('/')
        for part in path_parts:
            if part.lower() in ['auth', 'security', 'ssl', 'tls', 'crypto', 'keys', 'certs']:
                return True

        return False

    def _is_important_file(self, path: str, name: str, ext: str) -> bool:
        """Check if file is important for analysis."""
        name_lower = name.lower()
        ext_lower = ext.lower()

        # Important file patterns
        important_patterns = [
            'main', 'app', 'server', 'api', 'service', 'controller',
            'model', 'entity', 'repository', 'dao', 'manager'
        ]

        important_extensions = ['py', 'js', 'ts', 'java', 'cpp', 'c', 'php',
                               'go', 'rs', 'swift', 'kt', 'scala']

        # Check file name
        for pattern in important_patterns:
            if pattern in name_lower:
                return True

        # Check file extension for source code
        if ext_lower in important_extensions:
            return True

        # Check important directory patterns
        path_parts = path.split('/')
        if len(path_parts) >= 2:
            parent_dir = path_parts[-2]
            if parent_dir in ['backend', 'src', 'app', 'source', 'code']:
                return True

        return False

    @staticmethod
    def _get_timestamp() -> str:
        """Get current timestamp."""
        from datetime import datetime
        return datetime.now().isoformat()