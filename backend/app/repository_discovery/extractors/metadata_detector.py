"""
Metadata detector for SentinelAI repository discovery.
This module extracts and analyzes repository metadata.
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, List
from app.core.logger import get_logger

logger = get_logger(__name__)
class MetadataDetector:
    """Detects and extracts repository metadata."""

    def __init__(self, repository_path: str):
        self.repository_path = Path(repository_path)
        self.metadata = {}

    def detect_all(self) -> Dict[str, Any]:
        """Detect all available metadata."""
        logger.info(f"Detecting metadata for repository: {self.repository_path}")

        metadata = {
            "repository_info": self._detect_repository_info(),
            "file_analysis": self._analyze_files(),
            "structure_analysis": self._analyze_structure(),
            "content_indicators": self._detect_content_indicators(),
            "security_indicators": self._detect_security_indicators(),
            "technical_stack": self._detect_technical_stack(),
            "quality_metrics": self._calculate_quality_metrics(),
            "recommendations": self._generate_recommendations(),
        }

        self.metadata = metadata
        return metadata

    def _detect_repository_info(self) -> Dict[str, Any]:
        """Detect basic repository information."""
        repo_info = {
            "name": self.repository_path.name,
            "path": str(self.repository_path),
            "type": self._detect_repository_type(),
            "size": self._calculate_repository_size(),
            "file_count": self._count_files(),
            "language_count": self._count_languages(),
            "has_readme": self._has_readme(),
            "has_license": self._has_license(),
            "has_docker": self._has_docker_file(),
            "has_compose": self._has_docker_compose(),
            "has_package_json": self._has_package_json(),
            "has_requirements": self._has_requirements_txt(),
            "has_setup_py": self._has_setup_py(),
            "has_pyproject_toml": self._has_pyproject_toml(),
        }

        return repo_info

    def _detect_repository_type(self) -> str:
        """Detect the type of repository."""
        # Check for common repository indicators
        indicators = {
            'python': ['.py', '.pyw'],
            'javascript': ['.js', '.jsx', '.ts', '.tsx'],
            'java': ['.java', '.jsp'],
            'cpp': ['.cpp', '.cc', '.cxx', '.c', '.hpp', '.h'],
            'csharp': ['.cs'],
            'php': ['.php'],
            'ruby': ['.rb'],
            'go': ['.go'],
            'rust': ['.rs'],
            'swift': ['.swift'],
            'kotlin': ['.kt', '.kts'],
            'scala': ['.scala'],
            'r': ['.r'],
            'html': ['.html', '.htm'],
            'css': ['.css', '.scss', '.sass', '.less'],
            'ruby_on_rails': ['Gemfile', 'config.ru'],
            'node_js': ['package.json', 'gulpfile.js', 'webpack.config.js'],
            'django': ['manage.py', 'requirements.txt', 'wsgi.py'],
            'flask': ['app.py', 'requirements.txt', 'wsgi.py'],
            'spring': ['pom.xml', 'build.gradle', 'src/main/java'],
            'laravel': ['artisan', 'composer.json', 'app/Http'],
            'angular': ['angular.json', 'src/app'],
            'react': ['package.json', 'src/App.js', 'src/index.js'],
            'vue': ['vue.config.js', 'src/main.js'],
            'svelte': ['svelte.config.js', 'src/main.js'],
        }

        # Check for indicators
        detected_types = []
        for repo_type, type_indicators in indicators.items():
            for indicator in type_indicators:
                if (indicator.startswith('.') and any(
                        f.name == indicator[1:] or f.suffix == indicator
                        for f in self.repository_path.rglob('*') if f.is_file()
                )) or (not indicator.startswith('.') and
                        (self.repository_path / indicator).exists()):
                    detected_types.append(repo_type)
                    break

        return detected_types[0] if detected_types else "unknown"

    def _calculate_repository_size(self) -> Dict[str, Any]:
        """Calculate repository size metrics."""
        total_size = 0
        file_count = 0
        directory_count = 0

        for root, dirs, files in os.walk(self.repository_path):
            directory_count += len(dirs)
            for file in files:
                file_path = Path(root) / file
                try:
                    total_size += file_path.stat().st_size
                    file_count += 1
                except (OSError, IOError):
                    pass

        return {
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "file_count": file_count,
            "directory_count": directory_count,
            "average_file_size": round(total_size / max(file_count, 1), 2),
        }

    def _count_files(self) -> int:
        """Count total files in repository."""
        count = 0
        for root, dirs, files in os.walk(self.repository_path):
            count += len(files)
        return count

    def _count_languages(self) -> int:
        """Count detected programming languages."""
        languages = set()
        language_extensions = {
            '.py': 'python', '.pyw': 'python',
            '.js': 'javascript', '.jsx': 'javascript-react', '.ts': 'typescript',
            '.tsx': 'typescript-react', '.java': 'java', '.cpp': 'cpp',
            '.cc': 'cpp', '.cxx': 'cpp', '.c': 'c', '.h': 'c', '.hpp': 'cpp',
            '.cs': 'csharp', '.php': 'php', '.rb': 'ruby', '.go': 'go',
            '.rs': 'rust', '.swift': 'swift', '.kt': 'kotlin', '.scala': 'scala',
            '.r': 'r', '.sql': 'sql', '.html': 'html', '.css': 'css',
            '.scss': 'scss', '.sass': 'sass', '.less': 'less',
        }

        for root, dirs, files in os.walk(self.repository_path):
            for file in files:
                ext = Path(file).suffix.lower()
                if ext in language_extensions:
                    languages.add(language_extensions[ext])

        return len(languages)

    def _has_readme(self) -> bool:
        """Check if repository has README file."""
        readme_files = ['README.md', 'README.rst', 'README.txt', 'readme.md']
        for readme in readme_files:
            if (self.repository_path / readme).exists():
                return True
        return False

    def _has_license(self) -> bool:
        """Check if repository has license file."""
        license_files = ['LICENSE', 'LICENSE.md', 'LICENSE.txt',
                        'license', 'license.md', 'license.txt']
        for license_file in license_files:
            if (self.repository_path / license_file).exists():
                return True
        return False

    def _has_docker_file(self) -> bool:
        """Check if repository has Dockerfile."""
        return (self.repository_path / 'Dockerfile').exists()

    def _has_docker_compose(self) -> bool:
        """Check if repository has docker-compose files."""
        compose_files = ['docker-compose.yml', 'docker-compose.yaml',
                        'docker-compose.dev.yml', 'docker-compose.prod.yml']
        return any((self.repository_path / file).exists() for file in compose_files)

    def _has_package_json(self) -> bool:
        """Check if repository has package.json."""
        return (self.repository_path / 'package.json').exists()

    def _has_requirements_txt(self) -> bool:
        """Check if repository has requirements.txt."""
        return (self.repository_path / 'requirements.txt').exists()

    def _has_setup_py(self) -> bool:
        """Check if repository has setup.py."""
        return (self.repository_path / 'setup.py').exists()

    def _has_pyproject_toml(self) -> bool:
        """Check if repository has pyproject.toml."""
        return (self.repository_path / 'pyproject.toml').exists()

    def _analyze_files(self) -> Dict[str, Any]:
        """Analyze files in repository."""
        files_analysis = {
            "file_types": {},
            "file_sizes": {},
            "text_vs_binary": {"text": 0, "binary": 0},
            "by_extension": {},
            "largest_files": [],
            "smallest_files": [],
        }

        all_files = []
        extension_counts = {}
        binary_count = 0
        text_count = 0

        for root, dirs, files in os.walk(self.repository_path):
            for file in files:
                file_path = Path(root) / file
                rel_path = file_path.relative_to(self.repository_path)

                # Get file info
                try:
                    stat = file_path.stat()
                    size = stat.st_size
                    is_binary = self._is_binary_file(file_path)
                    ext = file_path.suffix.lower()[1:] if file_path.suffix else ''
                except (OSError, IOError):
                    continue

                # Update counts
                extension_counts[ext] = extension_counts.get(ext, 0) + 1
                if is_binary:
                    binary_count += 1
                else:
                    text_count += 1

                file_info = {
                    "path": str(rel_path).replace('\\', '/'),
                    "name": file,
                    "size": size,
                    "extension": ext,
                    "is_binary": is_binary,
                    "directory": str(rel_path.parent).replace('\\', '/'),
                }

                all_files.append(file_info)

        # Sort files by size
        all_files.sort(key=lambda x: x["size"], reverse=True)
        files_analysis["largest_files"] = all_files[:10]
        files_analysis["smallest_files"] = all_files[-10:]

        # Build file type analysis
        file_types = {}
        for file_info in all_files:
            file_type = file_info["extension"] or "no_extension"
            if file_type not in file_types:
                file_types[file_type] = {"count": 0, "total_size": 0}
            file_types[file_type]["count"] += 1
            file_types[file_type]["total_size"] += file_info["size"]

        files_analysis["file_types"] = file_types
        files_analysis["text_vs_binary"]["text"] = text_count
        files_analysis["text_vs_binary"]["binary"] = binary_count
        files_analysis["by_extension"] = extension_counts

        return files_analysis

    def _analyze_structure(self) -> Dict[str, Any]:
        """Analyze repository structure."""
        structure = {
            "depth": 0,
            "directory_count": 0,
            "max_depth_in_directory": {},
            "root_files": [],
            "has_subdirectories": False,
            "directory_structure": [],
        }

        max_depth = 0
        directory_structure = []

        for root, dirs, files in os.walk(self.repository_path):
            # Calculate depth
            rel_path = Path(root).relative_to(self.repository_path)
            depth = len(rel_path.parents) if rel_path != Path('.') else 0

            if depth > max_depth:
                max_depth = depth

            # Record directory structure
            directory_info = {
                "path": str(rel_path).replace('\\', '/'),
                "name": Path(root).name,
                "depth": depth,
                "file_count": len(files),
                "subdirectory_count": len(dirs),
                "is_hidden": Path(root).name.startswith('.'),
            }

            directory_structure.append(directory_info)

            # Track max depth per directory
            for dir_name in dirs:
                dir_path = Path(root) / dir_name
                dir_rel_path = dir_path.relative_to(self.repository_path)
                dir_depth = len(dir_rel_path.parents) if dir_rel_path != Path('.') else 0

                if dir_depth not in structure["max_depth_in_directory"]:
                    structure["max_depth_in_directory"][dir_depth] = 0
                structure["max_depth_in_directory"][dir_depth] += 1

        structure["depth"] = max_depth
        structure["directory_count"] = len(directory_structure) - 1  # Exclude root
        structure["has_subdirectories"] = structure["directory_count"] > 0
        structure["directory_structure"] = directory_structure

        # Get root files
        root_dir = self.repository_path
        structure["root_files"] = [
            {
                "name": file,
                "type": "file",
                "size": (root_dir / file).stat().st_size if (root_dir / file).exists() else 0,
            }
            for file in os.listdir(root_dir) if (root_dir / file).is_file()
        ]

        return structure

    def _detect_content_indicators(self) -> Dict[str, Any]:
        """Detect content indicators."""
        indicators = {
            "has_source_code": False,
            "has_tests": False,
            "has_documentation": False,
            "has_configuration": False,
            "has_database": False,
            "has_authentication": False,
            "has_api": False,
            "has_infrastructure": False,
            "has_cloud": False,
            "has_ci_cd": False,
        }

        # Check for various indicators by scanning files
        for root, dirs, files in os.walk(self.repository_path):
            for file in files:
                file_path = Path(root) / file
                rel_path = file_path.relative_to(self.repository_path)

                if self._is_source_code_file(file_path, rel_path):
                    indicators["has_source_code"] = True

                if self._is_test_file(file_path, rel_path):
                    indicators["has_tests"] = True

                if self._is_documentation_file(file_path, rel_path):
                    indicators["has_documentation"] = True

                if self._is_configuration_file(file_path, rel_path):
                    indicators["has_configuration"] = True

                if self._is_database_file(file_path, rel_path):
                    indicators["has_database"] = True

                if self._is_authentication_file(file_path, rel_path):
                    indicators["has_authentication"] = True

                if self._is_api_file(file_path, rel_path):
                    indicators["has_api"] = True

                if self._is_infrastructure_file(file_path, rel_path):
                    indicators["has_infrastructure"] = True

                if self._is_cloud_file(file_path, rel_path):
                    indicators["has_cloud"] = True

                if self._is_ci_cd_file(file_path, rel_path):
                    indicators["has_ci_cd"] = True

        return indicators

    def _detect_security_indicators(self) -> Dict[str, Any]:
        """Detect security-related indicators."""
        security_indicators = {
            "has_secrets": False,
            "has_api_keys": False,
            "has_certs": False,
            "has_tokens": False,
            "has_passwords": False,
            "has_security_config": False,
            "has_auth_infrastructure": False,
            "has_encryption": False,
        }

        # Check for security-related files
        for root, dirs, files in os.walk(self.repository_path):
            for file in files:
                file_path = Path(root) / file
                rel_path = file_path.relative_to(self.repository_path)

                if self._is_secret_file(file_path, rel_path):
                    security_indicators["has_secrets"] = True

                if self._is_api_key_file(file_path, rel_path):
                    security_indicators["has_api_keys"] = True

                if self._is_cert_file(file_path, rel_path):
                    security_indicators["has_certs"] = True

                if self._is_token_file(file_path, rel_path):
                    security_indicators["has_tokens"] = True

                if self._is_password_file(file_path, rel_path):
                    security_indicators["has_passwords"] = True

                if self._is_security_config_file(file_path, rel_path):
                    security_indicators["has_security_config"] = True

                if self._is_auth_infrastructure_file(file_path, rel_path):
                    security_indicators["has_auth_infrastructure"] = True

                if self._is_encryption_file(file_path, rel_path):
                    security_indicators["has_encryption"] = True

        return security_indicators

    def _detect_technical_stack(self) -> Dict[str, Any]:
        """Detect technical stack."""
        stack = {
            "languages": [],
            "frameworks": [],
            "databases": [],
            "web_servers": [],
            "build_tools": [],
            "deployment_methods": [],
            "monitoring_tools": [],
        }

        # Analyze files to detect technical stack
        for root, dirs, files in os.walk(self.repository_path):
            for file in files:
                file_path = Path(root) / file
                rel_path = file_path.relative_to(self.repository_path)

                # Detect languages
                if self._is_python_file(file_path, rel_path):
                    stack["languages"].append("python")
                elif self._is_javascript_file(file_path, rel_path):
                    stack["languages"].append("javascript")
                elif self._is_java_file(file_path, rel_path):
                    stack["languages"].append("java")
                elif self._is_cpp_file(file_path, rel_path):
                    stack["languages"].append("cpp")
                elif self._is_csharp_file(file_path, rel_path):
                    stack["languages"].append("csharp")
                elif self._is_php_file(file_path, rel_path):
                    stack["languages"].append("php")
                elif self._is_ruby_file(file_path, rel_path):
                    stack["languages"].append("ruby")
                elif self._is_go_file(file_path, rel_path):
                    stack["languages"].append("go")
                elif self._is_rust_file(file_path, rel_path):
                    stack["languages"].append("rust")

                # Detect frameworks
                if self._is_django_file(file_path, rel_path):
                    stack["frameworks"].append("django")
                elif self._is_flask_file(file_path, rel_path):
                    stack["frameworks"].append("flask")
                elif self._is_rails_file(file_path, rel_path):
                    stack["frameworks"].append("ruby_on_rails")
                elif self._is_laravel_file(file_path, rel_path):
                    stack["frameworks"].append("laravel")
                elif self._is_spring_file(file_path, rel_path):
                    stack["frameworks"].append("spring")

                # Detect databases
                if self._is_sql_file(file_path, rel_path):
                    stack["databases"].append("sql")
                elif self._is_mongo_file(file_path, rel_path):
                    stack["databases"].append("mongodb")
                elif self._is_postgres_file(file_path, rel_path):
                    stack["databases"].append("postgresql")
                elif self._is_mysql_file(file_path, rel_path):
                    stack["databases"].append("mysql")

        # Remove duplicates and convert to sets
        for key in stack:
            stack[key] = list(set(stack[key]))

        return stack

    def _calculate_quality_metrics(self) -> Dict[str, Any]:
        """Calculate repository quality metrics."""
        metrics = {
            "complexity_score": 0.0,
            "maintainability_score": 0.0,
            "documentation_score": 0.0,
            "security_score": 0.0,
            "test_coverage_indicator": 0.0,
            "overall_health": "unknown",
        }

        # Calculate various metrics
        total_files = self._count_files()
        has_readme = self._has_readme()
        has_license = self._has_license()
        has_tests = self._count_test_files() > 0
        has_documentation = self._count_documentation_files() > 0

        # Complexity score (higher = more complex)
        complexity_score = 0
        if total_files > 100:
            complexity_score += 3
        elif total_files > 50:
            complexity_score += 2
        elif total_files > 10:
            complexity_score += 1

        if self._count_languages() > 3:
            complexity_score += 2
        elif self._count_languages() > 1:
            complexity_score += 1

        metrics["complexity_score"] = min(complexity_score, 5.0)

        # Maintainability score (higher = more maintainable)
        maintainability_score = 0
        if has_readme:
            maintainability_score += 2
        if has_license:
            maintainability_score += 1
        if has_tests:
            maintainability_score += 3
        if has_documentation:
            maintainability_score += 2

        metrics["maintainability_score"] = min(maintainability_score, 5.0)

        # Documentation score
        documentation_score = 0
        if has_readme:
            documentation_score += 3
        documentation_score += self._count_documentation_files() * 0.5

        metrics["documentation_score"] = min(documentation_score, 5.0)

        # Overall health
        total_score = metrics["complexity_score"] + metrics["maintainability_score"] + metrics["documentation_score"]
        if total_score >= 8:
            metrics["overall_health"] = "excellent"
        elif total_score >= 6:
            metrics["overall_health"] = "good"
        elif total_score >= 4:
            metrics["overall_health"] = "fair"
        elif total_score >= 2:
            metrics["overall_health"] = "poor"
        else:
            metrics["overall_health"] = "critical"

        return metrics

    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on analysis."""
        recommendations = []

        # Generate recommendations based on findings
        if not self._has_readme():
            recommendations.append("Add a README file to improve documentation")

        if not self._has_license():
            recommendations.append("Add a license file to clarify usage terms")

        if self._count_test_files() == 0:
            recommendations.append("Add unit tests to improve code quality")

        if not self._has_documentation():
            recommendations.append("Add documentation for better maintainability")

        if self._has_security_issues():
            recommendations.append("Review and address security vulnerabilities")

        if self._count_files() > 1000:
            recommendations.append("Consider organizing large repositories with better structure")

        return recommendations

    def _is_binary_file(self, file_path: Path) -> bool:
        """Check if file is binary."""
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

        return False

    def _is_source_code_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is source code."""
        source_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.cpp', '.cc', '.cxx',
            '.c', '.h', '.hpp', '.cs', '.php', '.rb', '.go', '.rs', '.swift',
            '.kt', '.scala', '.r', '.sql', '.html', '.css', '.scss', '.sass',
            '.less', '.md', '.json', '.xml', '.yaml', '.yml', '.toml', '.ini'
        }

        ext = file_path.suffix.lower()
        return ext in source_extensions

    def _is_test_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is a test file."""
        name = file_path.name.lower()

        test_patterns = ['test_', '_test', 'tests', 'spec.', 'test.py', 'test.js']

        for pattern in test_patterns:
            if pattern in name:
                return True

        return False

    def _is_documentation_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is documentation."""
        ext = file_path.suffix.lower()
        name = file_path.name.lower()

        doc_extensions = ['.md', '.rst', '.txt', '.adoc']
        doc_patterns = ['readme', 'license', 'changelog', 'contributing', 'authors']

        if ext in doc_extensions:
            return True

        for pattern in doc_patterns:
            if pattern in name:
                return True

        return False

    def _is_configuration_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is configuration."""
        name = file_path.name.lower()

        config_patterns = ['config', 'settings', 'env', 'dockerfile', 'compose']

        for pattern in config_patterns:
            if pattern in name:
                return True

        return False

    def _is_database_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is database-related."""
        ext = file_path.suffix.lower()
        name = file_path.name.lower()

        db_extensions = ['.sql', '.db', '.sqlite', '.mdb', '.accdb']
        db_patterns = ['schema', 'migration', 'seed', 'database']

        if ext in db_extensions:
            return True

        for pattern in db_patterns:
            if pattern in name:
                return True

        return False

    def _is_authentication_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is authentication-related."""
        name = file_path.name.lower()

        auth_patterns = ['auth', 'login', 'register', 'session', 'token', 'jwt', 'oauth']

        for pattern in auth_patterns:
            if pattern in name:
                return True

        return False

    def _is_api_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is API-related."""
        name = file_path.name.lower()

        api_patterns = ['api', 'endpoint', 'route', 'controller', 'service']

        for pattern in api_patterns:
            if pattern in name:
                return True

        return False

    def _is_infrastructure_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is infrastructure-related."""
        name = file_path.name.lower()

        infra_patterns = ['terraform', 'kubernetes', 'dockerfile', 'compose', 'helm']

        for pattern in infra_patterns:
            if pattern in name:
                return True

        return False

    def _is_cloud_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is cloud-related."""
        name = file_path.name.lower()

        cloud_patterns = ['aws', 'azure', 'gcp', 'cloud', 'lambda', 'functions']

        for pattern in cloud_patterns:
            if pattern in name:
                return True

        return False

    def _is_ci_cd_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is CI/CD-related."""
        name = file_path.name.lower()

        cidir_patterns = ['.github/workflows', '.gitlab-ci.yml', '.travis.yml',
                         ' Jenkinsfile', 'azure-pipelines.yml', 'circleci.yml']

        if any(pattern in name for pattern in cidir_patterns):
            return True

        return False

    def _is_secret_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file contains secrets."""
        name = file_path.name.lower()

        secret_patterns = ['.env', 'credentials', 'secrets', 'passwords', 'keys']

        for pattern in secret_patterns:
            if pattern in name:
                return True

        return False

    def _is_api_key_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file contains API keys."""
        name = file_path.name.lower()

        key_patterns = ['api_key', 'apikey', 'access_key', 'secret_key', 'private_key']

        for pattern in key_patterns:
            if pattern in name:
                return True

        return False

    def _is_cert_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file contains certificates."""
        ext = file_path.suffix.lower()

        cert_extensions = ['.pem', '.crt', '.cer', '.p12', '.pfx']

        return ext in cert_extensions

    def _is_token_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file contains tokens."""
        name = file_path.name.lower()

        token_patterns = ['token', 'jwt', 'bearer', 'session']

        for pattern in token_patterns:
            if pattern in name:
                return True

        return False

    def _is_password_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file contains passwords."""
        name = file_path.name.lower()

        password_patterns = ['password', 'passwd', 'pwd', 'secret']

        for pattern in password_patterns:
            if pattern in name:
                return True

        return False

    def _is_security_config_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is security configuration."""
        name = file_path.name.lower()

        security_patterns = ['security', 'ssl', 'tls', 'encryption', 'firewall']

        for pattern in security_patterns:
            if pattern in name:
                return True

        return False

    def _is_auth_infrastructure_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is authentication infrastructure."""
        name = file_path.name.lower()

        auth_infra_patterns = ['auth', 'oauth', 'saml', 'ldap', 'ldap', 'rbac']

        for pattern in auth_infra_patterns:
            if pattern in name:
                return True

        return False

    def _is_encryption_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is encryption-related."""
        name = file_path.name.lower()

        encryption_patterns = ['encrypt', 'decrypt', 'cipher', 'hash', 'salt']

        for pattern in encryption_patterns:
            if pattern in name:
                return True

        return False

    # Language detection methods
    def _is_python_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is Python."""
        ext = file_path.suffix.lower()
        return ext == '.py'

    def _is_javascript_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is JavaScript."""
        ext = file_path.suffix.lower()
        return ext in ['.js', '.jsx']

    def _is_typescript_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is TypeScript."""
        ext = file_path.suffix.lower()
        return ext in ['.ts', '.tsx']

    def _is_java_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is Java."""
        ext = file_path.suffix.lower()
        return ext == '.java'

    def _is_cpp_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is C++."""
        ext = file_path.suffix.lower()
        return ext in ['.cpp', '.cc', '.cxx', '.c', '.hpp', '.h']

    def _is_csharp_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is C#."""
        ext = file_path.suffix.lower()
        return ext == '.cs'

    def _is_php_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is PHP."""
        ext = file_path.suffix.lower()
        return ext == '.php'

    def _is_ruby_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is Ruby."""
        ext = file_path.suffix.lower()
        return ext == '.rb'

    def _is_go_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is Go."""
        ext = file_path.suffix.lower()
        return ext == '.go'

    def _is_rust_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is Rust."""
        ext = file_path.suffix.lower()
        return ext == '.rs'

    # Framework detection methods
    def _is_django_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is Django-related."""
        name = file_path.name.lower()
        return 'django' in name or (self.repository_path / 'manage.py').exists()

    def _is_flask_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is Flask-related."""
        name = file_path.name.lower()
        return 'flask' in name or name == 'app.py'

    def _is_rails_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is Rails-related."""
        return (self.repository_path / 'Gemfile').exists() or 'rails' in name

    def _is_laravel_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is Laravel-related."""
        return (self.repository_path / 'artisan').exists() or 'laravel' in name

    def _is_spring_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is Spring-related."""
        return (self.repository_path / 'pom.xml').exists() or 'spring' in name

    # Database detection methods
    def _is_sql_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is SQL."""
        ext = file_path.suffix.lower()
        return ext == '.sql'

    def _is_mongo_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is MongoDB-related."""
        name = file_path.name.lower()
        return 'mongo' in name or 'mongodb' in name

    def _is_postgres_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is PostgreSQL-related."""
        name = file_path.name.lower()
        return 'postgres' in name or 'pg_' in name

    def _is_mysql_file(self, file_path: Path, rel_path: Path) -> bool:
        """Check if file is MySQL-related."""
        name = file_path.name.lower()
        return 'mysql' in name or 'my_' in name

    # File counting methods
    def _count_test_files(self) -> int:
        """Count test files."""
        count = 0
        for root, dirs, files in os.walk(self.repository_path):
            for file in files:
                file_path = Path(root) / file
                rel_path = file_path.relative_to(self.repository_path)
                if self._is_test_file(file_path, rel_path):
                    count += 1
        return count

    def _count_documentation_files(self) -> int:
        """Count documentation files."""
        count = 0
        for root, dirs, files in os.walk(self.repository_path):
            for file in files:
                file_path = Path(root) / file
                rel_path = file_path.relative_to(self.repository_path)
                if self._is_documentation_file(file_path, rel_path):
                    count += 1
        return count

    def _has_documentation(self) -> bool:
        """Check if repository has documentation."""
        return self._count_documentation_files() > 0

    def _has_security_issues(self) -> bool:
        """Check if repository has security issues."""
        # Simple heuristic for security issues
        for root, dirs, files in os.walk(self.repository_path):
            for file in files:
                file_path = Path(root) / file
                rel_path = file_path.relative_to(self.repository_path)
                if (self._is_secret_file(file_path, rel_path) or
                    self._is_api_key_file(file_path, rel_path) or
                    self._is_token_file(file_path, rel_path)):
                    return True
        return False