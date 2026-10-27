"""
Language detector for SentinelAI repository discovery.
This module detects and analyzes programming languages in repositories.
"""

import os
from pathlib import Path
from typing import Dict, Any, List, Set
from app.core.logger import get_logger

logger = get_logger(__name__)
class LanguageDetector:
    """Detects and analyzes programming languages in repositories."""

    def __init__(self, repository_path: str):
        self.repository_path = Path(repository_path)
        self.language_stats = {}
        self.file_associations = {}

    def detect_all_languages(self) -> Dict[str, Any]:
        """Detect all programming languages in the repository."""
        logger.info(f"Detecting languages for repository: {self.repository_path}")

        language_stats = self._collect_language_statistics()
        file_associations = self._analyze_file_associations()
        language_confidence = self._calculate_language_confidence(language_stats)
        language_trends = self._analyze_language_trends(language_stats)
        ecosystem_analysis = self._analyze_ecosystem(language_stats)

        result = {
            "primary_language": self._get_primary_language(language_stats),
            "secondary_languages": self._get_secondary_languages(language_stats),
            "language_statistics": language_stats,
            "file_associations": file_associations,
            "language_confidence_scores": language_confidence,
            "language_trends": language_trends,
            "ecosystem_analysis": ecosystem_analysis,
            "complexity_metrics": self._calculate_complexity_metrics(language_stats),
            "recommendations": self._generate_language_recommendations(language_stats),
        }

        self.language_stats = language_stats
        self.file_associations = file_associations

        return result

    def _collect_language_statistics(self) -> Dict[str, Any]:
        """Collect statistics for each detected language."""
        language_stats = {}
        total_files = 0

        for root, dirs, files in os.walk(self.repository_path):
            # Skip hidden directories and build artifacts
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in
                      ['__pycache__', '.git', '.venv', 'venv', '.env', 'node_modules',
                       'build', 'dist', '.pytest_cache', '.mypy_cache', 'target', 'bin',
                       'obj', '.DS_Store', 'Thumbs.db']]

            for file in files:
                file_path = Path(root) / file
                rel_path = file_path.relative_to(self.repository_path)

                # Detect language
                language = self._detect_language_from_file(file_path, rel_path)
                if language:
                    if language not in language_stats:
                        language_stats[language] = {
                            "file_count": 0,
                            "total_size": 0,
                            "average_size": 0,
                            "extension_count": {},
                            "file_types": {},
                            "directories": set(),
                            "complexity": 0,
                            "quality_score": 0,
                        }

                    language_info = language_stats[language]
                    language_info["file_count"] += 1

                    try:
                        file_size = file_path.stat().st_size
                        language_info["total_size"] += file_size
                    except (OSError, IOError):
                        file_size = 0

                    # Track file extension
                    ext = file_path.suffix.lower()
                    if ext:
                        ext_key = ext[1:] if len(ext) > 1 else ext
                        language_info["extension_count"][ext_key] = \
                            language_info["extension_count"].get(ext_key, 0) + 1

                    # Track file type
                    file_type = self._categorize_file_type(file_path, rel_path)
                    language_info["file_types"][file_type] = \
                        language_info["file_types"].get(file_type, 0) + 1

                    # Track directory
                    language_info["directories"].add(str(rel_path.parent).replace('\\', '/'))

                    # Calculate complexity
                    language_info["complexity"] += self._calculate_file_complexity(file_path, rel_path)

                    total_files += 1

        # Calculate averages and finalize statistics
        for language_info in language_stats.values():
            if language_info["file_count"] > 0:
                language_info["average_size"] = \
                    language_info["total_size"] / language_info["file_count"]

            # Convert directories to list
            language_info["directories"] = list(language_info["directories"])

            # Calculate quality score
            language_info["quality_score"] = self._calculate_language_quality_score(language_info)

        return language_stats

    def _detect_language_from_file(self, file_path: Path, rel_path: Path) -> str:
        """Detect programming language from file."""
        # Use file extension as primary indicator
        ext = file_path.suffix.lower()

        # Common language extensions
        language_extensions = {
            # Python
            '.py': 'python',
            '.pyw': 'python',
            # JavaScript
            '.js': 'javascript',
            '.jsx': 'javascript-react',
            '.mjs': 'javascript-esm',
            '.cjs': 'javascript-commonjs',
            # TypeScript
            '.ts': 'typescript',
            '.tsx': 'typescript-react',
            '.mts': 'typescript-esm',
            '.cts': 'typescript-commonjs',
            # Java
            '.java': 'java',
            '.jsp': 'java-server-pages',
            '.jpr': 'java-project',
            # C/C++
            '.cpp': 'cpp',
            '.cc': 'cpp',
            '.cxx': 'cpp',
            '.c': 'c',
            '.h': 'c-header',
            '.hpp': 'cpp-header',
            '.hxx': 'cpp-header',
            '.hh': 'cpp-header',
            # C#
            '.cs': 'csharp',
            '.csx': 'csharp-script',
            # PHP
            '.php': 'php',
            '.php3': 'php',
            '.php4': 'php',
            '.php5': 'php',
            # Ruby
            '.rb': 'ruby',
            '.rbw': 'ruby',
            '.gem': 'ruby-gem',
            # Go
            '.go': 'go',
            # Rust
            '.rs': 'rust',
            '.rlib': 'rust-library',
            # Swift
            '.swift': 'swift',
            # Kotlin
            '.kt': 'kotlin',
            '.kts': 'kotlin-script',
            # Scala
            '.scala': 'scala',
            '.sc': 'scala-script',
            # R
            '.r': 'r',
            '.R': 'r',
            '.rh': 'r-header',
            # SQL
            '.sql': 'sql',
            '.ddl': 'sql-ddl',
            '.dml': 'sql-dml',
            # HTML
            '.html': 'html',
            '.htm': 'html',
            '.xhtml': 'xhtml',
            # CSS
            '.css': 'css',
            '.scss': 'scss',
            '.sass': 'sass',
            '.less': 'less',
            '.styl': 'stylus',
            # Shell
            '.sh': 'bash',
            '.bash': 'bash',
            '.zsh': 'zsh',
            '.fish': 'fish',
            '.ps1': 'powershell',
            # Python variants
            '.pyi': 'python-stubs',
            '.pyx': 'cython',
            '.pxd': 'cython-definitions',
            # Documentation
            '.md': 'markdown',
            '.rst': 'restructuredtext',
            '.txt': 'text',
            '.mdwn': 'markdown-down',
            '.mkdn': 'markdown-kdenotes',
            # Configuration
            '.json': 'json',
            '.xml': 'xml',
            '.yaml': 'yaml',
            '.yml': 'yaml',
            '.toml': 'toml',
            '.ini': 'ini',
            '.cfg': 'ini',
            '.conf': 'ini',
            # Archive
            '.zip': 'archive',
            '.tar': 'archive-tar',
            '.gz': 'archive-gzip',
            '.bz2': 'archive-bzip2',
            '.xz': 'archive-xz',
            '.7z': 'archive-7zip',
        }

        # Get language from extension
        language = language_extensions.get(ext)

        # Fallback to filename-based detection
        if not language:
            language = self._detect_language_from_filename(file_path.name)

        return language

    def _detect_language_from_filename(self, filename: str) -> str:
        """Detect language from filename when extension is not available."""
        filename_lower = filename.lower()

        # Special files
        if filename_lower in ['makefile', 'gnumakefile', 'cmakefile']:
            return 'makefile'
        if filename_lower == 'rakefile':
            return 'ruby-rakefile'
        if filename_lower == 'go.mod':
            return 'go-mod'
        if filename_lower == 'go.sum':
            return 'go-sum'
        if filename_lower == 'cargo.toml':
            return 'rust-cargo'
        if filename_lower == 'cargo.lock':
            return 'rust-cargo-lock'
        if filename_lower == 'package.json':
            return 'node-package'
        if filename_lower == 'yarn.lock':
            return 'yarn-lock'
        if filename_lower == 'pnpm-lock.yaml':
            return 'pnpm-lock'
        if filename_lower == 'pyproject.toml':
            return 'python-pyproject'
        if filename_lower == 'setup.py':
            return 'python-setup'
        if filename_lower == 'requirements.txt':
            return 'python-requirements'
        if filename_lower == 'Pipfile':
            return 'python-pipfile'
        if filename_lower == 'poetry.lock':
            return 'python-poetry'
        if filename_lower == 'Gemfile':
            return 'ruby-gemfile'
        if filename_lower == 'composer.json':
            return 'php-composer'
        if filename_lower == 'pom.xml':
            return 'java-maven'
        if filename_lower == 'build.gradle':
            return 'java-gradle'
        if filename_lower == 'build.gradle.kts':
            return 'java-gradle-kts'
        if filename_lower == 'dockerfile':
            return 'dockerfile'
        if filename_lower == 'docker-compose.yml' or filename_lower == 'docker-compose.yaml':
            return 'docker-compose'
        if filename_lower == 'vagrantfile':
            return 'vagrant'
        if filename_lower == 'jenkinsfile':
            return 'jenkins'
        if filename_lower == '.gitignore':
            return 'gitignore'
        if filename_lower == '.dockerignore':
            return 'dockerignore'
        if filename_lower == '.env':
            return 'environment-variables'
        if filename_lower == 'readme.md' or filename_lower == 'readme.rst':
            return 'documentation'
        if filename_lower == 'license':
            return 'license'
        if filename_lower == 'changelog':
            return 'changelog'
        if filename_lower == 'contributing':
            return 'contributing-guide'
        if filename_lower == 'authors':
            return 'authors-file'
        if filename_lower == 'history':
            return 'history'
        if filename_lower == 'news':
            return 'news'
        if filename_lower == 'todo':
            return 'todo-list'
        if filename_lower == 'roadmap':
            return 'roadmap'

        # Framework-specific files
        if filename_lower.endswith('.py') and 'test' in filename_lower:
            return 'python-test'
        if filename_lower.endswith('.js') and 'test' in filename_lower:
            return 'javascript-test'
        if filename_lower.endswith('.ts') and 'test' in filename_lower:
            return 'typescript-test'
        if filename_lower.endswith('.spec.js') or filename_lower.endswith('.spec.ts'):
            return 'test-specification'
        if filename_lower.endswith('.feature'):
            return 'cucumber-feature'
        if filename_lower.endswith('.sql') and ('test' in filename_lower or 'test_' in filename_lower):
            return 'sql-test'
        if filename_lower.endswith('.sh') and ('test' in filename_lower or 'test_' in filename_lower):
            return 'bash-test'
        if filename_lower.endswith('.py') and ('__init__' in filename_lower):
            return 'python-package-init'
        if filename_lower.endswith('.js') and ('__init__' in filename_lower):
            return 'javascript-package-init'

        return 'unknown'

    def _categorize_file_type(self, file_path: Path, rel_path: Path) -> str:
        """Categorize file type for analysis."""
        filename = file_path.name.lower()
        ext = file_path.suffix.lower()

        # Source code files
        if ext in ['.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.cpp', '.cc',
                  '.cxx', '.c', '.h', '.hpp', '.cs', '.php', '.rb', '.go',
                  '.rs', '.swift', '.kt', '.scala', '.r', '.sql', '.html',
                  '.css', '.scss', '.sass', '.less']:
            return 'source_code'

        # Configuration files
        if ext in ['.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf', '.xml']:
            return 'configuration'

        # Documentation files
        if ext in ['.md', '.rst', '.txt', '.mdwn', '.mkdn']:
            return 'documentation'

        # Script files
        if ext in ['.sh', '.bash', '.zsh', '.fish', '.ps1']:
            return 'script'

        # Binary/executable files
        if ext in ['.exe', '.dll', '.so', '.dylib', '.bin', '.pyc', '.pyd',
                  '.dat', '.db', '.jpg', '.jpeg', '.png', '.gif', '.bmp',
                  '.ico', '.svg', '.webp', '.mp4', '.avi', '.mov', '.wmv',
                  '.flv', '.mp3', '.wav', '.flac', '.aac', '.ogg', '.zip',
                  '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.pdf', '.doc',
                  '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods',
                  '.odg', '.odp', 'ttf', '.otf', '.woff', '.woff2']:
            return 'binary'

        # Test files
        test_patterns = ['test_', '_test', 'tests', 'spec.', 'test.py', 'test.js']
        if any(pattern in filename for pattern in test_patterns):
            return 'test'

        # Special files
        special_files = ['makefile', 'rakefile', 'go.mod', 'go.sum', 'package.json',
                        'yarn.lock', 'pnpm-lock.yaml', 'pyproject.toml', 'setup.py',
                        'requirements.txt', 'Pipfile', 'poetry.lock', 'Gemfile',
                        'composer.json', 'pom.xml', 'build.gradle', 'dockerfile',
                        'docker-compose.yml', 'docker-compose.yaml', 'vagrantfile',
                        'jenkinsfile', '.gitignore', '.dockerignore', '.env',
                        'readme.md', 'readme.rst', 'license', 'changelog',
                        'contributing', 'authors', 'history', 'news', 'todo',
                        'roadmap']

        if filename in special_files:
            return 'special'

        # Archive files
        archive_extensions = ['.zip', '.tar', '.gz', '.bz2', '.xz', '.7z']
        if ext in archive_extensions:
            return 'archive'

        return 'other'

    def _calculate_file_complexity(self, file_path: Path, rel_path: Path) -> float:
        """Calculate complexity score for a file."""
        complexity = 0.0

        # Get file content for analysis
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Calculate based on various factors
            lines = content.split('\n')
            non_empty_lines = [line for line in lines if line.strip()]

            # Line count complexity
            complexity += min(len(non_empty_lines) / 10.0, 5.0)

            # Comment density
            comment_lines = self._count_comment_lines(content)
            if non_empty_lines:
                comment_ratio = comment_lines / len(non_empty_lines)
                complexity += comment_ratio * 2.0

            # Import/dependency complexity
            import_count = self._count_imports(content)
            complexity += min(import_count / 5.0, 3.0)

            # Function/method count
            func_count = self._count_functions(content)
            complexity += min(func_count / 10.0, 3.0)

            # Class count
            class_count = self._count_classes(content)
            complexity += min(class_count / 5.0, 2.0)

            # Ternary operator usage
            ternary_count = content.count('?') + content.count('?:')
            complexity += min(ternary_count / 5.0, 1.0)

            # Lambda/function expression usage
            lambda_count = content.count('lambda ') + content.count('=>')
            complexity += min(lambda_count / 5.0, 1.0)

        except (OSError, IOError, UnicodeDecodeError):
            # If we can't read the file, assign basic complexity
            pass

        return complexity

    def _count_comment_lines(self, content: str) -> int:
        """Count comment lines in content."""
        lines = content.split('\n')
        comment_lines = 0

        for line in lines:
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//') or \
               stripped.startswith('/*') or stripped.startswith('*') or \
               stripped.startswith('<!--'):
                comment_lines += 1
            elif '"""' in stripped or "'''" in stripped or '""""' in stripped:
                comment_lines += 1

        return comment_lines

    def _count_imports(self, content: str) -> int:
        """Count import statements in content."""
        lines = content.split('\n')
        import_count = 0

        for line in lines:
            stripped = line.strip()
            if (stripped.startswith('import ') or stripped.startswith('from ') or
                stripped.startswith('use ') or stripped.startswith('require(') or
                stripped.startswith('from @angular') or stripped.startswith('import {')):
                import_count += 1

        return import_count

    def _count_functions(self, content: str) -> int:
        """Count function definitions in content."""
        lines = content.split('\n')
        func_count = 0

        for line in lines:
            stripped = line.strip()
            if (stripped.startswith('def ') or stripped.startswith('function ') or
                stripped.startswith('const ') and '=>' in line or
                stripped.startswith('let ') and '=>' in line or
                stripped.startswith('var ') and '=>' in line or
                stripped.startswith('async function') or
                stripped.startswith('async const') and '=>' in line):
                func_count += 1

        return func_count

    def _count_classes(self, content: str) -> int:
        """Count class definitions in content."""
        lines = content.split('\n')
        class_count = 0

        for line in lines:
            stripped = line.strip()
            if (stripped.startswith('class ') or stripped.startswith('interface ') or
                stripped.startswith('trait ') or stripped.startswith('data class ') or
                stripped.startswith('abstract class') or stripped.startswith('sealed class')):
                class_count += 1

        return class_count

    def _calculate_language_quality_score(self, language_info: Dict[str, Any]) -> float:
        """Calculate quality score for a language."""
        score = 0.0

        # File count (balanced score)
        file_count = language_info["file_count"]
        if file_count > 0:
            score += min(file_count / 100.0, 2.0)

        # Size consideration
        total_size = language_info["total_size"]
        if total_size > 0:
            size_mb = total_size / (1024 * 1024)
            score += min(size_mb / 10.0, 1.0)

        # Diversity score (number of unique extensions)
        extension_count = len(language_info["extension_count"])
        score += min(extension_count * 0.5, 2.0)

        # Directory count
        directory_count = len(language_info["directories"])
        score += min(directory_count * 0.3, 1.0)

        # Complexity consideration
        complexity = language_info["complexity"]
        score += min(complexity / 5.0, 2.0)

        return min(score, 5.0)

    def _analyze_file_associations(self) -> Dict[str, Any]:
        """Analyze file associations and relationships."""
        associations = {
            "entry_points": [],
            "configuration_files": [],
            "test_files": [],
            "documentation_files": [],
            "dependency_files": [],
            "framework_files": [],
            "language_files": {},
            "directory_analysis": {},
            "file_type_distribution": {},
            "size_distribution": {},
        }

        # This would be populated by analyzing the repository structure
        # For now, return empty structure

        return associations

    def _calculate_language_confidence(self, language_stats: Dict[str, Any]) -> Dict[str, float]:
        """Calculate confidence scores for language detection."""
        confidence_scores = {}

        if not language_stats:
            return confidence_scores

        # Calculate based on various factors
        total_files = sum(stats["file_count"] for stats in language_stats.values())

        for language, stats in language_stats.items():
            confidence = 0.0

            # File count confidence
            file_confidence = min(stats["file_count"] / 10.0, 1.0)
            confidence += file_confidence

            # Extension diversity confidence
            ext_count = len(stats["extension_count"])
            ext_confidence = min(ext_count / 3.0, 1.0)
            confidence += ext_confidence

            # Directory diversity confidence
            dir_count = len(stats["directories"])
            dir_confidence = min(dir_count / 5.0, 1.0)
            confidence += dir_confidence

            # Complexity confidence
            complexity = stats["complexity"]
            complexity_confidence = min(complexity / 5.0, 1.0)
            confidence += complexity_confidence

            confidence_scores[language] = min(confidence, 1.0)

        return confidence_scores

    def _analyze_language_trends(self, language_stats: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze trends in language usage."""
        if not language_stats:
            return {}

        # Sort languages by file count
        sorted_languages = sorted(
            language_stats.items(),
            key=lambda x: x[1]["file_count"],
            reverse=True
        )

        # Calculate trends
        trends = {
            "dominant_language": sorted_languages[0][0] if sorted_languages else None,
            "language_ranking": [lang for lang, _ in sorted_languages],
            "total_languages": len(language_stats),
            "language_distribution": {},
            "growth_indicators": [],
            "decline_indicators": [],
        }

        # Calculate distribution percentages
        total_files = sum(stats["file_count"] for stats in language_stats.values())
        for language, stats in language_stats.items():
            percentage = (stats["file_count"] / total_files) * 100 if total_files > 0 else 0
            trends["language_distribution"][language] = {
                "file_count": stats["file_count"],
                "percentage": round(percentage, 2),
                "average_size": stats["average_size"],
                "quality_score": stats["quality_score"],
            }

        return trends

    def _analyze_ecosystem(self, language_stats: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze technology ecosystem."""
        ecosystem = {
            "frontend": [],
            "backend": [],
            "database": [],
            "devops": [],
            "mobile": [],
            "desktop": [],
            "embedded": [],
            "data_science": [],
            "artificial_intelligence": [],
        }

        # Analyze based on file patterns
        for language in language_stats.keys():
            if language in ['javascript', 'typescript', 'html', 'css']:
                ecosystem["frontend"].append(language)
            elif language in ['python', 'java', 'csharp', 'php', 'ruby', 'go', 'rust']:
                ecosystem["backend"].append(language)
            elif language in ['sql']:
                ecosystem["database"].append(language)
            elif language in ['dockerfile', 'bash', 'shell']:
                ecosystem["devops"].append(language)
            elif language in ['swift', 'kotlin']:
                ecosystem["mobile"].append(language)
            elif language in ['c', 'cpp']:
                ecosystem["desktop"].append(language)
            elif language in ['r', 'python']:
                ecosystem["data_science"].append(language)
            elif language in ['python', 'javascript']:
                ecosystem["artificial_intelligence"].append(language)

        return ecosystem

    def _calculate_complexity_metrics(self, language_stats: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate complexity metrics."""
        metrics = {
            "overall_complexity": 0.0,
            "language_diversity": len(language_stats),
            "file_size_variance": 0.0,
            "structural_complexity": 0.0,
            "dependency_complexity": 0.0,
            "test_coverage_indicator": 0.0,
        }

        if not language_stats:
            return metrics

        # Calculate overall complexity
        total_complexity = sum(stats["complexity"] for stats in language_stats.values())
        metrics["overall_complexity"] = min(total_complexity / len(language_stats), 5.0)

        # Calculate file size variance
        all_sizes = []
        for stats in language_stats.values():
            all_sizes.extend([stats["average_size"]] * stats["file_count"])

        if len(all_sizes) > 1:
            mean_size = sum(all_sizes) / len(all_sizes)
            variance = sum((x - mean_size) ** 2 for x in all_sizes) / len(all_sizes)
            metrics["file_size_variance"] = min(variance / 1000.0, 5.0)

        return metrics

    def _generate_language_recommendations(self, language_stats: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on language analysis."""
        recommendations = []

        if not language_stats:
            return recommendations

        # Find dominant language
        dominant_language = max(language_stats.items(), key=lambda x: x[1]["file_count"])[0]

        # Language-specific recommendations
        if dominant_language == 'python':
            recommendations.extend([
                "Consider using virtual environments for Python development",
                "Use requirements.txt or pyproject.toml for dependency management",
                "Consider using type hints for better code documentation",
                "Implement proper error handling and logging",
            ])
        elif dominant_language == 'javascript':
            recommendations.extend([
                "Use package.json for dependency management",
                "Consider using ESLint for code quality",
                "Implement proper error handling",
                "Use module systems (ES6 modules, CommonJS, or AMD)",
            ])
        elif dominant_language == 'java':
            recommendations.extend([
                "Use Maven or Gradle for build management",
                "Implement proper logging frameworks",
                "Consider using Spring Boot for web applications",
                "Use unit testing frameworks like JUnit",
            ])
        elif dominant_language == 'csharp':
            recommendations.extend([
                "Use .NET SDK for development",
                "Implement proper error handling",
                "Consider using dependency injection",
                "Use unit testing frameworks like MSTest or xUnit",
            ])

        # General recommendations
        if len(language_stats) > 2:
            recommendations.append(
                "Consider consolidating languages to reduce complexity and maintenance burden"
            )

        if language_stats.get('python', {}).get('quality_score', 0) < 3.0:
            recommendations.append(
                "Improve Python code quality by following PEP 8 and adding type hints"
            )

        return recommendations

    def _get_primary_language(self, language_stats: Dict[str, Any]) -> str:
        """Get the primary (most used) language."""
        if not language_stats:
            return "unknown"

        return max(language_stats.items(), key=lambda x: x[1]["file_count"])[0]

    def _get_secondary_languages(self, language_stats: Dict[str, Any]) -> List[str]:
        """Get secondary languages sorted by usage."""
        if not language_stats:
            return []

        sorted_languages = sorted(
            language_stats.items(),
            key=lambda x: x[1]["file_count"],
            reverse=True
        )

        # Return all languages except the primary one
        return [lang for lang, _ in sorted_languages[1:]]

    def analyze_languages(self) -> Dict[str, Any]:
        """Perform complete language analysis."""
        return self.detect_all_languages()