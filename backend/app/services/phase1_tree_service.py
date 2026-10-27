"""
Phase 1 — Repository Tree Builder.

Produces tree.json with per-file metadata required for downstream stages.

Output: runtime/workspaces/SCAN-xxxx/tree.json

Each file entry contains:
- relative_path: str
- directory: str (parent directory)
- extension: str
- language: str
- size: int (bytes)
- sha256: str
- is_binary: bool
- is_entry_point: bool
- is_config: bool
- is_dependency_manifest: bool
- is_test: bool
- is_docs: bool
"""
import hashlib
import json
import os
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Set


# Files/directories to ignore during walk
IGNORE_DIRECTORIES = {
    ".git",
    "node_modules",
    "__pycache__",
    ".idea",
    ".vscode",
    ".venv",
    "venv",
    "dist",
    "build",
    ".next",
    "coverage",
    "target",
    "out",
    ".gradle",
    ".mvn",
}

# Language mapping by extension
LANGUAGE_MAP = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "React",
    ".jsx": "React",
    ".java": "Java",
    ".kt": "Kotlin",
    ".go": "Go",
    ".cpp": "C++",
    ".cc": "C++",
    ".cxx": "C++",
    ".c": "C",
    ".h": "C/C++",
    ".hpp": "C++",
    ".cs": "C#",
    ".php": "PHP",
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".scss": "SCSS",
    ".sass": "SCSS",
    ".json": "JSON",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".xml": "XML",
    ".md": "Markdown",
    ".markdown": "Markdown",
    ".sql": "SQL",
    ".tf": "Terraform",
    ".tfvars": "Terraform",
    ".sh": "Shell",
    ".bash": "Shell",
    ".zsh": "Shell",
    ".rb": "Ruby",
    ".rs": "Rust",
    ".swift": "Swift",
    ".m": "Objective-C",
    ".mm": "Objective-C++",
    ".pl": "Perl",
    ".lua": "Lua",
    ".r": "R",
    ".scala": "Scala",
    ".clj": "Clojure",
    ".ex": "Elixir",
    ".exs": "Elixir",
    ".dart": "Dart",
    ".fs": "F#",
    ".vb": "VB.NET",
    ".groovy": "Groovy",
    ".gradle": "Gradle",
    ".properties": "Properties",
    ".ini": "INI",
    ".toml": "TOML",
    ".cfg": "Config",
    ".conf": "Config",
    ".env": "Env",
}


# Dependency manifest filenames (exact matches)
DEPENDENCY_MANIFESTS = {
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-test.txt",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "composer.json",
    "composer.lock",
    "Gemfile",
    "Gemfile.lock",
    "mix.exs",
    "mix.lock",
    "pubspec.yaml",
    "pubspec.lock",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "Dockerfile.dev",
    "Dockerfile.prod",
}

# Config file patterns (regex)
CONFIG_PATTERNS = [
    r"\.env(\..*)?$",
    r"config\.(yaml|yml|json|toml|ini|conf|properties)$",
    r"settings\.(yaml|yml|json|toml|ini|conf|properties)$",
    r"\.rc\.(yaml|yml|json|js|ts)$",
    r"\.(eslint|prettier|stylelint|babel|tsconfig)\.(json|yaml|yml|js|ts)$",
    r"webpack\.config\.(js|ts)$",
    r"vite\.config\.(js|ts)$",
    r"jest\.config\.(js|ts|json)$",
    r"vitest\.config\.(js|ts)$",
    r"\.github/workflows/.*\.(yaml|yml)$",
    r"\.gitlab-ci\.yml$",
    r"Jenkinsfile",
    r"\.travis\.yml$",
    r"circle\.yml$",
    r"appveyor\.yml$",
]

# Entry point patterns
ENTRY_POINT_PATTERNS = [
    r"main\.(py|js|ts|go|java|rb|rs|cs|php)$",
    r"app\.(py|js|ts|go|java)$",
    r"server\.(py|js|ts|go|java)$",
    r"index\.(js|ts|jsx|tsx)$",
    r"__main__\.py$",
    r"cli\.(py|js|ts|go)$",
    r"cmd/.*/main\.(go)$",
    r"manage\.py$",
    r"wsgi\.py$",
    r"asgi\.py$",
    r"Procfile$",
    r"entrypoint\.sh$",
    r"start\.sh$",
]

# Test file patterns
TEST_PATTERNS = [
    r"test_.*\.py$",
    r".*_test\.py$",
    r".*\.test\.(js|ts|jsx|tsx)$",
    r".*\.spec\.(js|ts|jsx|tsx)$",
    r".*Test\.java$",
    r".*Spec\.java$",
    r".*_test\.go$",
    r"test/.*",
    r"tests/.*",
    r"__tests__/.*",
    r"spec/.*",
    r"specs/.*",
    r"cypress/.*",
    r"playwright/.*",
]

# Documentation patterns
DOCS_PATTERNS = [
    r"README\.(md|rst|txt)$",
    r"CHANGELOG\.(md|rst|txt)$",
    r"CONTRIBUTING\.(md|rst|txt)$",
    r"LICENSE(\.(md|txt))?$",
    r"docs/.*",
    r"doc/.*",
    r"\.md$",
    r"\.rst$",
    r"\.txt$",
    r"ADR/.*",
    r"architecture/.*",
]


@dataclass
class TreeFileEntry:
    """Single file entry in tree.json"""
    relative_path: str
    directory: str
    extension: str
    language: str
    size: int
    sha256: str
    is_binary: bool
    is_entry_point: bool
    is_config: bool
    is_dependency_manifest: bool
    is_test: bool
    is_docs: bool


def _sha256(file_path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()


def _is_binary(file_path: Path) -> bool:
    """Heuristic: check if file is binary by reading first 8KB."""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(8192)
            return b"\x00" in chunk
    except Exception:
        return True


def _get_language(extension: str) -> str:
    """Map file extension to language."""
    return LANGUAGE_MAP.get(extension.lower(), "Unknown")


def _is_dependency_manifest(file_name: str, relative_path: str) -> bool:
    """Check if file is a dependency manifest."""
    # Exact filename match
    if file_name in DEPENDENCY_MANIFESTS:
        return True
    # Dockerfile variations
    if file_name.startswith("Dockerfile"):
        return True
    # docker-compose variations
    if file_name.startswith("docker-compose") and file_name.endswith((".yml", ".yaml")):
        return True
    return False


def _is_config(file_name: str, relative_path: str) -> bool:
    """Check if file is a configuration file."""
    path_lower = relative_path.lower()
    name_lower = file_name.lower()
    for pattern in CONFIG_PATTERNS:
        if re.search(pattern, path_lower) or re.search(pattern, name_lower):
            return True
    return False


def _is_entry_point(file_name: str, relative_path: str) -> bool:
    """Check if file is an application entry point."""
    path_lower = relative_path.lower()
    name_lower = file_name.lower()
    for pattern in ENTRY_POINT_PATTERNS:
        if re.search(pattern, path_lower) or re.search(pattern, name_lower):
            return True
    return False


def _is_test(file_name: str, relative_path: str) -> bool:
    """Check if file is a test file."""
    path_lower = relative_path.lower()
    name_lower = file_name.lower()
    for pattern in TEST_PATTERNS:
        if re.search(pattern, path_lower) or re.search(pattern, name_lower):
            return True
    return False


def _is_docs(file_name: str, relative_path: str) -> bool:
    """Check if file is documentation."""
    path_lower = relative_path.lower()
    name_lower = file_name.lower()
    for pattern in DOCS_PATTERNS:
        if re.search(pattern, path_lower) or re.search(pattern, name_lower):
            return True
    return False


def _get_directory(relative_path: str) -> str:
    """Get parent directory of a file."""
    parent = str(Path(relative_path).parent)
    return parent if parent != "." else ""


class Phase1TreeService:
    """
    Phase 1: Build repository tree.json with per-file metadata.

    This is a standalone service that can be called after cloning.
    It does NOT depend on LLM - it's purely deterministic file analysis.
    """

    @classmethod
    def build_tree(cls, repository_path: str, workspace_path: str) -> Dict:
        """
        Walk the repository and build tree.json.

        Args:
            repository_path: Path to cloned repository
            workspace_path: Path to scan workspace (for output)

        Returns:
            Dictionary with tree metadata and file entries
        """
        repo_root = Path(repository_path)
        files: List[TreeFileEntry] = []

        # Stats
        total_files = 0
        total_size = 0
        languages: Dict[str, int] = {}
        directories: Set[str] = set()
        extensions: Dict[str, int] = {}

        # Counts by category
        entry_point_count = 0
        config_count = 0
        manifest_count = 0
        test_count = 0
        docs_count = 0
        binary_count = 0

        for file_path in repo_root.rglob("*"):
            if not file_path.is_file():
                continue

            # Skip ignored directories
            relative_parts = file_path.relative_to(repo_root).parts
            if any(part in IGNORE_DIRECTORIES for part in relative_parts):
                continue

            relative_path = str(file_path.relative_to(repo_root)).replace("\\", "/")
            file_name = file_path.name
            extension = file_path.suffix.lower()
            directory = _get_directory(relative_path)

            # Track directories
            if directory:
                directories.add(directory)
                for parent in Path(directory).parents:
                    if str(parent) != ".":
                        directories.add(str(parent))

            # File stats
            try:
                size = file_path.stat().st_size
            except Exception:
                size = 0

            is_binary = _is_binary(file_path)
            if is_binary:
                binary_count += 1

            sha256_hash = _sha256(file_path) if not is_binary else ""
            language = _get_language(extension)

            # Categorize
            is_dep_manifest = _is_dependency_manifest(file_name, relative_path)
            is_cfg = _is_config(file_name, relative_path)
            is_entry = _is_entry_point(file_name, relative_path)
            is_tst = _is_test(file_name, relative_path)
            is_doc = _is_docs(file_name, relative_path)

            if is_dep_manifest:
                manifest_count += 1
            if is_cfg:
                config_count += 1
            if is_entry:
                entry_point_count += 1
            if is_tst:
                test_count += 1
            if is_doc:
                docs_count += 1

            # Create entry
            entry = TreeFileEntry(
                relative_path=relative_path,
                directory=directory,
                extension=extension or "none",
                language=language,
                size=size,
                sha256=sha256_hash,
                is_binary=is_binary,
                is_entry_point=is_entry,
                is_config=is_cfg,
                is_dependency_manifest=is_dep_manifest,
                is_test=is_tst,
                is_docs=is_doc,
            )
            files.append(entry)

            # Update stats
            total_files += 1
            total_size += size
            languages[language] = languages.get(language, 0) + 1
            extensions[extension or "none"] = extensions.get(extension or "none", 0) + 1

        # Build result
        result = {
            "scan_metadata": {
                "repository_path": repository_path,
                "workspace_path": workspace_path,
                "total_files": total_files,
                "total_size_bytes": total_size,
                "total_directories": len(directories),
                "binary_files": binary_count,
                "text_files": total_files - binary_count,
            },
            "summary": {
                "languages": dict(sorted(languages.items(), key=lambda x: x[1], reverse=True)),
                "extensions": dict(sorted(extensions.items(), key=lambda x: x[1], reverse=True)),
                "entry_points": entry_point_count,
                "config_files": config_count,
                "dependency_manifests": manifest_count,
                "test_files": test_count,
                "docs_files": docs_count,
            },
            "directories": sorted(directories),
            "files": [asdict(f) for f in files],
        }

        # Save tree.json
        output_path = Path(workspace_path) / "tree.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)

        return result

    @classmethod
    def load_tree(cls, workspace_path: str) -> Optional[Dict]:
        """Load existing tree.json from workspace."""
        tree_path = Path(workspace_path) / "tree.json"
        if tree_path.exists():
            with open(tree_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return None