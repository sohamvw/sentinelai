"""
Dependency Extractor
Parses package manifests from various ecosystems to extract exact dependency versions.
Supports: requirements.txt, pyproject.toml, package.json, pom.xml, build.gradle, go.mod, Cargo.toml
"""
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Any


class DependencyExtractor:

    @classmethod
    def extract(cls, repository_path: str) -> Dict[str, str]:
        """
        Walk the repository and extract all dependency versions from manifest files.
        Returns dict mapping package_name -> version.
        """
        repo = Path(repository_path)
        all_deps: Dict[str, str] = {}

        # Find all manifest files
        manifests = {
            "requirements.txt": cls._parse_requirements_txt,
            "pyproject.toml": cls._parse_pyproject_toml,
            "package.json": cls._parse_package_json,
            "pom.xml": cls._parse_pom_xml,
            "build.gradle": cls._parse_build_gradle,
            "build.gradle.kts": cls._parse_build_gradle,
            "go.mod": cls._parse_go_mod,
            "Cargo.toml": cls._parse_cargo_toml,
            "composer.json": cls._parse_composer_json,
            "Gemfile": cls._parse_gemfile,
        }

        for manifest_name, parser in manifests.items():
            for manifest_file in repo.rglob(manifest_name):
                try:
                    deps = parser(manifest_file)
                    all_deps.update(deps)
                except Exception as e:
                    print(f"[DependencyExtractor] Error parsing {manifest_file}: {e}")

        return all_deps

    @classmethod
    def _parse_requirements_txt(cls, file_path: Path) -> Dict[str, str]:
        """Parse requirements.txt (pip)."""
        deps = {}
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Handle: package==1.2.3, package>=1.2.3, package~=1.2, package
            match = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:==|>=|<=|~=|!=|===)?\s*([A-Za-z0-9_.+-]+)?", line)
            if match:
                name = match.group(1).lower()
                version = match.group(2) or "unknown"
                deps[name] = version
        return deps

    @classmethod
    def _parse_pyproject_toml(cls, file_path: Path) -> Dict[str, str]:
        """Parse pyproject.toml (poetry/flit/pip)."""
        deps = {}
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib
            except ImportError:
                print("[DependencyExtractor] tomllib/tomli not available, skipping pyproject.toml")
                return deps

        content = file_path.read_text(encoding="utf-8", errors="ignore")
        try:
            data = tomllib.loads(content)
        except Exception:
            return deps

        # Poetry format: [tool.poetry.dependencies]
        poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
        for name, spec in poetry_deps.items():
            if name.lower() == "python":
                continue
            if isinstance(spec, str):
                deps[name.lower()] = spec
            elif isinstance(spec, dict):
                version = spec.get("version", "unknown")
                deps[name.lower()] = version

        # PEP 621: [project.dependencies]
        project_deps = data.get("project", {}).get("dependencies", [])
        for dep in project_deps:
            match = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:==|>=|<=|~=|!=|===)?\s*([A-Za-z0-9_.+-]+)?", dep)
            if match:
                name = match.group(1).lower()
                version = match.group(2) or "unknown"
                deps[name] = version

        # Optional dependencies
        optional = data.get("project", {}).get("optional-dependencies", {})
        for extra_deps in optional.values():
            for dep in extra_deps:
                match = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:==|>=|<=|~=|!=|===)?\s*([A-Za-z0-9_.+-]+)?", dep)
                if match:
                    name = match.group(1).lower()
                    version = match.group(2) or "unknown"
                    deps[name] = version

        return deps

    @classmethod
    def _parse_package_json(cls, file_path: Path) -> Dict[str, str]:
        """Parse package.json (npm/yarn/pnpm)."""
        deps = {}
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        try:
            data = json.loads(content)
        except Exception:
            return deps

        for dep_type in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            for name, version in data.get(dep_type, {}).items():
                # Clean version: remove ^, ~, >=, etc.
                clean_version = re.sub(r"^[\^~><=]+", "", version).strip()
                deps[name.lower()] = clean_version or "unknown"

        return deps

    @classmethod
    def _parse_pom_xml(cls, file_path: Path) -> Dict[str, str]:
        """Parse pom.xml (Maven)."""
        deps = {}
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()

            # Namespace handling
            ns = {"m": "http://maven.apache.org/POM/4.0.0"}
            # Try with namespace first
            deps_elements = root.findall(".//m:dependency", ns)
            if not deps_elements:
                # Try without namespace
                deps_elements = root.findall(".//dependency")

            for dep in deps_elements:
                group_id = dep.findtext("groupId") or dep.findtext("m:groupId", namespaces=ns)
                artifact_id = dep.findtext("artifactId") or dep.findtext("m:artifactId", namespaces=ns)
                version = dep.findtext("version") or dep.findtext("m:version", namespaces=ns)

                if group_id and artifact_id:
                    name = f"{group_id}:{artifact_id}".lower()
                    deps[name] = version or "unknown"

            # Also check dependencyManagement
            mgmt_deps = root.findall(".//m:dependencyManagement/m:dependencies/m:dependency", ns)
            if not mgmt_deps:
                mgmt_deps = root.findall(".//dependencyManagement/dependencies/dependency")
            for dep in mgmt_deps:
                group_id = dep.findtext("groupId") or dep.findtext("m:groupId", namespaces=ns)
                artifact_id = dep.findtext("artifactId") or dep.findtext("m:artifactId", namespaces=ns)
                version = dep.findtext("version") or dep.findtext("m:version", namespaces=ns)
                if group_id and artifact_id:
                    name = f"{group_id}:{artifact_id}".lower()
                    deps[name] = version or "unknown"

        except Exception:
            pass
        return deps

    @classmethod
    def _parse_build_gradle(cls, file_path: Path) -> Dict[str, str]:
        """Parse build.gradle / build.gradle.kts (Gradle)."""
        deps = {}
        content = file_path.read_text(encoding="utf-8", errors="ignore")

        # Match: implementation 'group:artifact:version' or "group:artifact:version"
        # Also: implementation group: 'group', name: 'artifact', version: 'version'
        patterns = [
            r"['\"]([^:'\"]+):([^:'\"]+):([^:'\"]+)['\"]",  # 'group:artifact:version'
            r"group\s*[:=]\s*['\"]([^'\"]+)['\"]\s*.*?name\s*[:=]\s*['\"]([^'\"]+)['\"]\s*.*?version\s*[:=]\s*['\"]([^'\"]+)['\"]",
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, content, re.DOTALL):
                if len(match.groups()) == 3:
                    group, artifact, version = match.groups()
                    name = f"{group}:{artifact}".lower()
                    deps[name] = version

        return deps

    @classmethod
    def _parse_go_mod(cls, file_path: Path) -> Dict[str, str]:
        """Parse go.mod (Go modules)."""
        deps = {}
        content = file_path.read_text(encoding="utf-8", errors="ignore")

        # Match: module/path v1.2.3
        in_require = False
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("require ("):
                in_require = True
                continue
            if in_require and line == ")":
                in_require = False
                continue

            if in_require or line.startswith("require "):
                # module/path v1.2.3
                match = re.match(r"^([^\s]+)\s+v?([^\s]+)", line.replace("require ", ""))
                if match:
                    name, version = match.groups()
                    deps[name.lower()] = version

        return deps

    @classmethod
    def _parse_cargo_toml(cls, file_path: Path) -> Dict[str, str]:
        """Parse Cargo.toml (Rust)."""
        deps = {}
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib
            except ImportError:
                return deps

        content = file_path.read_text(encoding="utf-8", errors="ignore")
        try:
            data = tomllib.loads(content)
        except Exception:
            return deps

        for dep_type in ("dependencies", "dev-dependencies", "build-dependencies"):
            for name, spec in data.get(dep_type, {}).items():
                if isinstance(spec, str):
                    deps[name.lower()] = spec
                elif isinstance(spec, dict):
                    version = spec.get("version", "unknown")
                    deps[name.lower()] = version

        return deps

    @classmethod
    def _parse_composer_json(cls, file_path: Path) -> Dict[str, str]:
        """Parse composer.json (PHP)."""
        deps = {}
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        try:
            data = json.loads(content)
        except Exception:
            return deps

        for dep_type in ("require", "require-dev"):
            for name, version in data.get(dep_type, {}).items():
                deps[name.lower()] = version

        return deps

    @classmethod
    def _parse_gemfile(cls, file_path: Path) -> Dict[str, str]:
        """Parse Gemfile (Ruby Bundler)."""
        deps = {}
        content = file_path.read_text(encoding="utf-8", errors="ignore")

        # Match: gem 'name', 'version' or gem 'name', '~> 1.0'
        for line in content.splitlines():
            line = line.strip()
            if not line.startswith("gem "):
                continue
            # gem 'name', 'version'
            match = re.match(r"gem\s+['\"]([^'\"]+)['\"]\s*(?:,\s*['\"]([^'\"]+)['\"])?", line)
            if match:
                name = match.group(1).lower()
                version = match.group(2) or "unknown"
                # Clean version
                version = re.sub(r"^[\^~><=~]+", "", version).strip()
                deps[name] = version

        return deps


def extract_dependencies(repository_path: str) -> Dict[str, str]:
    """Convenience function."""
    return DependencyExtractor.extract(repository_path)