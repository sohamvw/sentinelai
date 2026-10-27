import json
import re
from pathlib import Path
from typing import Iterable

from app.knowledge.models.evidence import Evidence
from app.models.repository_model import RepositoryModel


class EvidenceEngine:

    FRAMEWORK_DEPENDENCIES = {
        "fastapi": "FastAPI",
        "django": "Django",
        "flask": "Flask",
        "express": "Express",
        "@nestjs/core": "NestJS",
        "react": "React",
        "next": "Next.js",
        "vite": "Vite",
        "vue": "Vue",
        "@angular/core": "Angular",
        "spring-boot-starter-web": "Spring Boot",
    }

    DATABASE_DEPENDENCIES = {
        "mongoose": "MongoDB",
        "mongodb": "MongoDB",
        "prisma": "Prisma",
        "sequelize": "Sequelize",
        "pg": "PostgreSQL",
        "psycopg2": "PostgreSQL",
        "mysql": "MySQL",
        "mysql2": "MySQL",
        "sqlite3": "SQLite",
        "sqlalchemy": "SQLAlchemy",
    }

    AUTH_DEPENDENCIES = {
        "jsonwebtoken": "JWT",
        "jwt": "JWT",
        "pyjwt": "JWT",
        "python-jose": "JWT",
        "passport": "Passport",
        "bcrypt": "Password Hashing",
        "bcryptjs": "Password Hashing",
        "fastapi-users": "FastAPI Users",
        "spring-security": "Spring Security",
    }

    IMPORTANT_FILES = {
        "package.json",
        "requirements.txt",
        "pyproject.toml",
        "poetry.lock",
        "pipfile",
        "dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        ".env",
        ".env.example",
        "github-actions.yml",
    }

    TEXT_EXTENSIONS = {
        ".py",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".json",
        ".yaml",
        ".yml",
        ".env",
        ".toml",
        ".ini",
        ".md",
    }

    CODE_SECRET_PATTERN = re.compile(
        r"(?i)\b(api[_-]?key|secret|token|password|private[_-]?key)\b"
        r"\s*[:=]\s*[\"']([^\"']{12,})[\"']"
    )

    ENV_SECRET_PATTERN = re.compile(
        r"(?i)^\s*([A-Z0-9_]*(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PRIVATE[_-]?KEY)[A-Z0-9_]*)"
        r"\s*=\s*([^\s#]+)"
    )

    DANGEROUS_CODE_PATTERNS = {
        "eval(": "Dynamic code execution",
        "exec(": "Dynamic Python execution",
        "shell=True": "Shell command execution",
        "pickle.loads": "Unsafe pickle deserialization",
        "innerHTML": "Potential DOM injection sink",
    }

    @classmethod
    def collect(cls, model: RepositoryModel) -> list[Evidence]:
        evidence: list[Evidence] = []

        for language in sorted(model.languages):
            if language != "Unknown":
                cls._add(evidence, "language", "detected_language", language)

        for relative_path, file in model.files.items():
            lower_name = file.file_name.lower()

            if lower_name in cls.IMPORTANT_FILES:
                cls._add(
                    evidence,
                    "important_file",
                    "important_file_present",
                    file.file_name,
                    source_path=relative_path,
                )

            if lower_name == "package.json":
                dependencies = cls._read_package_json(file.absolute_path)
                cls._emit_dependencies(evidence, dependencies.items(), relative_path)
                cls._add(
                    evidence,
                    "package_manager",
                    "package_manager_detected",
                    "npm",
                    source_path=relative_path,
                )

            if lower_name == "requirements.txt":
                dependencies = cls._read_requirements(file.absolute_path)
                cls._emit_dependencies(evidence, dependencies.items(), relative_path)
                cls._add(
                    evidence,
                    "package_manager",
                    "package_manager_detected",
                    "pip",
                    source_path=relative_path,
                )

            if lower_name in {"dockerfile", "docker-compose.yml", "docker-compose.yaml"}:
                cls._add(
                    evidence,
                    "container",
                    "container_config_detected",
                    file.file_name,
                    source_path=relative_path,
                )

            if ".github" in Path(relative_path).parts or lower_name.endswith((".yml", ".yaml")):
                if "workflow" in relative_path.lower() or ".github" in Path(relative_path).parts:
                    cls._add(
                        evidence,
                        "ci_cd",
                        "ci_cd_config_detected",
                        "GitHub Actions",
                        source_path=relative_path,
                    )

            cls._scan_security_patterns(evidence, file.absolute_path, relative_path)

        for relative_path, parsed in model.parsed_files.items():
            for import_name in parsed.imports:
                cls._emit_dependency_signal(evidence, import_name, "import_detected", relative_path)

            for route in parsed.api_routes:
                cls._add(
                    evidence,
                    "api_endpoint",
                    "api_route_detected",
                    route,
                    source_path=relative_path,
                )

        return evidence

    @classmethod
    def _emit_dependencies(
        cls,
        evidence: list[Evidence],
        dependencies: Iterable[tuple[str, str]],
        source_path: str,
    ):
        for name, version in dependencies:
            cls._add(
                evidence,
                "dependency",
                "dependency_declared",
                name,
                source_path=source_path,
                metadata={"version": version},
            )

            cls._emit_dependency_signal(
                evidence,
                name,
                "dependency_inferred",
                source_path,
                version=version,
            )

    @classmethod
    def _emit_dependency_signal(
        cls,
        evidence: list[Evidence],
        name: str,
        signal: str,
        source_path: str,
        version: str = "",
    ):
        normalized = cls._normalize_dependency_name(name)

        if normalized in cls.FRAMEWORK_DEPENDENCIES:
            cls._add(
                evidence,
                "framework",
                signal,
                cls.FRAMEWORK_DEPENDENCIES[normalized],
                source_path=source_path,
                metadata={"dependency": name, "version": version},
            )

        if normalized in cls.DATABASE_DEPENDENCIES:
            cls._add(
                evidence,
                "database",
                signal,
                cls.DATABASE_DEPENDENCIES[normalized],
                source_path=source_path,
                metadata={"dependency": name, "version": version},
            )

        if normalized in cls.AUTH_DEPENDENCIES:
            cls._add(
                evidence,
                "authentication",
                signal,
                cls.AUTH_DEPENDENCIES[normalized],
                source_path=source_path,
                metadata={"dependency": name, "version": version},
            )

    @classmethod
    def _scan_security_patterns(
        cls,
        evidence: list[Evidence],
        absolute_path: Path,
        relative_path: str,
    ):
        if absolute_path.suffix.lower() not in cls.TEXT_EXTENSIONS and absolute_path.name != ".env":
            return

        if absolute_path.name in {"package-lock.json", "pnpm-lock.yaml", "yarn.lock"}:
            return

        if absolute_path.stat().st_size > 512_000:
            return

        text = absolute_path.read_text(encoding="utf-8", errors="ignore")

        secret_pattern = (
            cls.ENV_SECRET_PATTERN
            if absolute_path.name == ".env"
            else cls.CODE_SECRET_PATTERN
        )

        for match in secret_pattern.finditer(text):
            if cls._looks_like_placeholder(match.group(2)):
                continue

            cls._add(
                evidence,
                "security",
                "possible_hardcoded_secret",
                match.group(1),
                source_path=relative_path,
                confidence=0.7,
            )

        for pattern, description in cls.DANGEROUS_CODE_PATTERNS.items():
            if pattern in text:
                cls._add(
                    evidence,
                    "security",
                    "dangerous_code_pattern",
                    description,
                    source_path=relative_path,
                    confidence=0.75,
                    metadata={"pattern": pattern},
                )

    @staticmethod
    def _read_package_json(path: Path) -> dict[str, str]:
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except json.JSONDecodeError:
            return {}

        dependencies: dict[str, str] = {}

        for key in ("dependencies", "devDependencies"):
            for name, version in data.get(key, {}).items():
                dependencies[name] = str(version)

        return dependencies

    @staticmethod
    def _read_requirements(path: Path) -> dict[str, str]:
        dependencies: dict[str, str] = {}

        for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw_line.strip()

            if not line or line.startswith("#"):
                continue

            parts = re.split(r"==|>=|<=|~=|>|<", line, maxsplit=1)
            name = parts[0].strip()
            version = parts[1].strip() if len(parts) > 1 else ""

            if name:
                dependencies[name] = version

        return dependencies

    @staticmethod
    def _normalize_dependency_name(name: str) -> str:
        normalized = name.lower().strip()

        if normalized.startswith("@types/"):
            normalized = normalized.removeprefix("@types/")

        return normalized

    @staticmethod
    def _looks_like_placeholder(value: str) -> bool:
        lowered = value.lower()

        return any(
            placeholder in lowered
            for placeholder in ("your_", "change_me", "changeme", "example", "placeholder")
        )

    @staticmethod
    def _add(
        evidence: list[Evidence],
        category: str,
        signal: str,
        value,
        source_path: str = "",
        confidence: float = 1.0,
        metadata: dict | None = None,
    ):
        evidence.append(
            Evidence(
                evidence_id=f"EVID-{len(evidence) + 1:06d}",
                category=category,
                signal=signal,
                value=value,
                source_path=source_path,
                confidence=confidence,
                metadata=metadata or {},
            )
        )
