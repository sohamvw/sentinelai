import hashlib
from pathlib import Path

from app.models.file_object import FileObject
from app.models.repository_index import RepositoryIndex


class RepositoryWalker:

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
        "coverage"
    }

    LANGUAGE_MAP = {
        ".py": "Python",
        ".js": "JavaScript",
        ".ts": "TypeScript",
        ".tsx": "React",
        ".java": "Java",
        ".kt": "Kotlin",
        ".go": "Go",
        ".cpp": "C++",
        ".c": "C",
        ".cs": "C#",
        ".php": "PHP",
        ".html": "HTML",
        ".css": "CSS",
        ".json": "JSON",
        ".yaml": "YAML",
        ".yml": "YAML",
        ".xml": "XML",
        ".md": "Markdown",
        ".sql": "SQL",
        ".tf": "Terraform",
        ".sh": "Shell"
    }

    @staticmethod
    def sha256(file_path: Path) -> str:

        hasher = hashlib.sha256()

        with open(file_path, "rb") as file:

            while chunk := file.read(8192):
                hasher.update(chunk)

        return hasher.hexdigest()

    @classmethod
    def walk(cls, repository_path: Path) -> RepositoryIndex:

        index = RepositoryIndex()

        for file in repository_path.rglob("*"):

            if not file.is_file():
                continue

            # Skip ignored directories
            relative_parts = file.relative_to(repository_path).parts

            if any(part in cls.IGNORE_DIRECTORIES for part in relative_parts):
                continue

            extension = file.suffix.lower()

            language = cls.LANGUAGE_MAP.get(
                extension,
                "Unknown"
            )

            file_object = FileObject(
                absolute_path=file,
                relative_path=str(file.relative_to(repository_path)),
                file_name=file.name,
                extension=extension,
                language=language,
                size=file.stat().st_size,
                sha256=cls.sha256(file),
                is_binary=False
            )

            index.files.append(file_object)
            index.total_files += 1
            index.total_size += file_object.size
            index.languages[language] = index.languages.get(language, 0) + 1

            for parent in Path(file_object.relative_path).parents:
                if str(parent) != ".":
                    index.directories.add(str(parent))

        return index
