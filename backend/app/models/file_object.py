from dataclasses import dataclass
from pathlib import Path


@dataclass
class FileObject:

    absolute_path: Path

    relative_path: str

    file_name: str

    extension: str

    language: str

    size: int

    sha256: str

    is_binary: bool