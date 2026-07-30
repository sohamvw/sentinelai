from dataclasses import dataclass, field
from typing import Dict, List

from app.models.file_object import FileObject


@dataclass
class RepositoryIndex:

    files: List[FileObject] = field(default_factory=list)

    total_files: int = 0

    total_size: int = 0

    languages: Dict[str, int] = field(default_factory=dict)