from pathlib import Path

from git import Repo

from app.models.scan import Scan


class CloneManager:

    @staticmethod
    def clone(scan: Scan):

        repository_path = Path(scan.workspace) / "repository"

        git_directory = repository_path / ".git"

        # Repository already cloned
        if git_directory.exists():
            return repository_path

        Repo.clone_from(
            scan.repository_url,
            repository_path
        )

        return repository_path