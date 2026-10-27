from pathlib import Path
from urllib.parse import urlparse

try:
    from git import InvalidGitRepositoryError, Repo
    HAS_GIT = True
except ImportError:
    HAS_GIT = False
    InvalidGitRepositoryError = Exception
    Repo = None

from app.models.repository_index import RepositoryIndex
from app.models.repository_model import RepositoryModel


class RepositoryModelBuilder:

    @staticmethod
    def build(
        index: RepositoryIndex,
        repository_path: Path | None = None,
        remote_url: str = ""
    ) -> RepositoryModel:

        model = RepositoryModel()
        model.remote_url = remote_url
        model.total_directories = len(index.directories)

        if repository_path:
            model.name = repository_path.name

        owner, name = RepositoryModelBuilder._parse_remote(remote_url)
        model.owner = owner
        if name:
            model.name = name

        for file in index.files:

            model.files[
                file.relative_path
            ] = file

            model.languages.add(
                file.language
            )

            model.total_files += 1

            model.total_size += file.size

        model.directories = sorted(index.directories)

        if repository_path:
            RepositoryModelBuilder._enrich_from_git(model, repository_path)

        return model

    @staticmethod
    def _parse_remote(remote_url: str) -> tuple[str, str]:
        if not remote_url:
            return "", ""

        parsed = urlparse(remote_url)
        parts = parsed.path.strip("/").split("/")

        if len(parts) < 2:
            return "", ""

        owner = parts[-2]
        name = parts[-1].removesuffix(".git")

        return owner, name

    @staticmethod
    def _enrich_from_git(model: RepositoryModel, repository_path: Path):
        if not HAS_GIT or Repo is None:
            model.warnings.append({"module": "repository_model_builder", "message": "Git library unavailable."})
            return

        try:
            repo = Repo(repository_path)

            if not model.remote_url and repo.remotes:
                model.remote_url = next(repo.remotes.origin.urls)

            try:
                model.default_branch = repo.active_branch.name
            except TypeError:
                model.default_branch = ""

            if repo.head.is_valid():
                model.current_commit = repo.head.commit.hexsha

        except (InvalidGitRepositoryError, ValueError):
            model.warnings.append(
                {
                    "module": "repository_model_builder",
                    "message": "Git metadata could not be read."
                }
            )
