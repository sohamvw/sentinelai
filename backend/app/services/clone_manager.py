import subprocess
import os
from pathlib import Path
from app.models.scan import Scan


class CloneManager:

    @staticmethod
    def clone(scan: Scan):
        repository_path = Path(scan.workspace) / "repository"
        git_directory = repository_path / ".git"

        # Repository already cloned
        if git_directory.exists():
            return repository_path

        repository_path.mkdir(parents=True, exist_ok=True)

        url = str(scan.repository_url)
        if not (url.startswith("http://") or url.startswith("https://") or url.startswith("git@")):
            raise ValueError(f"Invalid repository URL: {url}. Must be http(s) or git@ URL.")

        # Try python git library first, then shell git
        try:
            from git import Repo
            Repo.clone_from(url, repository_path)
            return repository_path
        except ImportError:
            pass  # Fall through to shell git
        except Exception as e:
            raise RuntimeError(f"GitPython clone failed: {e}")

        # Shell git fallback
        try:
            result = subprocess.run(
                ["git", "clone", url, str(repository_path)],
                check=True,
                capture_output=True,
                text=True,
                timeout=300,
            )
            return repository_path
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Git clone timed out after 5 minutes for {url}")
        except subprocess.CalledProcessError as e:
            stderr = e.stderr.strip() if e.stderr else "unknown error"
            raise RuntimeError(f"Git clone failed for {url}: {stderr}")
        except FileNotFoundError:
            raise RuntimeError("Git command not found in PATH. Install git to clone repositories.")
        except Exception as e:
            raise RuntimeError(f"Unexpected error during git clone: {e}")