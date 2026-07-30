from pathlib import Path

from app.repository_discovery.walker.repository_walker import RepositoryWalker

repository = Path(
    "runtime/workspaces/SCAN-20260722-000001/repository"
)

index = RepositoryWalker.walk(repository)

print()

print("=" * 50)

print("FILES FOUND:", len(index.files))

print("=" * 50)

for file in index.files[:20]:

    print(file.relative_path)