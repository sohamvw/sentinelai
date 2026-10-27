import os
import json
import uuid
import tempfile
import shutil
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional
import requests
import zipfile
from urllib.parse import urlsplit, urlunsplit
from app.schemas.scan_request import ScanRequest
from app.core.logger import get_logger
from app.services.audit_log_service import AuditLogService

logger = get_logger(__name__)

class ScanService:
    """Service for managing repository scans and workspace creation."""

    @staticmethod
    def _workspaces_root() -> Path:
        """Return the absolute runtime workspace directory, independent of CWD."""
        return Path(__file__).resolve().parents[2] / "runtime" / "workspaces"

    @staticmethod
    def generate_scan_id() -> str:
        """Generate a unique scan ID."""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        random_suffix = str(uuid.uuid4())[:8]
        return f"SCAN-{timestamp}-{random_suffix}"

    @staticmethod
    def create_scan_workspace(scan_id: str) -> str:
        """Create a new scan workspace directory."""
        workspace_path = ScanService._workspaces_root() / scan_id
        workspace_path.mkdir(parents=True, exist_ok=True)
        return str(workspace_path)

    @staticmethod
    def clone_github_repository(repository_url: str, branch: str, workspace_path: str) -> Optional[str]:
        """Clone a repository using the system Git executable."""
        try:
            if shutil.which("git") is None:
                raise RuntimeError(
                    "Git is not installed or is not on PATH. Install Git for Windows, "
                    "then reopen the terminal before starting a repository scan."
                )

            normalized_url = repository_url.strip()
            if "://" not in normalized_url:
                normalized_url = f"https://github.com/{normalized_url.strip('/')}.git"
            else:
                parsed = urlsplit(normalized_url)
                # Browser/share links often carry `utm_*` values. They are
                # valid web URLs but are not Git remotes. GitHub repository
                # URLs should contain only scheme, host, and repo path.
                if parsed.netloc.lower() in {"github.com", "www.github.com"}:
                    repo_path_part = parsed.path.rstrip("/")
                    if not repo_path_part.endswith(".git"):
                        repo_path_part = f"{repo_path_part}.git"
                    normalized_url = urlunsplit((parsed.scheme, parsed.netloc, repo_path_part, "", ""))
            repo_path = Path(workspace_path) / "repository"

            logger.info(f"Cloning repository {normalized_url} (branch: {branch or 'default'}) to {repo_path}")

            def clone(args: List[str]) -> subprocess.CompletedProcess:
                return subprocess.run(
                    args, capture_output=True, text=True, timeout=300, check=False,
                )

            completed = clone(
                ["git", "clone", "--depth", "1", "--branch", branch, normalized_url, str(repo_path)]
                if branch else ["git", "clone", "--depth", "1", normalized_url, str(repo_path)]
            )
            # A common user input is `main` for a repository whose default is
            # `master` or another branch. Retry once with Git's advertised
            # default branch instead of failing an otherwise valid scan.
            if completed.returncode != 0 and branch and "Remote branch" in (completed.stderr or ""):
                logger.warning("Branch '%s' was not found; retrying repository default branch.", branch)
                if repo_path.exists():
                    shutil.rmtree(repo_path)
                completed = clone(["git", "clone", "--depth", "1", normalized_url, str(repo_path)])
            if completed.returncode != 0:
                raise RuntimeError(completed.stderr.strip() or "git clone failed")
            if not repo_path.is_dir():
                raise Exception(f"Repository not found at {repo_path}")

            logger.info("Repository cloned successfully")
            return str(repo_path)
        except Exception as e:
            try:
                (Path(workspace_path) / "clone_error.txt").write_text(str(e), encoding="utf-8")
            except OSError:
                pass
            logger.error(f"Git clone failed for {repository_url}: {e}")
            return None

    @staticmethod
    def extract_zip_repository(zip_url: str, workspace_path: str) -> Optional[str]:
        """Extract a ZIP repository from URL."""
        try:
            logger.info(f"Extracting ZIP repository from {zip_url} to {workspace_path}")

            # Accept either a remote ZIP URL or a server-side uploaded ZIP.
            local_zip = Path(zip_url)
            zip_bytes = local_zip.read_bytes() if local_zip.is_file() else None
            if zip_bytes is None:
                response = requests.get(zip_url, timeout=120)
                response.raise_for_status()
                zip_bytes = response.content

            # Create temporary file
            with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_zip:
                temp_zip.write(zip_bytes)
                temp_zip_path = temp_zip.name

            try:
                # Create extraction directory
                repo_path = Path(workspace_path) / "extracted_repository"

                # Extract ZIP
                with zipfile.ZipFile(temp_zip_path, 'r') as zip_ref:
                    zip_ref.extractall(repo_path)

                # Remediation bundles contain reports and workflow metadata at
                # the archive root. Re-scan only the patched application under
                # codebase/ so bundle metadata is not mistaken for source.
                codebase_path = repo_path / "codebase"
                if codebase_path.is_dir() and any(codebase_path.iterdir()):
                    repo_path = codebase_path

                # Verify extraction
                if not repo_path.exists() or not any(repo_path.iterdir()):
                    raise Exception("ZIP extraction failed - no files found")

                logger.info(f"Successfully extracted ZIP repository with {len(list(repo_path.rglob('*')))} items")
                return str(repo_path)

            finally:
                # Clean up temporary file
                os.unlink(temp_zip_path)

        except requests.RequestException as e:
            logger.error(f"Failed to download ZIP repository {zip_url}: {e}")
            return None
        except zipfile.BadZipFile as e:
            logger.error(f"Invalid ZIP file {zip_url}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error extracting ZIP repository {zip_url}: {e}")
            return None

    @staticmethod
    def walk_repository(repository_path: str) -> Dict[str, Any]:
        """Walk repository and collect file metadata."""
        logger.info(f"Walking repository at {repository_path}")

        file_metadata = []
        total_files = 0
        binary_files = 0
        text_files = 0

        try:
            # Walk the repository
            for root, dirs, files in os.walk(repository_path):
                # Skip hidden directories and common ignore patterns
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in
                          ['__pycache__', '.git', '.venv', 'venv', '.env', 'node_modules',
                           'build', 'dist', '.pytest_cache', '.mypy_cache']]

                for file in files:
                    file_path = Path(root) / file
                    rel_path = file_path.relative_to(repository_path)

                    # Get file information
                    stat = file_path.stat()
                    size = stat.st_size

                    # Determine file extension
                    ext = file_path.suffix.lower()
                    if ext:
                        ext = ext[1:]  # Remove leading dot

                    # Classify file type
                    is_binary = ScanService._is_binary_file(file_path)
                    is_text = not is_binary

                    if is_text:
                        text_files += 1
                    else:
                        binary_files += 1

                    # Determine file indicators
                    is_entry_point = ScanService._is_entry_point_file(file_path, rel_path)
                    is_config = ScanService._is_config_file(file_path, rel_path)
                    is_test = ScanService._is_test_file(file_path, rel_path)
                    is_documentation = ScanService._is_documentation_file(file_path, rel_path)
                    is_dependency_manifest = ScanService._is_dependency_manifest(file_path, rel_path)

                    file_info = {
                        "path": str(rel_path).replace('\\', '/'),  # Normalize to forward slashes
                        "ext": ext,
                        "size": size,
                        "is_binary": is_binary,
                        "is_text": is_text,
                        "is_entry_point": is_entry_point,
                        "is_config": is_config,
                        "is_test": is_test,
                        "is_documentation": is_documentation,
                        "is_dependency_manifest": is_dependency_manifest,
                        "sha256": ScanService._calculate_file_hash(file_path),
                        "directory": str(rel_path.parent).replace('\\', '/'),
                        "language": ScanService._detect_language_from_extension(file),
                        "likely_entry_point": is_entry_point,
                        "likely_configuration": is_config,
                        "test_indicator": is_test,
                        "documentation_indicator": is_documentation,
                        "dependency_manifest_indicator": is_dependency_manifest,
                    }

                    file_metadata.append(file_info)
                    total_files += 1

            logger.info(f"Repository walk completed: {total_files} files analyzed ({text_files} text, {binary_files} binary)")

            return {
                "total_files": total_files,
                "text_files": text_files,
                "binary_files": binary_files,
                "files": file_metadata
            }

        except Exception as e:
            logger.error(f"Error walking repository {repository_path}: {e}")
            raise

    @staticmethod
    def _is_binary_file(file_path: Path) -> bool:
        """Check if file is binary based on extension and content."""
        # Binary file extensions
        binary_extensions = {
            'exe', 'dll', 'so', 'dylib', 'bin', 'pyc', 'pyd', 'dll', 'dat', 'db',
            'jpg', 'jpeg', 'png', 'gif', 'bmp', 'ico', 'svg', 'webp', 'mp4', 'avi',
            'mov', 'wmv', 'flv', 'mp3', 'wav', 'flac', 'aac', 'ogg', 'zip', 'rar',
            '7z', 'tar', 'gz', 'bz2', 'xz', 'pdf', 'doc', 'docx', 'xls', 'xlsx',
            'ppt', 'pptx', 'odt', 'ods', 'odg', 'odp', 'ttf', 'otf', 'woff', 'woff2'
        }

        ext = file_path.suffix.lower()
        if ext:
            ext = ext[1:]  # Remove leading dot
            if ext in binary_extensions:
                return True

        # Check file content for obvious binary indicators
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                # Check for null bytes (common in binary files)
                if b'\x00' in chunk:
                    return True

                # Check if file is valid UTF-8 text
                try:
                    chunk.decode('utf-8')
                except UnicodeDecodeError:
                    return True

        except (OSError, IOError):
            pass

        return False

    @staticmethod
    def _is_entry_point_file(file_path: Path, rel_path: Path) -> bool:
        """Check if file is likely an entry point."""
        file_name = file_path.name.lower()
        ext = file_path.suffix.lower()

        entry_point_patterns = [
            'main.py', 'main.js', 'main.ts', 'main.jsx', 'main.tsx',
            'app.py', 'app.js', 'app.ts', 'app.jsx', 'app.tsx',
            'index.py', 'index.js', 'index.ts',
            'server.py', 'server.js', 'server.ts',
            'api.py', 'api.js', 'api.ts',
            'run.py', 'run.js',
            'start.py', 'start.js',
            '__main__.py',
        ]

        # Check against patterns
        for pattern in entry_point_patterns:
            if pattern == file_name:
                return True

        # Check common entry point directory patterns
        path_parts = rel_path.parts
        if len(path_parts) >= 2:
            if path_parts[-2] in ['backend', 'src', 'app'] and file_name in entry_point_patterns:
                return True

        return False

    @staticmethod
    def _is_config_file(file_path: Path, rel_path: Path) -> bool:
        """Check if file is likely a configuration file."""
        file_name = file_path.name.lower()
        ext = file_path.suffix.lower()

        config_patterns = [
            'config.py', 'configuration.py', 'settings.py', 'appsettings.py',
            'django_settings.py', 'flask_app.py',
            'webpack.config.js', 'vite.config.js', 'rollup.config.js',
            'next.config.js', 'nuxt.config.js',
            '.env', '.env.local', '.env.development', '.env.production',
            'dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
            'docker-compose.dev.yml', 'docker-compose.prod.yml',
            'docker-compose.override.yml',
            'docker-compose.override.yaml',
            'Makefile', 'makefile',
            'setup.cfg', 'pyproject.toml', 'setup.py', 'requirements.txt',
            'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
            'Pipfile', 'Pipfile.lock', 'poetry.lock', 'Gemfile.lock',
            'pom.xml', 'build.gradle', 'build.gradle.kts',
            'composer.json', 'composer.lock',
            'go.mod', 'go.sum',
            'Cargo.toml', 'Cargo.lock',
            'terraform.tf', 'terraform.tfvars', 'terraform.tfstate',
            'kubernetes.yml', 'kubernetes.yaml', 'kustomization.yml', 'kustomization.yaml'
        ]

        # Check against patterns
        for pattern in config_patterns:
            if pattern == file_name.lower():
                return True

        # Check common config directory patterns
        path_parts = rel_path.parts
        if len(path_parts) >= 2:
            if path_parts[-2] in ['config', 'conf', 'settings', 'envs', '.config']:
                return True

        return False

    @staticmethod
    def _is_test_file(file_path: Path, rel_path: Path) -> bool:
        """Check if file is likely a test file."""
        file_name = file_path.name.lower()
        ext = file_path.suffix.lower()

        # Test file patterns
        test_patterns = [
            'test_', '_test', 'tests', 'test.py', 'test.js', 'test.ts',
            'spec.js', 'spec.ts', 'spec.jsx', 'spec.tsx',
            'spec_', '_spec',
        ]

        # Check if file name matches test patterns
        for pattern in test_patterns:
            if pattern in file_name:
                return True

        # Check test directory patterns
        path_parts = rel_path.parts
        for part in path_parts:
            if part.lower() in ['test', 'tests', 'spec', 'specs']:
                return True

        return False

    @staticmethod
    def _is_documentation_file(file_path: Path, rel_path: Path) -> bool:
        """Check if file is likely documentation."""
        file_name = file_path.name.lower()
        ext = file_path.suffix.lower()

        doc_extensions = ['.md', '.rst', '.txt', '.md', '.adoc', '.mdwn', '.mkdn']

        # Check file extension
        if ext in doc_extensions:
            return True

        # Check file name patterns
        doc_patterns = [
            'readme', 'license', 'changelog', 'contributing', 'authors',
            'history', 'news', 'todo', ' roadmap', 'documentation'
        ]

        for pattern in doc_patterns:
            if pattern in file_name:
                return True

        return False

    @staticmethod
    def _is_dependency_manifest(file_path: Path, rel_path: Path) -> bool:
        """Check if file is a dependency management manifest."""
        file_name = file_path.name.lower()

        dependency_manifests = [
            'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
            'requirements.txt', 'requirements-dev.txt', 'Pipfile', 'Pipfile.lock',
            'poetry.lock', 'poetry.toml', 'pyproject.toml', 'setup.py', 'setup.cfg',
            'Gemfile', 'Gemfile.lock', 'composer.json', 'composer.lock',
            'go.mod', 'go.sum', 'Cargo.toml', 'Cargo.lock', 'vcpkg.json',
            'conanfile.py', 'conanfile.txt', 'maven.xml', 'pom.xml', 'build.gradle',
            'build.gradle.kts', 'bzl', 'MODULE.bazel', 'WORKSPACE',
            'bower.json', 'angular.json', 'nx.json',
            'pnpm-workspace.yaml', 'turbo.json', 'lerna.json'
        ]

        return file_name in dependency_manifests

    @staticmethod
    def _detect_language_from_extension(file_path: str) -> Optional[str]:
        """Detect programming language from file extension."""
        ext = Path(file_path).suffix.lower()

        language_mapping = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'javascript-react',
            '.tsx': 'typescript-react',
            '.java': 'java',
            '.cpp': 'cpp',
            '.cc': 'cpp',
            '.cxx': 'cpp',
            '.c': 'c',
            '.h': 'c',
            '.hpp': 'cpp',
            '.cs': 'csharp',
            '.php': 'php',
            '.rb': 'ruby',
            '.go': 'go',
            '.rs': 'rust',
            '.swift': 'swift',
            '.kt': 'kotlin',
            '.scala': 'scala',
            '.r': 'r',
            '.sql': 'sql',
            '.html': 'html',
            '.css': 'css',
            '.scss': 'scss',
            '.sass': 'sass',
            '.less': 'less',
            '.md': 'markdown',
            '.json': 'json',
            '.xml': 'xml',
            '.yaml': 'yaml',
            '.yml': 'yaml',
            '.toml': 'toml',
            '.ini': 'ini',
            '.cfg': 'ini',
            '.conf': 'ini',
            '.sh': 'bash',
            '.bash': 'bash',
            '.zsh': 'zsh',
            '.fish': 'fish',
            '.pyw': 'python',
            '.jsw': 'javascript',
            '.tsw': 'typescript',
        }

        return language_mapping.get(ext, None)

    @staticmethod
    def _calculate_file_hash(file_path: Path) -> str:
        """Calculate SHA-256 hash of file content."""
        import hashlib

        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for byte_block in iter(lambda: f.read(4096), b''):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except (OSError, IOError):
            return ""

    @staticmethod
    def save_tree_metadata(scan_id: str, tree_data: Dict[str, Any]) -> bool:
        """Save tree metadata to scan workspace."""
        try:
            workspace_path = ScanService._workspaces_root() / scan_id
            tree_path = workspace_path / "tree.json"

            # Write tree.json with pretty formatting
            with open(tree_path, 'w', encoding='utf-8') as f:
                json.dump(tree_data, f, indent=2, ensure_ascii=False)

            logger.info(f"Tree metadata saved to {tree_path}")
            return True

        except Exception as e:
            logger.error(f"Error saving tree metadata for scan {scan_id}: {e}")
            return False

    @classmethod
    def start_scan_async(cls, request: ScanRequest, background_tasks) -> Dict[str, Any]:
        """Queue a real repository scan and return its live status handle."""
        from app.policy_engine.canonical_policy_loader import list_supported_sectors
        if request.sector not in list_supported_sectors():
            raise ValueError(
                "Unsupported compliance pack. Choose one of: "
                + ", ".join(list_supported_sectors())
            )
        scan_id = cls.generate_scan_id()
        workspace_path = cls.create_scan_workspace(scan_id)
        cls._write_scan_state(workspace_path, {
            "scan_id": scan_id,
            "status": "RUNNING",
            "stage": "INTAKE",
            "progress": 0,
            "repository_url": request.repository_url,
            "branch": request.branch,
            "started_at": datetime.now().isoformat(),
        })
        background_tasks.add_task(cls._run_pipeline, request, scan_id, workspace_path)
        return {
            "scan_id": scan_id,
            "status": "RUNNING",
            "stage": "INTAKE",
            "progress": 0,
            "message": "Scan accepted. Live progress is available from the scan status endpoint.",
            "workspace": workspace_path,
        }

        # Retained below temporarily for source-history compatibility; the
        # background pipeline above is the active path.
        try:
            # Generate unique scan ID
            scan_id = cls.generate_scan_id()
            logger.info(f"Starting scan {scan_id} for repository: {request.get_repository_identifier()}")

            # Create scan workspace
            workspace_path = cls.create_scan_workspace(scan_id)

            # Clone or extract repository
            repository_path = None
            if request.source_type == "github":
                repository_path = cls.clone_github_repository(request.repository_url, request.branch, workspace_path)
            elif request.source_type == "zip":
                repository_path = cls.extract_zip_repository(request.repository_url, workspace_path)

            if not repository_path:
                raise Exception(f"Failed to process repository from {request.repository_url}")

            # Walk repository and generate tree metadata
            tree_data = cls.walk_repository(repository_path)

            # Save tree metadata
            if not cls.save_tree_metadata(scan_id, tree_data):
                raise Exception("Failed to save tree metadata")

            # Store scan state
            scan_state = {
                "scan_id": scan_id,
                "status": "completed",
                "source_type": request.source_type,
                "repository_url": request.repository_url,
                "branch": request.branch,
                "workspace_path": workspace_path,
                "repository_path": repository_path,
                "tree_metadata_file": str(Path(workspace_path) / "tree.json"),
                "start_time": datetime.now().isoformat(),
                "completed_time": datetime.now().isoformat(),
                "total_files": tree_data.get("total_files", 0),
                "language_distribution": {},
                "frameworks": [],
                "analysis_plan": None
            }

            # Save scan state
            state_path = Path(workspace_path) / "scan_state.json"
            with open(state_path, 'w', encoding='utf-8') as f:
                json.dump(scan_state, f, indent=2, ensure_ascii=False)

            logger.info(f"Scan {scan_id} completed successfully. Processed {tree_data.get('total_files', 0)} files.")

            return {
                "scan_id": scan_id,
                "status": "completed",
                "message": f"Scan completed successfully. Processed {tree_data.get('total_files', 0)} files.",
                "repository_url": request.repository_url,
                "branch": request.branch,
                "files_processed": tree_data.get("total_files", 0),
                "workspace_path": workspace_path,
                "tree_metadata_file": str(Path(workspace_path) / "tree.json")
            }

        except Exception as e:
            logger.error(f"Error starting scan: {e}")

            # Store error state
            error_scan_state = {
                "scan_id": scan_id,
                "status": "failed",
                "error": str(e),
                "start_time": datetime.now().isoformat(),
                "completed_time": datetime.now().isoformat()
            }

            try:
                error_state_path = ScanService._workspaces_root() / f"{scan_id}_state.json"
                with open(error_state_path, 'w', encoding='utf-8') as f:
                    json.dump(error_scan_state, f, indent=2, ensure_ascii=False)
            except:
                pass

            raise Exception(f"Scan failed: {e}")

    @staticmethod
    def _write_scan_state(workspace_path: str, state: Dict[str, Any]) -> None:
        state_path = Path(workspace_path) / "scan_state.json"
        existing: Dict[str, Any] = {}
        if state_path.exists():
            try:
                existing = json.loads(state_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                existing = {}
        existing.update(state)
        existing["updated_at"] = datetime.now().isoformat()
        state_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
        ScanService._persist_scan_state(existing, workspace_path)

    @staticmethod
    def _persist_scan_state(state: Dict[str, Any], workspace_path: str) -> None:
        """Persist the same lifecycle record shown by the API to the active DB."""
        from app.core.database import get_db_connection

        conn, db_type = get_db_connection()
        cursor = conn.cursor()
        now = state.get("updated_at") or datetime.now().isoformat()
        payload = json.dumps({
            "repository_url": state.get("repository_url"),
            "branch": state.get("branch"),
            "stage": state.get("stage"),
            "artifacts": state.get("artifacts", {}),
            "metrics": {key: state.get(key) for key in ("total_findings", "critical_count", "high_count", "medium_count", "low_count")},
        })
        params = (
            state["scan_id"], state.get("started_at", now), state.get("status", "RUNNING"),
            state.get("progress", 0), state.get("status", "RUNNING").lower(), now,
            workspace_path, payload,
        )
        if db_type == "postgres":
            cursor.execute("""
                INSERT INTO scans (id, created_at, status, progress_percentage, realtime_status, last_updated, workspace_path, repository_info)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb)
                ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status,
                    progress_percentage = EXCLUDED.progress_percentage,
                    realtime_status = EXCLUDED.realtime_status, last_updated = EXCLUDED.last_updated,
                    workspace_path = EXCLUDED.workspace_path, repository_info = EXCLUDED.repository_info
            """, params)
        else:
            cursor.execute("""
                INSERT INTO scans (id, created_at, status, progress_percentage, realtime_status, last_updated, workspace_path, repository_info)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET status = excluded.status,
                    progress_percentage = excluded.progress_percentage,
                    realtime_status = excluded.realtime_status, last_updated = excluded.last_updated,
                    workspace_path = excluded.workspace_path, repository_info = excluded.repository_info
            """, params)
        conn.commit()
        conn.close()

    @classmethod
    def _run_pipeline(cls, request: ScanRequest, scan_id: str, workspace_path: str) -> None:
        """Execute each scan stage against only the cloned repository files."""
        active_stage = "REPOSITORY_CLONING"
        try:
            cls._write_scan_state(workspace_path, {"stage": active_stage, "progress": 5})
            if request.source_type == "zip":
                repository_path = cls.extract_zip_repository(request.repository_url or "", workspace_path)
            else:
                repository_path = cls.clone_github_repository(request.repository_url or "", request.branch, workspace_path)
            if not repository_path:
                error_path = Path(workspace_path) / "clone_error.txt"
                clone_detail = error_path.read_text(encoding="utf-8").strip() if error_path.exists() else "Unknown Git error"
                raise RuntimeError(f"Repository {'extraction' if request.source_type == 'zip' else 'cloning'} failed: {clone_detail}")
            cls._write_scan_state(workspace_path, {"stage": "REPOSITORY_CLONED", "progress": 10})

            from app.services.phase1_tree_service import Phase1TreeService
            from app.scanners.multi_tool_runner import MultiToolRunner
            from app.services.llm_verification_service import LLMVerificationService
            from app.policy_engine.policy_checker import PolicyChecker
            from app.services.chain_correlation_service import ChainCorrelationService
            from app.services.pdf_report_service import PDFReportService

            active_stage = "STAGE_1_TREE_MAPPING"
            cls._write_scan_state(workspace_path, {"stage": active_stage, "progress": 25})
            AuditLogService.log_event(
                scan_id=scan_id,
                stage=active_stage,
                event_type="STAGE_STARTED",
                message="Stage 1 started: mapping repository tree and prioritizing high-value files.",
                tool_name="SYSTEM",
            )
            tree = Phase1TreeService.build_tree(repository_path, workspace_path)
            selected_files = [
                {"path": item["relative_path"], "priority": 1, "source": "repository-tree"}
                for item in tree.get("files", [])
                if not item.get("is_binary") and not item.get("is_docs")
            ]

            active_stage = "MULTI_TOOL_SCAN"
            cls._write_scan_state(workspace_path, {"stage": active_stage, "progress": 45})
            raw_findings = MultiToolRunner.run_all(scan_id, repository_path, workspace_path, selected_files)

            # CVE/CVSS enrichment is a distinct knowledge step.  It uses
            # dependency evidence and authoritative data; source scanners
            # remain independently runnable and code-pattern findings do not
            # receive invented CVEs or scores.
            if raw_findings:
                from app.services.cve_lookup_service import enrich_findings
                raw_findings = enrich_findings(raw_findings)
                (Path(workspace_path) / "stage2_multi_hunter_findings.json").write_text(
                    json.dumps(raw_findings, indent=2), encoding="utf-8"
                )

            repository_files: Dict[str, str] = {}
            for item in selected_files:
                file_path = Path(repository_path) / item["path"]
                try:
                    repository_files[item["path"]] = file_path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
            active_stage = "POLICY_JURISDICTION_CHECK"
            cls._write_scan_state(workspace_path, {"stage": active_stage, "progress": 80})
            policy = PolicyChecker.evaluate_repository(
                sector=request.sector,
                uploaded_policy_text=request.policy_document_text or "",
                policy_filename=request.policy_filename or "uploaded_policy.txt",
                repository_files=repository_files,
            )
            # Policy checks are deterministic and evidence-backed.  Feed their
            # actual outcome to the LLM verifier for impact/remediation context
            # without letting the LLM invent or replace a control verdict.
            active_stage = "LLM_VERIFICATION"
            cls._write_scan_state(workspace_path, {"stage": active_stage, "progress": 74})
            verified_findings = LLMVerificationService.verify_findings(
                scan_id, workspace_path, raw_findings, policy_results=policy,
            ) if raw_findings else []
            active_stage = "STAGE_4_CORRELATION"
            cls._write_scan_state(workspace_path, {"stage": active_stage, "progress": 88})
            final_output = ChainCorrelationService.correlate_and_chain(
                scan_id,
                workspace_path,
                verified_findings,
                policy,
                raw_findings_count=len(raw_findings),
            )
            active_stage = "REPORT_GENERATION"
            cls._write_scan_state(workspace_path, {"stage": active_stage, "progress": 94})
            artifacts = PDFReportService.generate_report(scan_id, workspace_path, final_output)
            final_output["artifacts"] = artifacts
            cls._write_scan_state(workspace_path, {
                "status": "COMPLETED", "stage": "AUDIT_REPORT_READY", "progress": 100,
                **final_output, "final_output": final_output,
                "completed_at": datetime.now().isoformat(),
            })
        except Exception as error:
            logger.exception("Scan %s failed", scan_id)
            cls._write_scan_state(workspace_path, {
                "status": "FAILED", "stage": "FAILED", "failed_stage": active_stage,
                "error": str(error), "progress": 100,
                "completed_at": datetime.now().isoformat(),
            })

    @staticmethod
    def get_scan_status(scan_id: str) -> Dict[str, Any]:
        """Get scan status by scan ID."""
        try:
            # Look for scan state in workspaces
            workspace_path = ScanService._workspaces_root() / scan_id

            if not workspace_path.exists():
                return {"scan_id": scan_id, "status": "not_found"}

            # Try to read scan_state.json
            state_path = workspace_path / "scan_state.json"
            if state_path.exists():
                with open(state_path, 'r', encoding='utf-8') as f:
                    scan_state = json.load(f)
                return scan_state

            # Try to read error state
            error_state_path = ScanService._workspaces_root() / f"{scan_id}_state.json"
            if error_state_path.exists():
                with open(error_state_path, 'r', encoding='utf-8') as f:
                    error_state = json.load(f)
                return error_state

            # Check if tree.json exists (scan completed)
            tree_path = workspace_path / "tree.json"
            if tree_path.exists():
                return {
                    "scan_id": scan_id,
                    "status": "completed",
                    "message": "Scan completed successfully"
                }

            return {"scan_id": scan_id, "status": "unknown"}

        except Exception as e:
            logger.error(f"Error getting scan status for {scan_id}: {e}")
            return {"scan_id": scan_id, "status": "error", "error": str(e)}

    @staticmethod
    def cancel_scan(scan_id: str) -> Dict[str, Any]:
        """Cancel a running scan."""
        try:
            workspace_path = ScanService._workspaces_root() / scan_id

            if not workspace_path.exists():
                return {"scan_id": scan_id, "status": "not_found", "message": "Scan not found"}

            # Mark scan as cancelled
            scan_state = {
                "scan_id": scan_id,
                "status": "cancelled",
                "cancelled_time": datetime.now().isoformat(),
                "message": "Scan was cancelled"
            }

            # Update scan state
            state_path = workspace_path / "scan_state.json"
            with open(state_path, 'w', encoding='utf-8') as f:
                json.dump(scan_state, f, indent=2, ensure_ascii=False)

            return {
                "scan_id": scan_id,
                "status": "cancelled",
                "message": "Scan cancelled successfully"
            }

        except Exception as e:
            logger.error(f"Error cancelling scan {scan_id}: {e}")
            return {"scan_id": scan_id, "status": "error", "error": str(e)}

    @staticmethod
    def get_latest_scan_status() -> Optional[Dict[str, Any]]:
        """Get the latest scan status."""
        try:
            workspaces_path = ScanService._workspaces_root()

            if not workspaces_path.exists():
                return None

            # Find all scan directories
            scan_dirs = [d for d in workspaces_path.iterdir() if d.is_dir() and d.name.startswith("SCAN-")]

            if not scan_dirs:
                return None

            # Do not use directory mtime here. Remediation bundles, report
            # downloads, and checkpoints update an older scan directory and
            # would incorrectly make that scan appear to be the latest one.
            # Prefer the scan lifecycle timestamp persisted in scan_state.json.
            def scan_started_at(scan_dir: Path) -> float:
                state_path = scan_dir / "scan_state.json"
                try:
                    state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
                    stamp = state.get("started_at") or state.get("created_at") or state.get("completed_at")
                    if stamp:
                        return datetime.fromisoformat(str(stamp).replace("Z", "+00:00")).timestamp()
                except (OSError, ValueError, TypeError, json.JSONDecodeError):
                    pass
                return scan_dir.stat().st_mtime

            scan_dirs.sort(key=scan_started_at, reverse=True)

            # Get status of the latest scan
            latest_scan_id = scan_dirs[0].name
            return ScanService.get_scan_status(latest_scan_id)

        except Exception as e:
            logger.error(f"Error getting latest scan status: {e}")
            return None
