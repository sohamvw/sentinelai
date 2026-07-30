from app.services.scan_manager import ScanManager
from app.services.workspace_manager import WorkspaceManager
from app.services.clone_manager import CloneManager


class ScanService:

    @staticmethod
    def create_scan(request):

        # Create Scan
        scan = ScanManager.create_scan(
            repository_url=str(request.github_url)
        )

        # Create Workspace
        workspace = WorkspaceManager.create_workspace(scan)
        scan.workspace = str(workspace)

        # Clone Repository
        CloneManager.clone(scan)

        # Return Response
        return {
            "scan_id": scan.scan_id,
            "status": scan.status,
            "message": "Repository scan created successfully."
        }