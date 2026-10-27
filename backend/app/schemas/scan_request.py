from pydantic import BaseModel, Field, validator
from typing import Optional, Literal
import re

class ScanRequest(BaseModel):
    """Request model for creating a new repository scan."""

    # Repository source type
    source_type: Literal["github", "zip"] = Field("github", description="Source type: github or zip")

    # Repository URL or identifier
    repository_url: Optional[str] = Field(None, description="GitHub repository URL or ZIP file URL")

    # Branch/tag to scan (default: main)
    branch: str = Field("main", description="Repository branch to scan")

    # Framework/language preferences (optional)
    preferred_languages: Optional[list[str]] = Field(None, description="List of preferred programming languages")

    # Framework preferences (optional)
    preferred_frameworks: Optional[list[str]] = Field(None, description="List of preferred frameworks")

    # Metadata for tracking
    scan_name: Optional[str] = Field(None, description="Optional custom name for the scan")
    user_id: Optional[str] = Field(None, description="User ID initiating the scan")
    sector: str = Field("rbi_fintech", description="Selected compliance control pack")
    policy_document_text: Optional[str] = Field(None, description="Optional uploaded policy text")
    policy_filename: Optional[str] = Field(None, description="Original policy file name")

    @validator('repository_url')
    def validate_repository_url(cls, v, values):
        """Validate repository URL based on source_type."""
        source_type = values.get('source_type')

        if source_type == "github":
            if not v:
                raise ValueError("repository_url is required for github source_type")

            # GitHub URL patterns
            github_patterns = [
                r'^https?://github\.com/[^/]+/[^/]+/?(\.git)?$',
                r'^https?://github\.com/[^/]+/[^/]+\.git$',
                r'^[^/]+/[^/]+$',  # owner/repo format
            ]

            if not any(re.match(pattern, v.strip()) for pattern in github_patterns):
                raise ValueError("Invalid GitHub repository URL format. Expected: https://github.com/owner/repo or owner/repo")

        elif source_type == "zip":
            if not v:
                raise ValueError("repository_url is required for zip source_type")

            # ZIP URL should end with .zip
            if not v.lower().endswith('.zip'):
                raise ValueError("ZIP repository URL must end with .zip extension")

        return v.strip()

    @validator('branch')
    def validate_branch(cls, v):
        """Validate branch name."""
        if not v or not v.strip():
            raise ValueError("Branch cannot be empty")

        # Basic branch name validation
        if len(v) > 255:
            raise ValueError("Branch name too long (max 255 characters)")

        # Common branch name characters
        if not re.match(r'^[a-zA-Z0-9_/.\-]+$', v.strip()):
            raise ValueError("Branch name contains invalid characters. Use alphanumeric, underscore, slash, dot, or hyphen only")

        return v.strip()

    def get_repository_identifier(self) -> str:
        """Extract repository owner/repo from GitHub URL."""
        if self.source_type == "github" and self.repository_url:
            url = self.repository_url.strip()

            # Handle various GitHub URL formats
            if url.startswith(('http://', 'https://')):
                # Extract from URL: https://github.com/owner/repo
                parts = url.replace('https://github.com/', '').replace('http://github.com/', '').split('/')
            else:
                # Handle owner/repo format directly
                parts = url.split('/')

            if len(parts) >= 2:
                return f"{parts[0]}/{parts[1]}"

        return "unknown"
