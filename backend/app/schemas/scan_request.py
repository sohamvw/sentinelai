from pydantic import BaseModel, HttpUrl


class ScanRequest(BaseModel):
    github_url: HttpUrl