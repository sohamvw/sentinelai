from fastapi import FastAPI

from app.api.routes.scans import router as scan_router

app = FastAPI(
    title="SentinelAI",
    version="0.1.0"
)


@app.get("/")
def root():
    return {
        "message": "SentinelAI Backend Running"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


app.include_router(
    scan_router,
    prefix="/scans",
    tags=["Scans"]
)