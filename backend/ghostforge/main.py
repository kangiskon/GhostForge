from fastapi import FastAPI, HTTPException
from .scanner import ScanRequest, ScanResponse, InvalidURL, inspect

app = FastAPI(title="GhostForge Scanner", version="0.1.0")

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/api/v1/scan", response_model=ScanResponse)
async def scan(req: ScanRequest):
    try:
        return await inspect(req.url)
    except InvalidURL as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
