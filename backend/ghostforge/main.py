from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from .reputation import blocked_domains, check_hash
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

class HashLookup(BaseModel):
    sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")

@app.get("/api/v1/protection/domains")
def protection_domains():
    return {"domains": blocked_domains()}

@app.post("/api/v1/apk/hash")
def apk_hash(req: HashLookup):
    return {"verdict": "known_malicious" if check_hash(req.sha256) else "unverified"}
