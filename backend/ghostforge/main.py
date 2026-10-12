from fastapi import FastAPI, HTTPException, Header
from .scams import ScamRequest, ScamResponse, investigate
from .breaches import EmailInput, VerifyInput, request_code, verify_code, auth_email, breach_lookup, erase
from pydantic import BaseModel, Field
from .reputation import blocked_domains, check_hash
from .scanner import ScanRequest, ScanResponse, InvalidURL, inspect

app = FastAPI(title="GhostForge Scanner", version="0.3.0")

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

@app.post("/api/v1/scams/analyze", response_model=ScamResponse)
async def analyze_scam(body: ScamRequest):
    return await investigate(body)

@app.post("/api/v1/breach/request-code")
def breach_request(body: EmailInput):
    return request_code(str(body.email))

@app.post("/api/v1/breach/verify")
def breach_verify(body: VerifyInput):
    return verify_code(str(body.email), body.code)

@app.get("/api/v1/breach/check")
async def breach_check(authorization: str | None = Header(default=None)):
    return await breach_lookup(auth_email(authorization))

@app.post("/api/v1/breach/delete")
def breach_delete(authorization: str | None = Header(default=None)):
    return erase(authorization)
