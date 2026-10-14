from fastapi import FastAPI, HTTPException, Header
from urllib.parse import unquote
from . import accounts, billing, privacy_intelligence, privacy_removals
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


# Verified-email login is the initial GhostForge account identity.
# Every inventory/household/entitlement operation requires a bearer session.
@app.get("/api/v1/account/me")
def account_me(authorization: str | None = Header(default=None)):
    return accounts.profile(auth_email(authorization))

@app.post("/api/v1/account/devices")
def account_register_device(
    body: accounts.DeviceUpsert, authorization: str | None = Header(default=None)
):
    return accounts.register_device(auth_email(authorization), body)

@app.delete("/api/v1/account/devices/{device_id}")
def account_remove_device(device_id: str, authorization: str | None = Header(default=None)):
    return accounts.remove_device(auth_email(authorization), device_id)

@app.get("/api/v1/family")
def household_info(authorization: str | None = Header(default=None)):
    return accounts.family_info(auth_email(authorization))

@app.post("/api/v1/family")
def household_create(authorization: str | None = Header(default=None)):
    return accounts.create_household(auth_email(authorization))

@app.post("/api/v1/family/invite")
def household_invite(authorization: str | None = Header(default=None)):
    return accounts.issue_invite(auth_email(authorization))

@app.post("/api/v1/family/join")
def household_join(body: accounts.InviteInput,
                   authorization: str | None = Header(default=None)):
    return accounts.join_household(auth_email(authorization), body.invite_code)

@app.delete("/api/v1/family/members/{member_email}")
def household_remove_member(member_email: str,
                            authorization: str | None = Header(default=None)):
    return accounts.remove_member(auth_email(authorization), member_email.strip().lower())

@app.delete("/api/v1/family")
def household_delete(authorization: str | None = Header(default=None)):
    return accounts.delete_household(auth_email(authorization))

@app.delete("/api/v1/account")
def account_delete(authorization: str | None = Header(default=None)):
    return accounts.account_delete(auth_email(authorization))

@app.get("/api/v1/billing/config")
def billing_config():
    import os
    enabled = os.getenv("GHOSTFORGE_PLAY_BILLING_ENABLED", "").lower() == "true"
    return {"enabled": enabled, "product_ids": sorted(billing.allowed_products()) if enabled else [],
            "message": "Google Play billing requires registered products, a Play-distributed app and server verification."}

@app.get("/api/v1/billing/status")
def billing_status(authorization: str | None = Header(default=None)):
    return billing.entitlement(auth_email(authorization))

@app.post("/api/v1/billing/verify")
async def billing_verify(body: billing.PurchaseRequest,
                         authorization: str | None = Header(default=None)):
    return await billing.verify_subscription(auth_email(authorization), body)

# Privacy Shield v0.9: verified-email only; no arbitrary address lookups.
class PrivacyConsent(BaseModel):
    consent: bool = False

@app.post("/api/v1/privacy/stealer-logs")
async def privacy_stealer_logs(
    body: PrivacyConsent, authorization: str | None = Header(default=None)
):
    email = auth_email(authorization)
    if not body.consent:
        raise HTTPException(422, "User must authorize this licensed exposure lookup")
    return await privacy_intelligence.stealer_log_check(email)

@app.get("/api/v1/privacy/optery-status")
async def privacy_optery_status(authorization: str | None = Header(default=None)):
    auth_email(authorization)
    return await privacy_intelligence.optery_status()

@app.post("/api/v1/privacy/optout")
def privacy_optout(
    body: privacy_removals.OptOutSubmission,
    authorization: str | None = Header(default=None)
):
    return privacy_removals.submit(auth_email(authorization), body)

@app.get("/api/v1/privacy/optouts")
def privacy_optout_history(authorization: str | None = Header(default=None)):
    return privacy_removals.history(auth_email(authorization))

@app.delete("/api/v1/privacy/optouts")
def privacy_optout_erase(authorization: str | None = Header(default=None)):
    return privacy_removals.erase(auth_email(authorization))
