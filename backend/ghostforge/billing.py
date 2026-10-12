"""Google Play subscription verification. Never trusts purchase/price from Android.

Play API service-account access, product identifiers and Play Console setup are
required. If not configured, purchases are unavailable, not silently accepted.
"""
import datetime as dt
import os
import re
import time
from urllib.parse import quote
import httpx
from fastapi import HTTPException
from pydantic import BaseModel, Field
from .breaches import _db, _hash

PACKAGE = "com.ghostforge.app"

class PurchaseRequest(BaseModel):
    token: str = Field(min_length=20, max_length=600)

def allowed_products():
    configured = os.getenv("GHOSTFORGE_PLAY_PRODUCTS", "")
    return {
        s.strip() for s in configured.split(",")
        if re.fullmatch(r"[a-zA-Z0-9._]+", s.strip())
    }

def _setup(db):
    db.execute("""CREATE TABLE IF NOT EXISTS gf_entitlements (
        email TEXT PRIMARY KEY,
        product TEXT,
        token_hash TEXT UNIQUE,
        expires TEXT,
        updated INTEGER
    )""")

def _expiry(value):
    try:
        return dt.datetime.fromisoformat(value.replace("Z","+00:00"))
    except (ValueError, AttributeError, TypeError):
        return None

def _active(state, expiry):
    return state in {
        "SUBSCRIPTION_STATE_ACTIVE",
        "SUBSCRIPTION_STATE_IN_GRACE_PERIOD",
        "SUBSCRIPTION_STATE_CANCELED"
    } and expiry is not None and expiry > dt.datetime.now(dt.timezone.utc)

async def _google_check(purchase_token):
    if os.getenv("GHOSTFORGE_PLAY_BILLING_ENABLED", "").lower() != "true":
        raise HTTPException(503, "Google Play billing is disabled on this server")
    if not allowed_products():
        raise HTTPException(503, "Play products are not configured")
    # Obtains a scoped short-lived access token from the configured server service account.
    try:
        import google.auth
        import google.auth.transport.requests
        from google.oauth2 import service_account
        import asyncio

        def token_task():
            credentials, _ = google.auth.default(
                scopes=["https://www.googleapis.com/auth/androidpublisher"])
            credentials.refresh(google.auth.transport.requests.Request())
            return credentials.token
        access = await asyncio.to_thread(token_task)
    except Exception as exc:
        raise HTTPException(503, "Play Developer API credentials unavailable") from exc
    try:
        async with httpx.AsyncClient(timeout=12, follow_redirects=False) as client:
            response = await client.get(
                "https://androidpublisher.googleapis.com/androidpublisher/v3/applications/"
                + PACKAGE + "/purchases/subscriptionsv2/tokens/"
                + quote(purchase_token, safe=""),
                headers={"Authorization": "Bearer " + access})
        if response.status_code != 200:
            # Avoid leaking opaque Play server responses to the client.
            raise HTTPException(503 if response.status_code >= 500 else 422,
                                "Google Play could not verify this subscription")
        return response.json()
    except httpx.HTTPError as exc:
        raise HTTPException(503, "Google Play verification is temporarily unavailable") from exc

async def verify_subscription(email, req):
    info = await _google_check(req.token)
    state = str(info.get("subscriptionState", ""))
    lines = info.get("lineItems", [])
    if not isinstance(lines, list):
        raise HTTPException(422, "Invalid Google Play subscription response")
    matches = []
    for item in lines:
        product = item.get("productId")
        expiry = _expiry(item.get("expiryTime"))
        if product in allowed_products() and _active(state, expiry):
            matches.append((product, expiry))
    if not matches:
        raise HTTPException(403, "Subscription is inactive, expired, or not one of GhostForge's configured products")
    product, expiry = max(matches, key=lambda p: p[1])
    digest = _hash("purchase:" + req.token)
    with _db() as db:
        _setup(db)
        owned = db.execute("SELECT email FROM gf_entitlements WHERE token_hash=?", (digest,)).fetchone()
        if owned and owned[0] != email:
            raise HTTPException(409, "This purchase is linked to another verified account")
        db.execute("""INSERT INTO gf_entitlements(email,product,token_hash,expires,updated)
            VALUES(?,?,?,?,?) ON CONFLICT(email) DO UPDATE SET
            product=excluded.product,token_hash=excluded.token_hash,
            expires=excluded.expires,updated=excluded.updated""",
            (email,product,digest,expiry.isoformat(),int(time.time())))
    return {"plan": product, "verified": True, "expires": expiry.isoformat(),
            "status": "verified_play_purchase"}

def entitlement(email):
    with _db() as db:
        _setup(db)
        row = db.execute("SELECT product,expires,updated FROM gf_entitlements WHERE email=?",
                         (email,)).fetchone()
    if not row:
        return {"plan":"free", "verified":False, "status":"no_subscription"}
    product, expires, refreshed = row
    expire = _expiry(expires)
    if not expire or expire <= dt.datetime.now(dt.timezone.utc):
        return {"plan":"free", "verified":False, "status":"expired"}
    if time.time() - refreshed > 3 * 3600:
        return {"plan":"free", "verified":False, "status":"reverification_required"}
    return {"plan":product, "verified":True, "expires":expires, "status":"recently_verified"}
