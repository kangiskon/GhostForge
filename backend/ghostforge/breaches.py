"""Verified-email breach checks. Never search unverified addresses."""
import hashlib
import hmac
import os
import re
import secrets
import smtplib
import sqlite3
import ssl
from contextlib import contextmanager
import time
from email.message import EmailMessage
from urllib.parse import quote
import httpx
from fastapi import HTTPException
from pydantic import BaseModel, EmailStr, Field

DB = os.getenv("GHOSTFORGE_STATE_DB", "/data/ghostforge.db")
class EmailInput(BaseModel):
    email: EmailStr
class VerifyInput(EmailInput):
    code: str = Field(pattern=r"^[0-9]{6}$")
class EmailCheck(BaseModel):
    email: str
    checked: bool
    breaches: list[str]
    status: str

def _config():
    secret = os.getenv("GHOSTFORGE_AUTH_SECRET", "")
    if len(secret) < 32:
        raise HTTPException(503, "Email verification not configured")
    return secret.encode()

@contextmanager
def _db():
    path = os.path.abspath(os.getenv("GHOSTFORGE_STATE_DB", DB))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path, timeout=6)
    conn.execute("""CREATE TABLE IF NOT EXISTS challenges(
        email TEXT PRIMARY KEY, code_hash TEXT NOT NULL, expires INTEGER,
        attempts INTEGER DEFAULT 0, last_sent INTEGER, sent_count INTEGER DEFAULT 1,
        window_start INTEGER)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS sessions(
        token_hash TEXT PRIMARY KEY, email TEXT NOT NULL, expires INTEGER)""")
    try:
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()

def _normalize(value: str) -> str:
    return value.strip().lower()

def _hash(value: str) -> str:
    return hmac.new(_config(), value.encode(), hashlib.sha256).hexdigest()

def _mail(email: str, code: str):
    host = os.getenv("SMTP_HOST", "").strip()
    sender = os.getenv("SMTP_FROM", "").strip()
    user = os.getenv("SMTP_USER", "").strip()
    password = os.getenv("SMTP_PASSWORD", "")
    if not (host and sender and user and password):
        raise HTTPException(503, "Email delivery is not configured")
    try:
        port = int(os.getenv("SMTP_PORT", "465"))
    except ValueError:
        raise HTTPException(503, "SMTP port invalid")
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = email
    msg["Subject"] = "GhostForge email verification"
    msg.set_content(
        f"Your GhostForge confirmation code is {code}. It expires in 10 minutes.\n"
        "If you did not request this, you may ignore it."
    )
    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port, context=ssl.create_default_context(), timeout=10) as smtp:
                smtp.login(user, password)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=10) as smtp:
                smtp.starttls(context=ssl.create_default_context())
                smtp.login(user, password)
                smtp.send_message(msg)
    except (OSError, smtplib.SMTPException) as exc:
        raise HTTPException(503, "Verification email could not be delivered") from exc

def request_code(address: str):
    email = _normalize(address)
    now = int(time.time())
    # Never echo the OTP or include it in logs / API responses.
    code = f"{secrets.randbelow(1_000_000):06d}"
    _config()
    with _db() as db:
        # Conservative per-email throttling (also requires infrastructure-level IP limits).
        row = db.execute(
            "SELECT last_sent,sent_count,window_start FROM challenges WHERE email=?",
            (email,)
        ).fetchone()
        if row:
            sent, count, start = row
            if now - sent < 90:
                raise HTTPException(429, "Try again later")
            if now - start < 3600 and count >= 3:
                raise HTTPException(429, "Verification limit reached")
            next_count = count + 1 if now - start < 3600 else 1
            start = start if now - start < 3600 else now
        else:
            next_count, start = 1, now
        # Send before saving so delivery failure does not consume the code.
        _mail(email, code)
        db.execute("""INSERT INTO challenges
            (email,code_hash,expires,attempts,last_sent,sent_count,window_start)
            VALUES(?,?,?,?,?,?,?)
            ON CONFLICT(email) DO UPDATE SET code_hash=excluded.code_hash,
            expires=excluded.expires,attempts=0,last_sent=excluded.last_sent,
            sent_count=excluded.sent_count,window_start=excluded.window_start""",
            (email, _hash(email + ":" + code), now + 600, 0, now, next_count, start))
    return {"message": "If delivery is configured, your verification code has been sent."}

def verify_code(address: str, code: str):
    email = _normalize(address)
    now = int(time.time())
    with _db() as db:
        row = db.execute(
            "SELECT code_hash,expires,attempts FROM challenges WHERE email=?", (email,)
        ).fetchone()
        if not row or row[1] <= now or row[2] >= 5:
            raise HTTPException(400, "Invalid or expired verification code")
        db.execute("UPDATE challenges SET attempts=attempts+1 WHERE email=?", (email,))
        if not hmac.compare_digest(row[0], _hash(email + ":" + code)):
            raise HTTPException(400, "Invalid or expired verification code")
        token = secrets.token_urlsafe(32)
        db.execute("DELETE FROM challenges WHERE email=?", (email,))
        db.execute("DELETE FROM sessions WHERE email=?", (email,))
        db.execute(
            "INSERT INTO sessions(token_hash,email,expires) VALUES(?,?,?)",
            (_hash(token), email, now + 60 * 60 * 24 * 30))
    return {"token": token, "email": email, "expires_in": 60 * 60 * 24 * 30}

def auth_email(bearer: str | None):
    if not bearer or not bearer.startswith("Bearer "):
        raise HTTPException(401, "Verified email session required")
    token = bearer.removeprefix("Bearer ").strip()
    if len(token) < 30:
        raise HTTPException(401, "Invalid session")
    with _db() as db:
        row = db.execute("SELECT email,expires FROM sessions WHERE token_hash=?", (_hash(token),)).fetchone()
    if row is None or row[1] <= int(time.time()):
        raise HTTPException(401, "Verification expired")
    return row[0]

async def breach_lookup(email: str):
    key = os.getenv("HIBP_API_KEY", "").strip()
    if not key:
        return EmailCheck(email=email, checked=False, breaches=[], status="provider_not_configured")
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
            result = await client.get(
                "https://haveibeenpwned.com/api/v3/breachedaccount/" + quote(email, safe=""),
                params={"truncateResponse": "true"},
                headers={"hibp-api-key": key, "user-agent": "GhostForge-security-app/0.3"}
            )
        if result.status_code == 404:
            return EmailCheck(email=email, checked=True, breaches=[], status="not_listed")
        if result.status_code != 200:
            return EmailCheck(email=email, checked=False, breaches=[], status="provider_unavailable")
        data = result.json()
        names = [str(item.get("Name", "")) for item in data if isinstance(item, dict)]
        names = [n for n in names if n][:100]
        return EmailCheck(email=email, checked=True, breaches=names, status="found" if names else "not_listed")
    except (httpx.HTTPError, ValueError, TypeError, AttributeError):
        return EmailCheck(email=email, checked=False, breaches=[], status="provider_unavailable")

def erase(bearer: str | None):
    email = auth_email(bearer)
    with _db() as db:
        db.execute("DELETE FROM sessions WHERE email=?", (email,))
        db.execute("DELETE FROM challenges WHERE email=?", (email,))
    return {"deleted": True, "message": "GhostForge verification session records deleted"}
