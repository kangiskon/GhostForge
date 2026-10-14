"""Conservative, verified-user opt-out request submission via the user's own SMTP backend.

A successful SMTP send only proves the message was accepted by the SMTP server.
It does NOT mean an information broker removed anything. No universal deletion.
"""
from contextlib import contextmanager
from email.message import EmailMessage
import os
import re
import smtplib
import sqlite3
import ssl
import time
import uuid
from urllib.parse import urlsplit
from fastapi import HTTPException
from pydantic import BaseModel, EmailStr, Field

class OptOutSubmission(BaseModel):
    site: str = Field(min_length=4, max_length=253)
    contact: EmailStr
    consent: bool

DB = os.getenv("GHOSTFORGE_STATE_DB", "/data/ghostforge.db")

def _site(value: str) -> str:
    source = value.strip().lower()
    if any(x in source for x in ("/", ":", "@", "\\", "?", "#", " ", "\n", "\r")):
        raise HTTPException(422, "Use only the public website's domain, not a URL.")
    try:
        host = source.encode("idna").decode("ascii")
    except UnicodeError as err:
        raise HTTPException(422, "Invalid website hostname") from err
    if (len(host) > 253 or "." not in host or
        host.endswith((".local", ".test", ".internal", ".invalid", ".onion", ".localhost")) or
        not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x)
                for x in host.split("."))):
        raise HTTPException(422, "A public website hostname is required.")
    return host

def _recipient(site: str, contact: str):
    address = contact.strip().lower()
    maildomain = address.rsplit("@", 1)[-1]
    # Never become a generic third-party bulk mailing endpoint. Only allow an
    # explicitly entered privacy contact at the matching public domain.
    if maildomain != site and not maildomain.endswith("." + site):
        raise HTTPException(422, "Contact email must belong to the listing site's domain.")
    return address

@contextmanager
def _db():
    path = os.path.abspath(os.getenv("GHOSTFORGE_STATE_DB", DB))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    db = sqlite3.connect(path, timeout=10, isolation_level=None)
    db.execute("""CREATE TABLE IF NOT EXISTS privacy_optouts(
         request_id TEXT PRIMARY KEY,
         owner_email TEXT NOT NULL,
         website TEXT NOT NULL,
         contact TEXT NOT NULL,
         created_at INTEGER NOT NULL,
         updated_at INTEGER NOT NULL,
         status TEXT NOT NULL)""")
    try:
        yield db
    finally:
        db.close()

def _send(email: str, contact: str, site: str):
    host = os.getenv("SMTP_HOST", "").strip()
    from_address = os.getenv("SMTP_FROM", "").strip()
    user = os.getenv("SMTP_USER", "").strip()
    password = os.getenv("SMTP_PASSWORD", "")
    if not (host and from_address and user and password):
        raise HTTPException(503, "SMTP delivery is not configured")
    try:
        port = int(os.getenv("SMTP_PORT", "465"))
    except ValueError:
        raise HTTPException(503, "Invalid SMTP configuration")
    msg = EmailMessage()
    msg["From"] = from_address
    msg["Reply-To"] = email
    msg["To"] = contact
    msg["Subject"] = "Privacy information opt-out request"
    msg.set_content(
        "Hello Privacy Team,\n\n"
        "I am the owner of the verified reply-to email address for this request. "
        "Please remove or suppress any public people-search or data-broker listing "
        "on " + site + " associated with this email address, subject to applicable law.\n"
        "If no listing exists, please confirm, or provide the official secure process "
        "and minimum necessary verification required. Do not request passwords or OTP codes.\n\n"
        "Please reply to the verified Reply-To address.\nThank you."
    )
    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port, context=ssl.create_default_context(), timeout=12) as smtp:
                smtp.login(user, password)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=12) as smtp:
                smtp.starttls(context=ssl.create_default_context())
                smtp.login(user, password)
                smtp.send_message(msg)
    except (OSError, smtplib.SMTPException) as err:
        raise HTTPException(503, "Email submission failed. No deletion was confirmed.") from err

def submit(email: str, req: OptOutSubmission):
    if not req.consent:
        raise HTTPException(422, "Explicit consent is required for every new contact.")
    site = _site(req.site)
    target = _recipient(site, str(req.contact))
    now = int(time.time())
    # 2 submissions/user/24h + at most 1 request/site/user/30 days.
    with _db() as db:
        db.execute("BEGIN IMMEDIATE")
        try:
            count = db.execute("""SELECT COUNT(*) FROM privacy_optouts
                WHERE owner_email=? AND created_at>?""", (email, now - 86400)).fetchone()[0]
            recent = db.execute("""SELECT 1 FROM privacy_optouts
                WHERE owner_email=? AND website=? AND created_at>?""",
                (email, site, now - 30*86400)).fetchone()
            if count >= 2 or recent:
                raise HTTPException(429, "Opt-out request frequency limit reached; review prior requests.")
            rid = str(uuid.uuid4())
            db.execute("""INSERT INTO privacy_optouts
                (request_id,owner_email,website,contact,created_at,updated_at,status)
                VALUES (?,?,?,?,?,?,?)""",
                (rid,email,site,target,now,now,"pending"))
            db.execute("COMMIT")
        except Exception:
            db.execute("ROLLBACK")
            raise
    try:
        _send(email,target,site)
    except Exception:
        with _db() as db:
            db.execute("""UPDATE privacy_optouts SET status='submission_failed',updated_at=?
                WHERE request_id=? AND owner_email=?""", (int(time.time()),rid,email))
        raise
    with _db() as db:
        db.execute("""UPDATE privacy_optouts SET status='submitted_to_smtp',updated_at=?
            WHERE request_id=? AND owner_email=?""", (int(time.time()),rid,email))
    return {
        "request_id": rid, "site": site, "status": "submitted_to_smtp",
        "removal_confirmed": False,
        "message": "Sent to the site's configured privacy mailbox. No removal is confirmed."
    }

def history(email: str):
    with _db() as db:
        rows = db.execute("""SELECT request_id,website,created_at,status FROM privacy_optouts
            WHERE owner_email=? ORDER BY created_at DESC LIMIT 100""", (email,)).fetchall()
    return {"items":[{"request_id":r[0],"site":r[1],"created_at":r[2],
                       "status":r[3], "removal_confirmed":False} for r in rows]}

def erase(email: str):
    with _db() as db:
        db.execute("DELETE FROM privacy_optouts WHERE owner_email=?", (email,))
    return {"deleted": True, "note": "GhostForge removed its own submission log; third parties are unaffected."}
