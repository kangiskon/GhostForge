"""Authenticated account, household and device inventory API.

All records are scoped to a verified email session from breaches.auth_email.
No physical device identifiers are collected: clients generate random UUIDs.
A household does not grant paid benefits by itself.
"""
import os
import re
import secrets
import time
import uuid
from fastapi import HTTPException
from pydantic import BaseModel, Field
from .breaches import _db, _hash, auth_email

MAX_HOUSEHOLD = 5
MAX_DEVICES = 6
MAX_LABEL = 60

class DeviceUpsert(BaseModel):
    device_id: uuid.UUID
    label: str = Field(min_length=1, max_length=MAX_LABEL)

class InviteInput(BaseModel):
    invite_code: str = Field(min_length=18, max_length=128)

def _setup(db):
    db.execute("""CREATE TABLE IF NOT EXISTS gf_devices (
        account TEXT NOT NULL,
        device_id TEXT NOT NULL,
        label TEXT NOT NULL,
        last_seen INTEGER NOT NULL,
        PRIMARY KEY (account, device_id))""")
    db.execute("""CREATE TABLE IF NOT EXISTS gf_households (
        id TEXT PRIMARY KEY, owner TEXT NOT NULL UNIQUE, created INTEGER NOT NULL)""")
    db.execute("""CREATE TABLE IF NOT EXISTS gf_household_members (
        member TEXT PRIMARY KEY, household TEXT NOT NULL,
        joined INTEGER NOT NULL)""")
    db.execute("""CREATE TABLE IF NOT EXISTS gf_household_invites (
        digest TEXT PRIMARY KEY, household TEXT NOT NULL,
        created INTEGER NOT NULL, expires INTEGER NOT NULL)""")

def _household(db, email):
    row = db.execute("""SELECT h.id, h.owner
        FROM gf_households h JOIN gf_household_members m ON m.household=h.id
        WHERE m.member=?""", (email,)).fetchone()
    return row

def _devices(db, email):
    return [{"id":i, "label":label, "last_seen":at} for i,label,at in
        db.execute("""SELECT device_id,label,last_seen FROM gf_devices
            WHERE account=? ORDER BY last_seen DESC""", (email,)).fetchall()]

def profile(email):
    with _db() as db:
        _setup(db)
        household = _household(db, email)
        count = 0
        if household:
            count = db.execute(
                "SELECT COUNT(*) FROM gf_household_members WHERE household=?",
                (household[0],)).fetchone()[0]
        return {
            "email": email,
            "verified": True,
            "devices": _devices(db, email),
            "household_role": ("owner" if household[1] == email else "member") if household else "none",
            "household_members": count,
            "account_type": "verified_email_beta"
        }

def register_device(email, request: DeviceUpsert):
    ident = str(request.device_id)
    label = request.label.strip()
    if not label:
        raise HTTPException(422, "Device name cannot be empty")
    now = int(time.time())
    with _db() as db:
        _setup(db)
        existing = db.execute(
            "SELECT 1 FROM gf_devices WHERE account=? AND device_id=?",
            (email, ident)).fetchone()
        if not existing:
            count = db.execute(
                "SELECT COUNT(*) FROM gf_devices WHERE account=?", (email,)).fetchone()[0]
            if count >= MAX_DEVICES:
                raise HTTPException(409, "Maximum registered devices reached")
        db.execute("""INSERT INTO gf_devices(account,device_id,label,last_seen) VALUES(?,?,?,?)
            ON CONFLICT(account,device_id) DO UPDATE SET
            label=excluded.label,last_seen=excluded.last_seen""", (email,ident,label,now))
    return {"registered": True, "device_id": ident}

def remove_device(email, ident):
    try:
        value = str(uuid.UUID(ident))
    except ValueError as exc:
        raise HTTPException(422, "Invalid device ID") from exc
    with _db() as db:
        _setup(db)
        count = db.execute(
            "DELETE FROM gf_devices WHERE account=? AND device_id=?",
            (email, value)).rowcount
    return {"removed": bool(count)}

def family_info(email):
    with _db() as db:
        _setup(db)
        item = _household(db, email)
        if not item:
            return {"role": "none", "members": [], "owner": None, "household_id": None}
        group, owner = item
        members = [
            {"email": e, "role": "owner" if e == owner else "member"}
            for (e,) in db.execute(
                "SELECT member FROM gf_household_members WHERE household=? ORDER BY joined",
                (group,)).fetchall()
        ]
        return {"role": "owner" if owner == email else "member",
                "members": members, "owner": owner, "household_id": group}

def create_household(email):
    with _db() as db:
        _setup(db)
        if _household(db, email):
            raise HTTPException(409, "Account already belongs to a household")
        ident = str(uuid.uuid4())
        now = int(time.time())
        db.execute("INSERT INTO gf_households VALUES(?,?,?)", (ident,email,now))
        db.execute("INSERT INTO gf_household_members VALUES(?,?,?)", (email,ident,now))
    return family_info(email)

def issue_invite(email):
    with _db() as db:
        _setup(db)
        item = _household(db, email)
        if not item or item[1] != email:
            raise HTTPException(403, "Only a household owner can issue invitations")
        group, _ = item
        count = db.execute("SELECT COUNT(*) FROM gf_household_members WHERE household=?", (group,)).fetchone()[0]
        if count >= MAX_HOUSEHOLD:
            raise HTTPException(409, "Household is full")
        db.execute("DELETE FROM gf_household_invites WHERE household=?", (group,))
        code = secrets.token_urlsafe(20)
        now = int(time.time())
        db.execute("INSERT INTO gf_household_invites VALUES(?,?,?,?)",
                   (_hash(code),group,now,now+3600))
    # Shown once to the owner; not logged or sent to arbitrary addresses.
    return {"invite_code": code, "expires_in": 3600, "single_use": True}

def join_household(email, code):
    now = int(time.time())
    with _db() as db:
        _setup(db)
        if _household(db,email):
            raise HTTPException(409, "Leave your current household first")
        row = db.execute("SELECT household,expires FROM gf_household_invites WHERE digest=?",
                         (_hash(code),)).fetchone()
        if not row or row[1] <= now:
            raise HTTPException(400, "Invite has expired or was already used")
        group = row[0]
        count = db.execute("SELECT COUNT(*) FROM gf_household_members WHERE household=?",
                           (group,)).fetchone()[0]
        if count >= MAX_HOUSEHOLD:
            raise HTTPException(409, "Household is full")
        db.execute("INSERT INTO gf_household_members VALUES(?,?,?)", (email,group,now))
        db.execute("DELETE FROM gf_household_invites WHERE digest=?", (_hash(code),))
    return family_info(email)

def remove_member(email, member):
    with _db() as db:
        _setup(db)
        group = _household(db,email)
        if not group:
            raise HTTPException(404, "No household")
        if member == email and group[1] != email:
            db.execute("DELETE FROM gf_household_members WHERE member=?", (email,))
            return {"removed": True}
        if group[1] != email:
            raise HTTPException(403, "Only owners may remove other members")
        if member == email:
            raise HTTPException(400, "Owner must delete household or account")
        result = db.execute("DELETE FROM gf_household_members WHERE household=? AND member=?",
                           (group[0],member))
        return {"removed": result.rowcount > 0}

def delete_household(email):
    with _db() as db:
        _setup(db)
        item = _household(db,email)
        if not item or item[1] != email:
            raise HTTPException(403, "Only household owner can delete it")
        db.execute("DELETE FROM gf_household_invites WHERE household=?", (item[0],))
        db.execute("DELETE FROM gf_household_members WHERE household=?", (item[0],))
        db.execute("DELETE FROM gf_households WHERE id=?", (item[0],))
    return {"deleted": True}

def account_delete(email):
    # Delete account-specific records including verification sessions.
    with _db() as db:
        _setup(db)
        item = _household(db,email)
        if item and item[1] == email:
            db.execute("DELETE FROM gf_household_invites WHERE household=?", (item[0],))
            db.execute("DELETE FROM gf_household_members WHERE household=?", (item[0],))
            db.execute("DELETE FROM gf_households WHERE id=?", (item[0],))
        else:
            db.execute("DELETE FROM gf_household_members WHERE member=?", (email,))
        db.execute("DELETE FROM gf_devices WHERE account=?", (email,))
        db.execute("DELETE FROM sessions WHERE email=?", (email,))
        db.execute("DELETE FROM challenges WHERE email=?", (email,))
        # Entitlement records are removed too; billing obligations and subscriptions
        # must still be canceled separately through Google Play.
        db.execute("""CREATE TABLE IF NOT EXISTS gf_entitlements (
            email TEXT PRIMARY KEY,product TEXT,token_hash TEXT UNIQUE,expires TEXT,updated INTEGER)""")
        db.execute("DELETE FROM gf_entitlements WHERE email=?", (email,))
    return {"deleted": True, "subscription_not_canceled": True}
