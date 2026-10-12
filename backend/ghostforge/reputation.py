"""Explicitly configured operator-curated lists; empty lists mean unverified."""
import os
import re

def _split(name: str):
    return re.split(r"[\s,;]+", os.getenv(name, "").strip())

def blocked_domains():
    out = []
    for item in _split("BLOCKED_DOMAINS"):
        d = item.strip().lower().strip(".")
        if len(d) in range(4, 254) and "." in d and re.fullmatch(r"[a-z0-9.-]+", d) and ".." not in d:
            out.append(d)
    return sorted(set(out))[:20000]

def check_hash(value: str) -> bool:
    hashes = {item.lower() for item in _split("KNOWN_BAD_APK_SHA256")
              if re.fullmatch(r"[0-9a-fA-F]{64}", item)}
    return value.lower() in hashes
