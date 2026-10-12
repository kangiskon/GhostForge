"""User-initiated URL scanner. Never requests the submitted website itself."""
import ipaddress
import os
from urllib.parse import urlsplit, urlunsplit
import httpx
from pydantic import BaseModel, Field

class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)

class Signal(BaseModel):
    title: str
    detail: str

class ScanResponse(BaseModel):
    url: str
    host: str
    verdict: str
    lookup: str
    message: str
    threats: list[str] = Field(default_factory=list)
    signals: list[Signal] = Field(default_factory=list)

class InvalidURL(ValueError):
    pass

def normalize(raw: str):
    value = raw.strip()
    if not value or len(value) > 2048 or any(ch.isspace() or ord(ch) < 32 for ch in value):
        raise InvalidURL("Invalid or oversized URL.")
    if "://" not in value:
        value = "https://" + value
    try:
        p = urlsplit(value)
        if p.scheme.lower() not in ("http", "https") or p.username or p.password or not p.hostname:
            raise InvalidURL("Only HTTP(S) URLs without embedded credentials are accepted.")
        host = p.hostname.encode("idna").decode("ascii").lower()
        port = p.port
        if len(host) > 253 or not host:
            raise InvalidURL("Invalid hostname.")
        ip = False
        try:
            ipaddress.ip_address(host)
            ip = True
        except ValueError:
            if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") or not all(c.isalnum() or c == "-" for c in label) for label in host.split(".")):
                raise InvalidURL("Invalid hostname.")
            if "." not in host and host != "localhost":
                raise InvalidURL("Incomplete hostname.")
        netloc = ("[" + host + "]") if ":" in host else host
        if port is not None: netloc += ":" + str(port)
        return urlunsplit((p.scheme.lower(), netloc, p.path or "/", p.query, "")), host, ip
    except (ValueError, UnicodeError) as exc:
        if isinstance(exc, InvalidURL): raise
        raise InvalidURL("Could not parse that URL.") from exc

async def web_risk(url: str):
    key = os.environ.get("WEB_RISK_API_KEY", "").strip()
    if not key:
        return "not_configured", []
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=False) as client:
            response = await client.get("https://webrisk.googleapis.com/v1/uris:search", params=[
                ("uri", url), ("threatTypes", "MALWARE"),
                ("threatTypes", "SOCIAL_ENGINEERING"),
                ("threatTypes", "UNWANTED_SOFTWARE"), ("key", key)])
            response.raise_for_status()
            data = response.json()
        threats = data.get("threat", {}).get("threatTypes", [])
        return "confirmed", threats if isinstance(threats, list) else []
    except (httpx.HTTPError, ValueError, TypeError, AttributeError):
        return "error", []

async def inspect(raw: str):
    url, host, ip = normalize(raw)
    p = urlsplit(url)
    signals = []
    if p.scheme == "http": signals.append(Signal(title="Unencrypted website", detail="Avoid providing sensitive information over HTTP."))
    if ip: signals.append(Signal(title="IP address hostname", detail="Direct IP links need additional verification."))
    if "xn--" in host: signals.append(Signal(title="Punycode", detail="A domain name may be impersonating another website."))
    if host in {"bit.ly", "tinyurl.com", "is.gd", "t.co"}: signals.append(Signal(title="Link shortener", detail="The destination is concealed; redirects were not followed."))
    if p.port not in (None, 80, 443): signals.append(Signal(title="Unusual port", detail="The link uses a nonstandard port."))
    if host.count(".") >= 4: signals.append(Signal(title="Many subdomains", detail="Check the true registered domain."))
    lookup, threats = await web_risk(url)
    if threats:
        verdict = "malicious"
        message = "Listed by the configured reputation provider. Avoid this URL."
    elif signals:
        verdict = "suspicious"
        message = "This URL has warning signs. Check carefully."
    elif lookup == "confirmed":
        verdict = "not_listed"
        message = "Not present on the checked threat lists. Safety is not guaranteed."
    else:
        verdict = "unverified"
        message = "Reputation check unavailable. No safety conclusion is possible."
    return ScanResponse(url=url, host=host, verdict=verdict, lookup=lookup,
                        message=message, threats=threats, signals=signals)
