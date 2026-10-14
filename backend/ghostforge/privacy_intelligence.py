"""Privacy intelligence from licensed providers, for the *verified session email only*.

HIBP stealerLogsByEmail requires Pro tier and verified control of the email domain.
We never accept a target email from the request body or expose harvested passwords.
"""
import os
from urllib.parse import quote
import httpx
from fastapi import HTTPException

HIBP = "https://haveibeenpwned.com/api/v3"

async def stealer_log_check(email: str) -> dict:
    key = os.getenv("HIBP_API_KEY", "").strip()
    if not key:
        return {
            "provider": "Have I Been Pwned",
            "status": "not_configured",
            "checked": False,
            "domains": [],
            "note": "An HIBP Pro API subscription and verified email domain are required."
        }
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
            result = await client.get(
                HIBP + "/stealerLogsByEmail/" + quote(email, safe=""),
                headers={"hibp-api-key": key, "user-agent": "GhostForge-PrivacyShield/0.9"})
        if result.status_code == 404:
            return {"provider": "Have I Been Pwned", "checked": True, "status": "not_listed",
                    "domains": [], "note": "No stealer-log website domains were listed for this verified address."}
        if result.status_code == 403:
            return {"provider": "Have I Been Pwned", "checked": False,
                    "status": "plan_or_domain_not_authorized", "domains": [],
                    "note": "HIBP Pro access and verified control of the email domain are required."}
        if result.status_code in (401, 402):
            return {"provider": "Have I Been Pwned", "checked": False,
                    "status": "invalid_or_insufficient_subscription", "domains": [],
                    "note": "The licensed provider rejected this API subscription."}
        if result.status_code == 429:
            return {"provider": "Have I Been Pwned", "checked": False,
                    "status": "rate_limited", "domains": [],
                    "note": "Provider rate limit reached; retry later."}
        if result.status_code != 200:
            return {"provider": "Have I Been Pwned", "checked": False,
                    "status": "provider_unavailable", "domains": [],
                    "note": "The provider did not complete the check."}
        data = result.json()
        if not isinstance(data, list):
            raise ValueError("Unexpected response")
        # HIBP endpoint returns only website domains; no passwords, emails or victims.
        domains = [d[:253] for d in data if isinstance(d, str) and
                   len(d) <= 253 and "/" not in d and "\\" not in d and
                   "\n" not in d and "@" not in d][:100]
        return {"provider": "Have I Been Pwned", "checked": True,
                "status": "found" if domains else "not_listed", "domains": domains,
                "note": "Stealer-log website domains are evidence of possible credential exposure, not a live compromise assessment."}
    except (httpx.HTTPError, ValueError, TypeError):
        return {"provider": "Have I Been Pwned", "checked": False,
                "status": "provider_unavailable", "domains": [],
                "note": "Stealer-log provider could not complete the check."}


async def optery_status() -> dict:
    """Verify partner API connectivity, not a fictional member/removal status."""
    key = os.getenv("OPTERY_API_KEY", "").strip()
    if not key:
        return {"provider": "Optery", "connected": False, "status": "not_configured",
                "automated_removals_active": False,
                "note": "Obtain an Optery for Business API key and partner access."}
    environment = os.getenv("OPTERY_ENVIRONMENT", "sandbox").strip().lower()
    if environment not in ("sandbox", "production"):
        raise HTTPException(503, "Invalid Optery environment setting")
    if environment == "sandbox" and not key.startswith("sk_test-"):
        return {"provider": "Optery", "connected": False, "status": "invalid_key_type",
                "automated_removals_active": False}
    if environment == "production" and not key.startswith("sk_live-"):
        return {"provider": "Optery", "connected": False, "status": "invalid_key_type",
                "automated_removals_active": False}
    host = ("https://public-api-sandbox.test.optery.com" if environment == "sandbox"
            else "https://business-api.optery.com")
    try:
        async with httpx.AsyncClient(timeout=8, follow_redirects=False) as client:
            response = await client.get(host + "/v1/plans",
                headers={"Authorization": "Bearer " + key})
        return {
            "provider": "Optery",
            "connected": response.status_code == 200,
            "status": ("connected" if response.status_code == 200
                else "credentials_rejected" if response.status_code == 401
                else "rate_limited" if response.status_code == 429 else "unavailable"),
            "environment": environment,
            "automated_removals_active": False,
            "note": "Provider connectivity alone does not create a member, subscription or deletion job. Business onboarding is still required."
        }
    except httpx.HTTPError:
        return {"provider": "Optery", "connected": False, "status": "unavailable",
                "automated_removals_active": False}
