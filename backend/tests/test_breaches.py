import pytest
from fastapi import HTTPException
from ghostforge import breaches

def test_breach_access_requires_verified_token(tmp_path, monkeypatch):
    monkeypatch.setenv("GHOSTFORGE_STATE_DB", str(tmp_path / "auth.db"))
    monkeypatch.setenv("GHOSTFORGE_AUTH_SECRET", "this-is-a-32-character-or-longer-development-key")
    with pytest.raises(HTTPException) as exc:
        breaches.auth_email(None)
    assert exc.value.status_code == 401

def test_verified_email_session_lifecycle(tmp_path, monkeypatch):
    monkeypatch.setenv("GHOSTFORGE_STATE_DB", str(tmp_path / "auth.db"))
    monkeypatch.setenv("GHOSTFORGE_AUTH_SECRET", "this-is-a-32-character-or-longer-development-key")
    sent = {}
    monkeypatch.setattr(breaches, "_mail", lambda email, code: sent.update(email=email, code=code))
    answer = breaches.request_code("myaddress@example.com")
    assert "code" not in answer
    with pytest.raises(HTTPException):
        breaches.verify_code("myaddress@example.com", "123456" if sent["code"] != "123456" else "654321")
    result = breaches.verify_code("myaddress@example.com", sent["code"])
    token = result["token"]
    assert token != sent["code"]
    assert breaches.auth_email("Bearer " + token) == "myaddress@example.com"
    assert breaches.erase("Bearer " + token)["deleted"] is True
    with pytest.raises(HTTPException):
        breaches.auth_email("Bearer " + token)

@pytest.mark.asyncio
async def test_provider_unconfigured_is_not_a_clean_bill(monkeypatch):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    response = await breaches.breach_lookup("verified@example.com")
    assert response.checked is False
    assert response.status == "provider_not_configured"
