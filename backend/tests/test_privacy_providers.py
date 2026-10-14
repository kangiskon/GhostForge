import pytest
from fastapi import HTTPException
from ghostforge import privacy_intelligence, privacy_removals
import httpx


@pytest.mark.asyncio
async def test_darkweb_feed_missing_credentials_never_means_clean(monkeypatch):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    result = await privacy_intelligence.stealer_log_check("verified@example.com")
    assert result["status"] == "not_configured"
    assert result["checked"] is False
    assert result["domains"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("status,expected,checked", [
    (404,"not_listed",True), (403,"plan_or_domain_not_authorized",False),
    (401,"invalid_or_insufficient_subscription",False), (429,"rate_limited",False),
    (503,"provider_unavailable",False)
])
async def test_stealer_lookup_status_mapped_safely(monkeypatch,status,expected,checked):
    monkeypatch.setenv("HIBP_API_KEY","a"*32)
    seen = {}
    class FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self,*args): return None
        async def get(self,url,headers):
            seen["url"] = url
            seen["headers"] = headers
            return httpx.Response(status, json={"message":"mock"})
    monkeypatch.setattr(privacy_intelligence.httpx,"AsyncClient",lambda **k:FakeClient())
    res = await privacy_intelligence.stealer_log_check("verified+test@example.com")
    assert res["status"] == expected
    assert res["checked"] is checked
    assert "verified%2Btest%40example.com" in seen["url"]
    assert "hibp-api-key" in seen["headers"]


@pytest.mark.asyncio
async def test_stealer_domains_from_licensed_provider(monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY","a"*32)
    class FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self,*args): return None
        async def get(self,url,headers):
            return httpx.Response(200, json=["example.net","accounts.example.com","evil/path"])
    monkeypatch.setattr(privacy_intelligence.httpx,"AsyncClient",lambda **k:FakeClient())
    report=await privacy_intelligence.stealer_log_check("user@example.com")
    assert report["checked"] is True
    assert report["status"] == "found"
    assert report["domains"] == ["example.net","accounts.example.com"]


@pytest.mark.asyncio
async def test_optery_unconfigured_has_no_active_removals(monkeypatch):
    monkeypatch.delenv("OPTERY_API_KEY",raising=False)
    res=await privacy_intelligence.optery_status()
    assert res["connected"] is False
    assert res["automated_removals_active"] is False


@pytest.mark.asyncio
async def test_optery_connected_does_not_mean_enrolled(monkeypatch):
    monkeypatch.setenv("OPTERY_API_KEY","sk_test-example")
    monkeypatch.setenv("OPTERY_ENVIRONMENT","sandbox")
    class FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self,*args): return None
        async def get(self,url,headers):
            assert url=="https://public-api-sandbox.test.optery.com/v1/plans"
            assert headers["Authorization"].startswith("Bearer sk_test-")
            return httpx.Response(200,json=[])
    monkeypatch.setattr(privacy_intelligence.httpx,"AsyncClient",lambda **k:FakeClient())
    res=await privacy_intelligence.optery_status()
    assert res["connected"] is True
    assert res["automated_removals_active"] is False


def test_automated_optout_requires_consent_and_matching_broker_mailbox(tmp_path,monkeypatch):
    monkeypatch.setenv("GHOSTFORGE_STATE_DB",str(tmp_path/"privacy.sqlite"))
    sends=[]
    monkeypatch.setattr(privacy_removals,"_send",lambda email,contact,site:sends.append((email,contact,site)))
    Opt=privacy_removals.OptOutSubmission
    with pytest.raises(HTTPException) as err:
        privacy_removals.submit("verified@example.org",
            Opt(site="broker.example.com",contact="privacy@broker.example.com",consent=False))
    assert err.value.status_code==422
    with pytest.raises(HTTPException) as err:
        privacy_removals.submit("verified@example.org",
            Opt(site="broker.example.com",contact="privacy@other.example.com",consent=True))
    assert err.value.status_code==422
    assert sends==[]
    receipt=privacy_removals.submit("verified@example.org",
        Opt(site="broker.example.com",contact="privacy@broker.example.com",consent=True))
    assert receipt["status"]=="submitted_to_smtp"
    assert receipt["removal_confirmed"] is False
    assert sends==[("verified@example.org","privacy@broker.example.com","broker.example.com")]
    history=privacy_removals.history("verified@example.org")
    assert history["items"][0]["site"]=="broker.example.com"
    assert "verified@example.org" not in str(history)
    assert "privacy@" not in str(history)


def test_repeated_optout_cannot_spam_mailboxes(tmp_path,monkeypatch):
    monkeypatch.setenv("GHOSTFORGE_STATE_DB",str(tmp_path/"privacy.sqlite"))
    calls=[]
    monkeypatch.setattr(privacy_removals,"_send",lambda *args:calls.append(args))
    Opt=privacy_removals.OptOutSubmission
    for site in ("one.example.org","two.example.org"):
        privacy_removals.submit("verified@example.org",Opt(
            site=site, contact="privacy@"+site, consent=True))
    with pytest.raises(HTTPException) as err:
        privacy_removals.submit("verified@example.org",Opt(
            site="three.example.org",contact="privacy@three.example.org",consent=True))
    assert err.value.status_code==429
    assert len(calls)==2
    assert privacy_removals.erase("verified@example.org")["deleted"] is True
    assert privacy_removals.history("verified@example.org")["items"]==[]
