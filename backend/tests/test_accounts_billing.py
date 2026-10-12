"""Account and subscription authorization regression tests."""
import datetime as dt
import secrets
import uuid
import pytest
from fastapi import HTTPException
from ghostforge import accounts, billing, breaches

@pytest.fixture
def state(tmp_path,monkeypatch):
    monkeypatch.setenv("GHOSTFORGE_STATE_DB",str(tmp_path / "ghostforge.db"))
    monkeypatch.setenv("GHOSTFORGE_AUTH_SECRET","local-tests-are-not-a-production-secret-12345678")
    monkeypatch.setenv("GHOSTFORGE_PLAY_PRODUCTS","ghostforge_premium_monthly,ghostforge_family_monthly")
    return tmp_path

def test_household_join_and_permissions(state):
    a="owner@example.test"
    b="member@example.test"
    c="attacker@example.test"
    owner=accounts.create_household(a)
    assert owner["role"]=="owner"
    code=accounts.issue_invite(a)["invite_code"]
    assert code and code not in str(accounts.family_info(a))
    assert accounts.join_household(b,code)["role"]=="member"
    with pytest.raises(HTTPException) as ex:
        accounts.join_household(c,code)
    assert ex.value.status_code==400
    with pytest.raises(HTTPException) as ex:
        accounts.issue_invite(b)
    assert ex.value.status_code==403
    with pytest.raises(HTTPException) as ex:
        accounts.remove_member(c,b)
    assert ex.value.status_code==404
    assert len(accounts.family_info(a)["members"])==2
    assert accounts.remove_member(a,b)["removed"] is True
    assert accounts.family_info(b)["role"]=="none"

def test_device_isolation_and_limit(state):
    dev=str(uuid.uuid4())
    req=accounts.DeviceUpsert(device_id=dev,label="Test tablet")
    accounts.register_device("alice@example.test",req)
    assert len(accounts.profile("alice@example.test")["devices"])==1
    assert accounts.remove_device("bob@example.test",dev)["removed"] is False
    assert len(accounts.profile("alice@example.test")["devices"])==1
    assert accounts.remove_device("alice@example.test",dev)["removed"] is True
    for n in range(accounts.MAX_DEVICES):
        accounts.register_device("alice@example.test",accounts.DeviceUpsert(device_id=uuid.uuid4(),label="Test"))
    with pytest.raises(HTTPException) as ex:
        accounts.register_device("alice@example.test",accounts.DeviceUpsert(device_id=uuid.uuid4(),label="Overflow"))
    assert ex.value.status_code==409

def test_delete_account_revokes_sessions_and_disbands_owned_household(state):
    sent={}
    original=breaches._mail
    breaches._mail=lambda email,code:sent.update(code=code)
    try:
        breaches.request_code("owner@example.test")
        token=breaches.verify_code("owner@example.test",sent["code"])["token"]
    finally:
        breaches._mail=original
    accounts.create_household("owner@example.test")
    code=accounts.issue_invite("owner@example.test")["invite_code"]
    accounts.join_household("member@example.test",code)
    assert accounts.account_delete("owner@example.test")["deleted"]
    assert accounts.family_info("member@example.test")["role"]=="none"
    with pytest.raises(HTTPException):
        breaches.auth_email("Bearer "+token)

@pytest.mark.asyncio
async def test_play_validated_entitlement_and_token_ownership(state,monkeypatch):
    expiry=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(days=14)).isoformat()
    async def verified(_):
        return {"subscriptionState":"SUBSCRIPTION_STATE_ACTIVE",
                "lineItems":[{"productId":"ghostforge_premium_monthly","expiryTime":expiry}]}
    monkeypatch.setattr(billing,"_google_check",verified)
    request=billing.PurchaseRequest(token="a"*40)
    info=await billing.verify_subscription("alice@example.test",request)
    assert info["verified"]
    assert billing.entitlement("alice@example.test")["verified"]
    with pytest.raises(HTTPException) as ex:
        await billing.verify_subscription("bob@example.test",request)
    assert ex.value.status_code==409
    assert billing.entitlement("bob@example.test")["plan"]=="free"

@pytest.mark.asyncio
async def test_play_does_not_grant_unlisted_or_expired(state,monkeypatch):
    async def invalid(_):
        return {"subscriptionState":"SUBSCRIPTION_STATE_ACTIVE",
                "lineItems":[{"productId":"not_a_configured_product",
                    "expiryTime":"2099-01-01T00:00:00Z"}]}
    monkeypatch.setattr(billing,"_google_check",invalid)
    with pytest.raises(HTTPException) as ex:
        await billing.verify_subscription("alice@example.test",billing.PurchaseRequest(token="z"*40))
    assert ex.value.status_code==403
    assert billing.entitlement("alice@example.test")["plan"]=="free"
