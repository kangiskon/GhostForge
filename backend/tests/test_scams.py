import pytest
from ghostforge.scams import ScamRequest, heuristic, investigate

def test_scam_risk_rules():
    found = heuristic("URGENT: verify your account password. Send gift cards immediately.")
    assert found.risk == "high_warning"
    assert len(found.reasons) >= 2
    assert "safe" not in found.summary.lower()

def test_scam_no_signals_does_not_say_safe():
    found = heuristic("Hi, thanks for meeting me today.")
    assert found.risk == "unverified"
    assert found.mode == "heuristics"

@pytest.mark.asyncio
async def test_ai_disabled_never_calls_provider(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    found = await investigate(ScamRequest(text="Please call me tomorrow", use_ai=False))
    assert found.mode == "heuristics"

@pytest.mark.asyncio
async def test_ai_unconfigured_falls_back(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    found = await investigate(ScamRequest(text="Verify your login credentials", use_ai=True))
    assert found.mode == "heuristics_ai_unavailable"
