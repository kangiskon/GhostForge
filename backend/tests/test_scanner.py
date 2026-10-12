import pytest
from ghostforge import scanner

def test_normal_url():
    url, host, ip = scanner.normalize("https://example.com")
    assert host == "example.com" and not ip
    assert url.startswith("https://")

def test_invalid_schemes():
    with pytest.raises(scanner.InvalidURL):
        scanner.normalize("file:///etc/passwd")

def test_embedded_password_rejected():
    with pytest.raises(scanner.InvalidURL):
        scanner.normalize("https://name:password@example.com")

@pytest.mark.asyncio
async def test_unverified_no_key(monkeypatch):
    monkeypatch.delenv("WEB_RISK_API_KEY", raising=False)
    result = await scanner.inspect("https://example.com")
    assert result.verdict == "unverified"

@pytest.mark.asyncio
async def test_http_suspicious(monkeypatch):
    monkeypatch.delenv("WEB_RISK_API_KEY", raising=False)
    result = await scanner.inspect("http://example.com")
    assert result.verdict == "suspicious"
