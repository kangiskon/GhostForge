import os
from ghostforge.reputation import blocked_domains, check_hash

def test_domain_feed(monkeypatch):
    monkeypatch.setenv("BLOCKED_DOMAINS", "Bad.Example, phishing.test\nmalware.test,invalid!!")
    assert blocked_domains() == ["bad.example", "malware.test", "phishing.test"]

def test_empty_hash_reputation(monkeypatch):
    monkeypatch.delenv("KNOWN_BAD_APK_SHA256", raising=False)
    assert not check_hash("a" * 64)

def test_configured_hash_matches_case_insensitively(monkeypatch):
    monkeypatch.setenv("KNOWN_BAD_APK_SHA256", "A" * 64)
    assert check_hash("a" * 64)
    assert not check_hash("b" * 64)
