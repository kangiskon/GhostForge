package com.ghostforge.app

import org.junit.Assert.*
import org.junit.Test

class QrSafetyGateTest {
    @Test fun harmlessHttpsLinkIsUnverifiedUntilReputation() {
        val a = QrSafetyGate.inspect("https://example.com/path")
        assertEquals(QrVerdict.UNVERIFIED, a.verdict)
        assertTrue(a.canOfferOpen)
        assertFalse(a.checkedThreatLists)
        assertTrue(a.title.contains("unverified"))
    }

    @Test fun phoneWifiIntentAndInstallPayloadsNeverOpen() {
        val codes = listOf(
            "tel:+14165550100",
            "smsto:+14165550100:hi",
            "WIFI:T:WPA;S:test;P:pass;;",
            "intent://example.com/#Intent;scheme=https;end",
            "javascript:alert(1)",
            "http://example.com",
            "https://127.0.0.1/admin",
            "https://192.168.0.1/",
            "https://site.local/",
            "https://example.com:8443/",
            "https://example.com@evil.test/",
            "https://example.com/%0d%0aheader",
            "https://example.com/&#x0a;"
        )
        codes.forEach { code ->
            val a=QrSafetyGate.inspect(code)
            assertFalse("must not open: "+code, a.canOfferOpen)
        }
    }

    @Test fun suspiciousDomainsRequireChoosingDifferentWebsite() {
        val a=QrSafetyGate.inspect("https://bit.ly/some-short-code")
        assertEquals(QrVerdict.WARNING,a.verdict)
        assertFalse(a.canOfferOpen)
    }

    @Test fun reputationListedThreatDisablesOpen() {
        val a=QrSafetyGate.inspect("https://example.com/login")
        val b=QrSafetyGate.applyReputation(a, ScanFinding(
            "https://example.com/login", "example.com", "malicious",
            "confirmed", "Listed phishing", listOf("SOCIAL_ENGINEERING"), emptyList()))
        assertEquals(QrVerdict.BLOCKED,b.verdict)
        assertFalse(b.canOfferOpen)
    }

    @Test fun negativeListLookupNeverClaimsSafe() {
        val a=QrSafetyGate.inspect("https://example.com/")
        val b=QrSafetyGate.applyReputation(a, ScanFinding(
            "https://example.com/", "example.com", "not_listed",
            "confirmed", "No listings", emptyList(),emptyList()))
        assertEquals(QrVerdict.NOT_LISTED,b.verdict)
        assertTrue(b.checkedThreatLists)
        assertTrue(b.canOfferOpen)
        assertTrue(b.explanation.contains("may still be harmful"))
    }

    @Test fun untrustedReputationCannotBlessDifferentUrl() {
        val a=QrSafetyGate.inspect("https://example.com/login")
        val b=QrSafetyGate.applyReputation(a, ScanFinding(
            "https://example.com/wrong", "example.com", "not_listed",
            "confirmed", "Not listed",emptyList(),emptyList()))
        assertEquals(QrVerdict.UNVERIFIED,b.verdict)
        assertFalse(b.checkedThreatLists)
    }

    @Test fun localWarningCannotBeOverridden() {
        val a=QrSafetyGate.inspect("https://bit.ly/x")
        val b=QrSafetyGate.applyReputation(a, ScanFinding(
            "https://bit.ly/x","bit.ly","not_listed","confirmed","Not listed",
            emptyList(),emptyList()))
        assertEquals(QrVerdict.WARNING,b.verdict)
        assertFalse(b.canOfferOpen)
    }
}

class PhoneOsintQueriesTest {
    @Test fun generatesConsentGatedSearchUrlsWithEncodedNumber() {
        val report = PhoneTraceAnalyzer.inspect("+1 416 555 0100","CA").getOrThrow()
        val searches = PhoneOsintQueries.searches(report)
        assertTrue(searches.size>=5)
        assertTrue(searches.any { it.title.contains("Scam") })
        searches.forEach { source ->
            assertTrue(source.url.startsWith("https://www.google.com/search?q="))
            assertTrue(source.url.contains("%22"))
            assertFalse(source.url.contains(" "))
        }
    }

    @Test fun fakeNumberCannotGenerateSearches() {
        val report = PhoneTraceAnalyzer.inspect("+1 416 555 0100","CA").getOrThrow()
        val invalid = report.copy(e164="x'.doevil")
        assertThrows(IllegalArgumentException::class.java) {
            PhoneOsintQueries.searches(invalid)
        }
    }
}
