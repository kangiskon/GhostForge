package com.ghostforge.app

import org.junit.Assert.*
import org.junit.Test

class PhoneTraceAnalyzerTest {
    @Test fun parsesCanadianNumberWithoutInternet() {
        val report = PhoneTraceAnalyzer.inspect("(416) 555-0100", "CA").getOrThrow()
        assertEquals("+14165550100", report.e164)
        assertEquals("+1", report.countryCallingCode)
        assertEquals("416", report.geographicPrefix)
        assertTrue(report.numberingRegion.contains("CA"))
        assertTrue(report.possible)
        assertFalse(report.disclaimer.contains("can prove"))
    }

    @Test fun explicitCountryCodeOverridesDefaultRegion() {
        val report = PhoneTraceAnalyzer.inspect("+1 202 555 0123", "CA").getOrThrow()
        assertEquals("+12025550123", report.e164)
        assertTrue(report.numberingRegion.contains("US"))
    }

    @Test fun noCurrentLocationOrIdentityClaims() {
        val report = PhoneTraceAnalyzer.inspect("+1 416 555 0100", "US").getOrThrow()
        assertTrue(report.disclaimer.contains("current location"))
        assertTrue(report.disclaimer.contains("identity"))
        assertTrue(report.disclaimer.contains("spoofed"))
    }

    @Test fun suspiciousInputRejectedWithoutNetworkRequests() {
        for (value in listOf("https://example.org", "416-555-0100;DROP", "<script>",
                             "555-0100\nCall me", "+1 416 555 0100 ext 10", "")) {
            assertTrue(value, PhoneTraceAnalyzer.inspect(value, "CA").isFailure)
        }
        assertTrue(PhoneTraceAnalyzer.inspect("+14165550100","invalid").isFailure)
    }

    @Test fun shortNumberIsNotVerifiedAsARealPerson() {
        val result = PhoneTraceAnalyzer.inspect("123", "CA")
        if (result.isSuccess) {
            assertFalse(result.getOrThrow().validPattern)
        }
    }
}
