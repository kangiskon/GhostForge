package com.ghostforge.app

import org.junit.Assert.*
import org.junit.Test

class PrivacyShieldPlannerTest {
    @Test fun localSearchDoesNotSubmitRequests() {
        val searches = PrivacyShieldPlanner.searches("private@example.com")
        assertTrue(searches.size >= 4)
        for (item in searches) {
            assertTrue(item.url.startsWith("https://www.google.com/search?q="))
            assertTrue(item.url.contains("private%40example.com"))
            assertFalse(item.url.contains(" "))
        }
    }

    @Test fun rejectSensitiveOrInvalidSearchInputs() {
        for (raw in listOf("", "a", "b\nc", "  ", "q".repeat(170))) {
            assertThrows(IllegalArgumentException::class.java) {
                PrivacyShieldPlanner.searches(raw)
            }
        }
    }

    @Test fun rejectsPrivateAndNonHttpsExposureSites() {
        for (raw in listOf("https://127.0.0.1/", "http://example.com/",
            "https://router.local/", "https://test.onion/",
            "https://site.example.com@evil.test/", "private",
            "https://192.168.1.2:8443/admin", "")) {
            assertThrows(IllegalArgumentException::class.java) {
                PrivacyShieldPlanner.normalizeSite(raw)
            }
        }
        assertEquals("example.com",
            PrivacyShieldPlanner.normalizeSite("https://Example.Com/exposure?q=secret"))
    }

    @Test fun trackerNeverStoresSearchValueOrListingPath() {
        val record = PrivacyShieldPlanner.case(
            "https://Example.COM/person/my-secret-email?q=private",
            "Email address", "11111111-2222-3333-4444-555555555555", 100L)
        assertEquals("example.com", record.site)
        assertEquals(PrivacyShieldPlanner.DRAFT, record.status)
        assertFalse(record.toString().contains("my-secret-email"))
    }

    @Test fun cannotClaimRemovedWithoutPreviouslySentRequest() {
        val item = PrivacyShieldPlanner.case(
            "example.com", "Phone number", "11111111-2222-3333-4444-555555555555", 100L)
        assertThrows(IllegalArgumentException::class.java) {
            PrivacyShieldPlanner.update(item, PrivacyShieldPlanner.REMOVED, 200L)
        }
        val sent = PrivacyShieldPlanner.update(item, PrivacyShieldPlanner.SENT, 300L)
        assertEquals(PrivacyShieldPlanner.SENT, sent.status)
        val removed = PrivacyShieldPlanner.update(sent, PrivacyShieldPlanner.REMOVED, 400L)
        assertEquals(PrivacyShieldPlanner.REMOVED, removed.status)
    }

    @Test fun optOutDraftRequiresOwnerInformationAndIsNotASentReceipt() {
        val item = PrivacyShieldPlanner.case(
            "example.com", "Home address", "11111111-2222-3333-4444-555555555555", 100L)
        val draft = PrivacyShieldPlanner.draft(item, "Test Person", "owner@example.com")
        assertTrue(draft.contains("test Person", ignoreCase = true))
        assertTrue(draft.contains("example.com"))
        assertTrue(draft.contains("secure privacy process"))
        assertFalse(draft.contains("request submitted", ignoreCase = true))
        assertThrows(IllegalArgumentException::class.java) {
            PrivacyShieldPlanner.draft(item, "A", "not-email")
        }
    }
}
