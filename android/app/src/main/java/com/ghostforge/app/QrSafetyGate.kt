package com.ghostforge.app

import java.net.URI
import java.util.Locale

/**
 * A QR code is untrusted input. This gate must run before GhostForge ever offers
 * an ACTION_VIEW intent; decoding the QR itself must NEVER launch a URL.
 *
 * This is phishing risk assessment, not a guarantee that a website is safe.
 */
enum class QrVerdict { BLOCKED, WARNING, UNVERIFIED, NOT_LISTED }

data class QrAssessment(
    val url: String?,
    val host: String?,
    val verdict: QrVerdict,
    val title: String,
    val explanation: String,
    val reasons: List<String> = emptyList(),
    val checkedThreatLists: Boolean = false
) {
    val canOfferOpen: Boolean get() =
        url != null && verdict in setOf(QrVerdict.UNVERIFIED, QrVerdict.NOT_LISTED)
}

/** Pure assessment methods so all opening rules can be tested without an Android device. */
object QrSafetyGate {
    private val nonPublicTlds = setOf(
        "localhost", "local", "lan", "internal", "home", "test", "invalid", "onion"
    )
    private val suspiciousUrlEncodings = Regex("%(?:0[0-9a-f]|1[0-9a-f]|7f)", RegexOption.IGNORE_CASE)
    private val allowedPorts = setOf(-1, 443)

    fun inspect(raw: String): QrAssessment {
        val qr = raw.trim()
        fun rejected(title: String, reason: String) = QrAssessment(
            null, null, QrVerdict.BLOCKED, title, reason
        )
        if (qr.isBlank()) return rejected("QR code was empty", "No website address was found.")
        if (qr.length > 2048 || qr.any { it.isWhitespace() || it.code < 32 || it.code == 127 }) {
            return rejected("Unsupported QR contents", "Oversized URLs or QR text containing whitespace/control characters are blocked.")
        }
        val uri = try { URI(qr) } catch (_: Exception) {
            return rejected("Invalid website address", "This QR code does not contain a valid website URL.")
        }
        if (!uri.isAbsolute || !uri.scheme.equals("https", ignoreCase = true)) {
            return rejected(
                "QR destination blocked",
                "Only HTTPS website links are allowed. Plain HTTP, Wi-Fi setup, app-install, " +
                    "payment, SMS, telephone, intent and other QR actions are never launched."
            )
        }
        if (uri.rawUserInfo != null || uri.rawFragment != null) {
            return rejected("Unsafe URL format", "QR URLs containing credentials or fragments are blocked.")
        }
        if (uri.port !in allowedPorts) {
            return rejected("Unusual website port", "QR codes may open only the standard HTTPS port.")
        }
        val host = uri.host?.lowercase(Locale.ROOT)
            ?: return rejected("Invalid hostname", "GhostForge couldn't identify the website's real hostname.")
        if (host.length > 253 || !host.contains(".") ||
            host.contains(":") || host.matches(Regex("""[0-9.]+""")) ||
            host.substringAfterLast(".") in nonPublicTlds ||
            host.endsWith(".localhost") ||
            host.endsWith(".local") ||
            host.endsWith(".internal") ||
            host.endsWith(".lan") ||
            host.endsWith(".test") ||
            host.endsWith(".onion")
        ) {
            return rejected("Non-public destination blocked",
                "QR links to IP addresses, local-network hosts, or unsupported domains aren't opened.")
        }
        if (suspiciousUrlEncodings.containsMatchIn(uri.rawPath.orEmpty()) ||
            suspiciousUrlEncodings.containsMatchIn(uri.rawQuery.orEmpty())) {
            return rejected("Encoded control characters",
                "The URL contains encoded control characters and can't be opened through GhostForge.")
        }
        val local = OfflineScanner.link(qr).getOrElse {
            return rejected("Unsafe or invalid QR link", it.message ?: "QR link validation failed.")
        }
        if (local.signals.isNotEmpty() || local.verdict == "suspicious" ||
            local.verdict == "malicious") {
            return QrAssessment(qr, host, QrVerdict.WARNING, "Suspicious QR destination",
                "GhostForge found warning signs and has disabled the Open Website button.",
                local.signals.ifEmpty { listOf(local.message) })
        }
        return QrAssessment(qr, host, QrVerdict.UNVERIFIED,
            "No obvious warning signs — unverified",
            "The URL format passed local checks, but no live threat database was consulted. " +
                "This does NOT mean the site is safe.")
    }

    fun applyReputation(original: QrAssessment, response: ScanFinding): QrAssessment {
        if (!original.canOfferOpen) return original // Never override local blocks or warnings.
        val scanned = original.url ?: return original
        // Do not let a misconfigured or compromised backend bless a different destination.
        if (response.host.lowercase(Locale.ROOT) != original.host ||
            response.url.isBlank() ||
            !equivalentUrl(scanned, response.url)) {
            return original.copy(
                verdict = QrVerdict.UNVERIFIED, checkedThreatLists = false,
                title = "Reputation result not verified",
                explanation = "The security service returned a mismatched destination; the website remains unverified."
            )
        }
        if (response.verdict == "malicious" || response.threats.isNotEmpty()) {
            return original.copy(verdict = QrVerdict.BLOCKED,
                title = "Known malicious QR destination — blocked",
                explanation = "A configured threat-intelligence source identified this destination. Do not open it.",
                reasons = response.threats.ifEmpty { listOf(response.message) },
                checkedThreatLists = response.lookup == "confirmed")
        }
        if (response.verdict == "suspicious" || response.signals.isNotEmpty()) {
            return original.copy(verdict = QrVerdict.WARNING,
                title = "Suspicious QR destination — blocked",
                explanation = "The online scan found warning signs. GhostForge will not open this QR link.",
                reasons = response.signals.ifEmpty { listOf(response.message) },
                checkedThreatLists = response.lookup == "confirmed")
        }
        if (response.verdict == "not_listed" && response.lookup == "confirmed") {
            return original.copy(verdict = QrVerdict.NOT_LISTED,
                title = "Not listed in checked threat databases",
                explanation = "The configured reputation service found no listing. " +
                    "New or undiscovered malicious sites may still be harmful.",
                checkedThreatLists = true)
        }
        return original.copy(verdict = QrVerdict.UNVERIFIED,
            title = "QR website remains unverified",
            explanation = "No usable live reputation verdict was returned. This doesn't establish safety.",
            checkedThreatLists = false)
    }

    private fun equivalentUrl(a: String, b: String): Boolean = try {
        val x = URI(a)
        val y = URI(b)
        x.scheme.equals(y.scheme, true) &&
            x.host.equals(y.host, true) &&
            x.port == y.port &&
            (x.rawPath.ifBlank { "/" } == y.rawPath.ifBlank { "/" }) &&
            x.rawQuery == y.rawQuery
    } catch (_: Exception) { false }
}
