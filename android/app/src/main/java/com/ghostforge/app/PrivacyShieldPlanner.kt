package com.ghostforge.app

import java.net.IDN
import java.net.URI
import java.net.URLEncoder
import java.util.Locale

/**
 * Local-only Privacy Shield planning. No actual web requests, crawling, or hidden
 * service access. Searches disclose query terms only when the user opens a link.
 */
data class PrivacySearch(
    val title: String,
    val description: String,
    val url: String
)

data class PrivacyCase(
    val id: String,
    val site: String,
    val dataType: String,
    val status: String,
    val createdAt: Long,
    val updatedAt: Long
)

object PrivacyShieldPlanner {
    const val DRAFT = "draft"
    const val SENT = "request_sent"
    const val RESPONSE = "acknowledged"
    const val REMOVED = "verified_removed"
    const val DECLINED = "declined"

    val types = listOf("Email address", "Phone number", "Full name", "Home address",
        "Profile / data broker listing", "Other personal information")
    val statuses = listOf(DRAFT, SENT, RESPONSE, REMOVED, DECLINED)

    private fun q(s: String) = URLEncoder.encode(s, "UTF-8")

    fun validateSelfInfo(value: String): String {
        val data = value.trim()
        require(data.length in 3..160 && data.none { it.code < 32 || it.code == 127 }) {
            "Enter 3–160 characters of your own information to search."
        }
        return data
    }

    fun searches(value: String): List<PrivacySearch> {
        val data = validateSelfInfo(value)
        fun query(term: String) = "https://www.google.com/search?q=" + q(term)
        val quoted = "\"" + data + "\""
        return listOf(
            PrivacySearch("Public web mentions", "Search indexed public webpages for the exact information.",
                query(quoted)),
            PrivacySearch("People-search and directory listings",
                "Look for publicly indexed directories. Results are not verified.",
                query(quoted + " people search OR directory OR listing")),
            PrivacySearch("Public document exposure",
                "Check publicly indexed PDF documents for the exact information.",
                query(quoted + " filetype:pdf")),
            PrivacySearch("Public forum mentions",
                "Search indexed discussion posts. No private forums are accessed.",
                query("site:reddit.com " + quoted)),
            PrivacySearch("Data broker opt-out pages",
                "Find a listing site's official privacy or opt-out instructions.",
                query(quoted + " privacy opt out remove listing"))
        )
    }

    /** Store only the public site hostname, never the full profile URL or PII. */
    fun normalizeSite(input: String): String {
        val raw = input.trim()
        require(raw.length in 4..250 &&
            raw.none { it.isWhitespace() || it.code < 32 }) {
            "Enter a public listing's website hostname or HTTPS URL."
        }
        val uri = try {
            URI(if (raw.contains("://")) raw else "https://" + raw)
        } catch (e: Exception) {
            throw IllegalArgumentException("Enter a valid public website domain.")
        }
        require(uri.scheme.equals("https", true) && uri.rawUserInfo == null) {
            "Only public HTTPS websites are accepted."
        }
        val host = uri.host?.let { IDN.toASCII(it, IDN.USE_STD3_ASCII_RULES).lowercase(Locale.ROOT) }
            ?: throw IllegalArgumentException("Enter a valid website hostname.")
        require(host.contains(".") && host.length <= 253 &&
            !host.endsWith(".local") && !host.endsWith(".internal") &&
            !host.endsWith(".test") && !host.endsWith(".onion") &&
            !host.endsWith(".localhost") && !host.endsWith(".lan") &&
            !host.matches(Regex("""[0-9.]+""")) && !host.contains(":")) {
            "Only public domains are supported."
        }
        return host
    }

    fun case(site: String, dataType: String, id: String, now: Long): PrivacyCase {
        require(dataType in types) { "Select an exposure category." }
        require(id.matches(Regex("""[a-f0-9-]{36}"""))) { "Invalid case ID." }
        return PrivacyCase(id, normalizeSite(site), dataType, DRAFT, now, now)
    }

    fun update(item: PrivacyCase, next: String, now: Long): PrivacyCase {
        require(next in statuses) { "Unknown removal status." }
        require(next != REMOVED || item.status in listOf(SENT, RESPONSE)) {
            "First submit the request and independently check that the listing was removed."
        }
        return item.copy(status = next, updatedAt = now)
    }

    fun subject(item: PrivacyCase): String =
        "Privacy / personal information removal request — " + item.site

    fun draft(item: PrivacyCase, ownName: String, ownEmail: String): String {
        val name = ownName.trim()
        val email = ownEmail.trim()
        require(name.length in 2..120 && name.none { it.code < 32 }) {
            "Enter your name for the request."
        }
        require(email.length in 5..254 &&
            email.matches(Regex("""^[^@\s]+@[^@\s]+\.[^@\s]+$"""))) {
            "Enter an email address you control."
        }
        require(item.dataType in types)
        return "Hello,\n\n" +
            "I am contacting you about a personal-information listing on " + item.site + ".\n" +
            "Please tell me how to request removal or suppression of information relating to me, " +
            "specifically the category: " + item.dataType + ".\n\n" +
            "Please confirm any steps you need to verify my identity through your official, " +
            "secure privacy process. Do not request my passwords or one-time codes.\n" +
            "If appropriate under the laws that apply to my request, please erase the " +
            "information and let me know when you have completed the request, or explain " +
            "why removal is not possible.\n\n" +
            "Name: " + name + "\n" +
            "Reply email: " + email + "\n\n" +
            "Thank you."
    }
}
