package com.ghostforge.app

import java.net.URLEncoder
import java.nio.charset.StandardCharsets

/**
 * PhoneInfoga-inspired public OSINT search worksheet.
 * No harvesting, scraping, tracking, subscriber lookup or automatic network calls.
 *
 * Each search opens in the user's browser only after an explicit consent gate.
 * Search results may be incorrect, stale, spoofed or refer to a different person.
 */
data class OsintSearch(val title: String, val purpose: String, val url: String)

object PhoneOsintQueries {
    private fun encode(value: String) = URLEncoder.encode(value, StandardCharsets.UTF_8.name())

    fun searches(report: PhoneTraceReport): List<OsintSearch> {
        val e164 = report.e164
        require(e164.matches(Regex("""\+[0-9]{7,15}"""))) {
            "A complete international number is required for public searching."
        }
        val national = e164.removePrefix(report.countryCallingCode)
        val internationalDigits = e164.removePrefix("+")
        val formatTerms = listOf(e164, internationalDigits, national)
            .filter { it.length >= 7 }.distinct()
            .take(3)
            .joinToString(" OR ") { "\"$it\"" }
        fun google(query: String) = "https://www.google.com/search?q=" + encode(query)
        return listOf(
            OsintSearch("Scam & spam reports",
                "Search indexed caller complaints and suspected fraud reports.",
                google("($formatTerms) scam OR spam OR fraud OR robocall")),
            OsintSearch("General public mentions",
                "Check whether the number appears in publicly indexed websites.",
                google(formatTerms)),
            OsintSearch("Business listings",
                "Find possible published business contacts; not proof of ownership.",
                google("($formatTerms) business OR company OR contact")),
            OsintSearch("Public discussions",
                "Search public discussions and anecdotal caller reports.",
                google("site:reddit.com ($formatTerms) spam OR call OR number")),
            OsintSearch("Public social mentions",
                "Look for public, indexed mentions; profiles are NOT verified identity.",
                google("($formatTerms) site:facebook.com OR site:linkedin.com OR site:instagram.com")),
            OsintSearch("Public document mentions",
                "Search publicly indexed PDF documents mentioning the number.",
                google("($formatTerms) filetype:pdf"))
        )
    }
}
