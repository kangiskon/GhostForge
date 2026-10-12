package com.ghostforge.app

import org.json.JSONArray
import org.json.JSONObject
import java.net.IDN
import java.net.InetAddress
import java.net.URI

/**
 * Offline-only warning-sign checks; no URL fetching, no threat list lookups,
 * no unsupported claim that a website or message is safe.
 */
object OfflineScanner {
    fun link(raw: String): Result<ScanFinding> = runCatching {
        val value = raw.trim().let { if (it.contains("://")) it else "https://" + it }
        require(value.length <= 2048 && !value.any { it.isWhitespace() || it.code < 32 }) {
            "Enter a single website URL of at most 2048 characters."
        }
        val uri = URI(value)
        require(uri.scheme?.lowercase() in listOf("http","https")) {
            "Only http:// and https:// websites can be checked."
        }
        require(uri.rawUserInfo == null) { "Embedded username or password in URL is not supported." }
        val host = uri.host?.let { IDN.toASCII(it, IDN.USE_STD3_ASCII_RULES).lowercase() }
            ?: error("Could not determine the website hostname.")
        require(host.contains(".") && host.length <= 253) { "Enter a complete domain name." }
        val signals=mutableListOf<String>()
        if (uri.scheme.equals("http",true))
            signals.add("Unencrypted HTTP: don't enter personal information.")
        if (host.contains("xn--"))
            signals.add("Internationalized domain: check for visually misleading characters.")
        if (host in setOf("bit.ly","tinyurl.com","t.co","is.gd","cutt.ly"))
            signals.add("Link shortener: destination cannot be confirmed offline.")
        if (host.count { it=='.' } >= 4)
            signals.add("Many subdomains: inspect the actual domain carefully.")
        if (host.length > 65)
            signals.add("Unusually long hostname: check for impersonation.")
        if (uri.port !in listOf(-1,80,443))
            signals.add("Non-standard port: verify the intended service.")
        if (host.matches(Regex("""\d+\.\d+\.\d+\.\d+""")))
            signals.add("Direct IP address: verify its origin before sharing data.")
        val verdict = if (signals.isEmpty()) "unverified" else "suspicious"
        val message =
            if (signals.isEmpty())
                "Only local formatting checks were completed. No known-threat list was consulted. This does NOT establish that the website is safe."
            else "Offline warning signs detected. No threat-intelligence lookup was completed."
        ScanFinding(value,host,verdict,"offline_heuristics",message,emptyList(),signals)
    }

    fun message(text: String): JSONObject {
        val reasons = mutableListOf<String>()
        val patterns = listOf(
            Regex("""(?i)\b(urgent|immediately|act now|final notice|last chance|account suspended)\b""") to
                "Urgency or pressure is commonly used in scams.",
            Regex("""(?i)\b(otp|one.time code|password|verify your account|login credentials|security code)\b""") to
                "Requests for passwords or verification codes should be independently checked.",
            Regex("""(?i)\b(gift cards?|bitcoin|crypto|wire transfer|send money|pay a fee)\b""") to
                "Unexpected payment requests may be fraudulent.",
            Regex("""(?i)\b(anydesk|teamviewer|remote desktop|install this app)\b""") to
                "Remote-access software requests may allow a scammer to control your device.",
            Regex("""(?i)\b(bank security|tax agency|police|parcel delivery|refund)\b""") to
                "Claims of authority or delivery problems should be confirmed directly."
        )
        for ((pattern,reason) in patterns) if (pattern.containsMatchIn(text)) reasons.add(reason)
        val risk = if (reasons.size >= 2) "high_warning"
            else if (reasons.isNotEmpty()) "warning_signs" else "unverified"
        val description = if (reasons.isEmpty())
            "No listed warning patterns were found. That does not establish that this message is authentic."
        else "Common scam warning patterns appear in this message. Confirm them independently."
        val reasonArray=JSONArray()
        reasons.forEach { reasonArray.put(it) }
        val advice=JSONArray()
            .put("Never send an unexpected caller passwords, one-time codes or money.")
            .put("Use your own bookmark or official website to contact the claimed company.")
            .put("Do not install APKs or remote-control apps at a stranger's request.")
        return JSONObject()
            .put("risk",risk).put("mode","offline_heuristics")
            .put("summary",description).put("reasons",reasonArray).put("advice",advice)
            .put("privacy","Local check only: your message was not submitted to an analysis provider.")
    }
}
