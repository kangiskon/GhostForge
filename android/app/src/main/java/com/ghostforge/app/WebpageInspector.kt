package com.ghostforge.app

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Request
import org.jsoup.Jsoup
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.IDN
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.Proxy
import java.net.URI
import java.util.concurrent.TimeUnit

data class WebpageReport(
    val host: String,
    val title: String,
    val verdict: String,
    val httpCode: Int,
    val sampleChars: Int,
    val signals: List<String>,
    val notice: String
)

/** A user-initiated, read-only HTML inspection. NOT a browser or full traffic monitor. */
object WebpageInspector {
    const val MAX_BYTES = 196608

    /**
     * The phone must not be tricked into fetching local/admin/LAN pages.
     * Fail closed if *any* DNS answer is private, reserved or otherwise non-public.
     * OkHttp uses this resolver for its actual connection (not a separate DNS check).
     */
    fun isPublicAddress(ip: InetAddress): Boolean {
        if (ip.isAnyLocalAddress || ip.isLoopbackAddress || ip.isLinkLocalAddress ||
            ip.isSiteLocalAddress || ip.isMulticastAddress) return false
        val bytes = ip.address.map { it.toInt() and 0xff }
        if (ip is Inet4Address) {
            val a = bytes[0]; val b = bytes[1]; val c = bytes[2]
            if (a == 0 || a == 10 || a == 127 || a >= 224 ||
                (a == 100 && b in 64..127) ||
                (a == 169 && b == 254) ||
                (a == 172 && b in 16..31) ||
                (a == 192 && b in listOf(0, 168)) ||
                (a == 192 && b == 88 && c == 99) ||
                (a == 192 && b == 0 && c == 2) ||
                (a == 198 && b in 18..19) ||
                (a == 198 && b == 51 && c == 100) ||
                (a == 203 && b == 0 && c == 113)) return false
            return true
        }
        if (ip is Inet6Address) {
            // Conservatively allow only currently allocated IPv6 global unicast 2000::/3.
            // All other kinds, including ULA, mapped, loopback and link-local, are blocked.
            return (bytes[0] and 0xe0) == 0x20
        }
        return false
    }

    private val safeDns = Dns { hostname ->
        val addresses = Dns.SYSTEM.lookup(hostname)
        if (addresses.isEmpty() || addresses.any { !isPublicAddress(it) }) {
            throw IOException("This host resolves to a private or restricted address and cannot be inspected.")
        }
        addresses
    }

    private val client = OkHttpClient.Builder()
        .dns(safeDns)
        .proxy(Proxy.NO_PROXY)
        .followRedirects(false)
        .followSslRedirects(false)
        .retryOnConnectionFailure(false)
        .connectTimeout(6, TimeUnit.SECONDS)
        .readTimeout(8, TimeUnit.SECONDS)
        .callTimeout(16, TimeUnit.SECONDS)
        .build()

    /** Intentionally only permits public, direct HTTPS page fetches. */
    fun validatedUrl(raw: String): URI {
        val text = raw.trim()
        require(text.length in 9..2048 && !text.any { it.isWhitespace() || it.code < 32 }) {
            "Enter one HTTPS URL (maximum 2,048 characters)."
        }
        val url = URI(text)
        require(url.scheme.equals("https", true)) {
            "For page inspection, enter a URL beginning with https://."
        }
        require(url.rawUserInfo == null && url.rawFragment == null) {
            "URLs containing credentials or fragments aren't accepted."
        }
        require(url.port == -1 || url.port == 443) {
            "Only the standard HTTPS port (443) is supported."
        }
        val host = url.host ?: error("The URL has no valid hostname.")
        val ascii = IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES).lowercase()
        require(ascii.length in 4..253 && ascii.contains(".") &&
            !ascii.endsWith(".local") && !ascii.endsWith(".lan") &&
            !ascii.endsWith(".internal") && !ascii.endsWith(".test") &&
            !ascii.endsWith(".localhost") && !ascii.endsWith(".onion") &&
            !ascii.matches(Regex("""\d+\.\d+\.\d+\.\d+""")) &&
            !ascii.contains(":")) {
            "Only public HTTPS domain names are supported; no local networks or raw IPs."
        }
        return url
    }

    suspend fun inspect(raw: String): Result<WebpageReport> = withContext(Dispatchers.IO) {
        runCatching {
            val uri = validatedUrl(raw)
            val request = Request.Builder()
                .url(uri.toASCIIString())
                .get()
                .header("Accept", "text/html,application/xhtml+xml")
                .header("User-Agent", "GhostForge-Webpage-Inspector/0.5")
                .header("Cache-Control", "no-store")
                .build()
            client.newCall(request).execute().use { response ->
                val contentType = response.header("Content-Type").orEmpty().lowercase()
                if (response.code in 300..399) {
                    return@runCatching WebpageReport(
                        uri.host, "Redirect not followed", "unverified", response.code, 0,
                        listOf("Server returned a redirect. GhostForge did not follow it."),
                        "To inspect the destination, enter its HTTPS URL explicitly."
                    )
                }
                require(response.isSuccessful) {
                    "Website returned HTTP " + response.code + ". HTML was not inspected."
                }
                require(contentType.startsWith("text/html") ||
                    contentType.startsWith("application/xhtml+xml")) {
                    "The server did not return an HTML page."
                }
                val body = response.body ?: error("The page contained no content.")
                require(body.contentLength() <= MAX_BYTES) {
                    "Page exceeds the inspection size limit."
                }
                val bytes = body.byteStream().use { input ->
                    val out = ByteArrayOutputStream()
                    val buffer = ByteArray(4096)
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        require(out.size() + count <= MAX_BYTES) {
                            "Page exceeded the 192 KiB read limit; inspection canceled."
                        }
                        out.write(buffer, 0, count)
                    }
                    out.toByteArray()
                }
                val charset = try { body.contentType()?.charset(Charsets.UTF_8) ?: Charsets.UTF_8 }
                              catch (_: Exception) { Charsets.UTF_8 }
                analyzeHtml(uri.toASCIIString(), String(bytes, charset), response.code)
            }
        }
    }

    /** Pure parser for repeatable unit tests; never executes scripts or requests resources. */
    fun analyzeHtml(url: String, html: String, httpCode: Int = 200): WebpageReport {
        val uri = URI(url)
        val host = uri.host ?: "unknown"
        val doc = Jsoup.parse(html, url)
        doc.select("script,style,noscript,template").remove()
        val text = doc.body()?.text().orEmpty().take(14000)
        val title = doc.title().take(160)
        val signals = mutableListOf<String>()
        val passwordForms = doc.select("form:has(input[type=password])")
        if (passwordForms.isNotEmpty()) {
            signals.add("This page asks for a password. Check the domain before entering credentials.")
        }
        for (form in doc.select("form[action]").take(30)) {
            val action = form.absUrl("action")
            if (action.isNotBlank()) {
                try {
                    val target = URI(action)
                    val dest = target.host
                    if (target.scheme.equals("http", true))
                        signals.add("A form may submit data over unencrypted HTTP.")
                    if (dest != null && !dest.equals(host, true))
                        signals.add("A form submits data to another hostname: " + dest.take(120))
                } catch (_: Exception) { }
            }
        }
        if (doc.select("meta[http-equiv=refresh]").isNotEmpty()) {
            signals.add("Page includes an automatic refresh or redirect instruction.")
        }
        val textSamples = (title + " " + text).lowercase()
        val urgent = Regex("""\b(verify your account|account suspended|urgent action|send gift card|claim your prize|confirm your password|wallet recovery phrase|seed phrase)\b""")
        if (urgent.containsMatchIn(textSamples)) {
            signals.add("Page text contains common credential-theft or scam-pressure language.")
        }
        var misleading = 0
        for (anchor in doc.select("a[href]").take(120)) {
            val visible = anchor.text().trim()
            if (visible.startsWith("http://") || visible.startsWith("https://")) {
                try {
                    val stated = URI(visible).host
                    val actual = URI(anchor.absUrl("href")).host
                    if (stated != null && actual != null && !stated.equals(actual, true)) {
                        misleading++
                    }
                } catch (_: Exception) {}
            }
        }
        if (misleading > 0) signals.add("Some visible website links point to different hostnames.")
        if (doc.select("iframe").isNotEmpty()) {
            signals.add("Page embeds external content in a frame; embedded pages weren't inspected.")
        }
        val unique = signals.distinct().take(12)
        return WebpageReport(host, title.ifBlank { "(Untitled page)" },
            if (unique.isEmpty()) "unverified" else "warning_signs",
            httpCode, text.length, unique,
            "Only the initial HTML was fetched. Scripts, dynamically loaded content, " +
                "login-protected pages and other apps' HTTPS traffic weren't inspected. " +
                "No findings does not mean safe.")
    }
}
