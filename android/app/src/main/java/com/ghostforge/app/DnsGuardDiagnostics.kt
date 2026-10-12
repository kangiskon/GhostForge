package com.ghostforge.app

import android.content.Context
import android.provider.Settings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL

/**
 * Direct DNS-over-HTTPS preflight, not a substitute for testing VPN routing on a device.
 * GhostForge is excluded from its own VPN to avoid recursive DNS resolution.
 */
object DnsGuardDiagnostics {
    private const val RESOLVER = "https://security.cloudflare-dns.com/dns-query"

    fun privateDnsWarning(context: Context): String? {
        val mode = try {
            Settings.Global.getString(context.contentResolver, "private_dns_mode")
        } catch (_: Exception) { null }
        return if (mode == "hostname") {
            "Android Private DNS uses a custom provider. Its encrypted traffic can bypass " +
                "GhostForge. On Samsung: Settings > Connections > More connection settings " +
                "> Private DNS > Automatic. Change it only if you want to use GhostForge DNS."
        } else null
    }

    suspend fun checkConnection(): String = withContext(Dispatchers.IO) {
        checkResolver() ?: "Cloudflare malware/phishing DNS-over-HTTPS is reachable. " +
            "This checks upstream access only, not VPN routing. Start DNS Guard, then test browsing in Chrome."
    }

    /**
     * Returns null on valid DNS response or a useful failure reason.
     * Uses a fixed harmless DNS question, never fetches the queried website.
     */
    fun checkResolver(): String? {
        // DNS question: example.com A, ID 0x4701, recursion desired.
        val request = byteArrayOf(
            0x47, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
            0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01
        )
        return try {
            val conn = URL(RESOLVER).openConnection() as HttpURLConnection
            try {
                conn.requestMethod = "POST"
                conn.instanceFollowRedirects = false
                conn.connectTimeout = 6000
                conn.readTimeout = 6000
                conn.doOutput = true
                conn.setRequestProperty("Accept", "application/dns-message")
                conn.setRequestProperty("Content-Type", "application/dns-message")
                conn.setFixedLengthStreamingMode(request.size)
                conn.outputStream.use { it.write(request) }
                val code = conn.responseCode
                if (code != 200) {
                    "Cloudflare DNS returned HTTP " + code + ". DNS Guard needs a working resolver."
                } else {
                    val bytes = conn.inputStream.use { input ->
                        val out = ByteArrayOutputStream()
                        val buf = ByteArray(512)
                        while (out.size() < 4096) {
                            val read = input.read(buf, 0, minOf(buf.size, 4096 - out.size()))
                            if (read < 0) break
                            out.write(buf, 0, read)
                        }
                        out.toByteArray()
                    }
                    if (bytes.size < 12 || bytes[0] != request[0] || bytes[1] != request[1] ||
                        (bytes[2].toInt() and 0x80) == 0 || (bytes[3].toInt() and 0x0f) != 0) {
                        "Cloudflare returned an invalid DNS response. Check your network or captive portal."
                    } else null
                }
            } finally { conn.disconnect() }
        } catch (e: Exception) {
            "Unable to reach encrypted DNS (" + e.javaClass.simpleName + "). " +
                "Check internet connectivity and network restrictions."
        }
    }
}
