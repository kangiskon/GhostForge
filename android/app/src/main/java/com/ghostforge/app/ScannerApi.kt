package com.ghostforge.app

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

data class ScanFinding(
    val url: String,
    val host: String,
    val verdict: String,
    val lookup: String,
    val message: String,
    val threats: List<String>,
    val signals: List<String>
)

object ScannerApi {
    suspend fun scan(server: String, raw: String): Result<ScanFinding> = withContext(Dispatchers.IO) {
        runCatching {
            val base = server.trim().trimEnd('/')
            require(base.startsWith("https://")) { "Set an HTTPS scanner backend in Settings." }
            require(raw.isNotBlank()) { "Enter a link." }
            val conn = URL("$base/api/v1/scan").openConnection() as HttpURLConnection
            try {
                conn.requestMethod = "POST"
                conn.connectTimeout = 10000
                conn.readTimeout = 10000
                conn.instanceFollowRedirects = false
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/json")
                conn.outputStream.use { it.write(JSONObject().put("url", raw.trim()).toString().toByteArray()) }
                val response = conn.responseCode
                require(response in 200..299) { "Scanner returned HTTP " + response }
                val json = JSONObject(conn.inputStream.bufferedReader().use { it.readText() })
                val threatData = json.optJSONArray("threats")
                val signalData = json.optJSONArray("signals")
                val threats = mutableListOf<String>()
                val signals = mutableListOf<String>()
                if (threatData != null) for (i in 0 until threatData.length()) threats.add(threatData.optString(i))
                if (signalData != null) for (i in 0 until signalData.length()) {
                    val s = signalData.optJSONObject(i)
                    if (s != null) signals.add(s.optString("title") + ": " + s.optString("detail"))
                }
                ScanFinding(json.optString("url"), json.optString("host"), json.optString("verdict"),
                    json.optString("lookup"), json.optString("message"), threats, signals)
            } finally {
                conn.disconnect()
            }
        }
    }
}
