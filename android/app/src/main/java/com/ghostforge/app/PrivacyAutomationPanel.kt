package com.ghostforge.app

import android.content.Context
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/**
 * Secure provider client. Never stores licenses or provider keys in the APK.
 * Backend authenticates each call with the existing verified-email session.
 */
object PrivacyAutomationApi {
    suspend fun request(
        endpoint: String, path: String, token: String, method: String = "GET",
        body: JSONObject? = null
    ): Result<JSONObject> = withContext(Dispatchers.IO) { runCatching {
        val base = endpoint.trim().trimEnd('/')
        require(base.startsWith("https://") && !base.endsWith(".invalid")) {
            "Configure your trusted HTTPS GhostForge server in Settings."
        }
        require(path in setOf("/api/v1/privacy/stealer-logs",
            "/api/v1/privacy/optery-status", "/api/v1/privacy/optout",
            "/api/v1/privacy/optouts")) { "Unsupported privacy API." }
        require(method in setOf("GET", "POST", "DELETE")) { "Unsupported request method." }
        val conn = URL(base + path).openConnection() as HttpURLConnection
        try {
            conn.instanceFollowRedirects = false
            conn.connectTimeout = 9000
            conn.readTimeout = 14000
            conn.requestMethod = method
            conn.setRequestProperty("Accept", "application/json")
            conn.setRequestProperty("Authorization", "Bearer " + token)
            if (body != null) {
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/json")
                conn.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
            }
            val status = conn.responseCode
            if (status !in 200..299) {
                val reason = when (status) {
                    401 -> "Verify your email again before using licensed privacy services."
                    422 -> "Check input and authorization. Recipient must be at the broker's domain."
                    429 -> "Privacy requests are rate-limited. Try later."
                    503 -> "Your GhostForge server has not been configured for this service."
                    else -> "Privacy provider API returned HTTP " + status + "."
                }
                throw IllegalStateException(reason)
            }
            val bytes = conn.inputStream.use { input ->
                val out = java.io.ByteArrayOutputStream()
                val buf = ByteArray(4096)
                while (out.size() < 65536) {
                    val count = input.read(buf, 0, minOf(buf.size, 65536 - out.size()))
                    if (count < 0) break
                    out.write(buf, 0, count)
                }
                out.toByteArray()
            }
            JSONObject(String(bytes, Charsets.UTF_8))
        } finally { conn.disconnect() }
    } }
}

private val amberPrivacy = Color(0xFFFFCA75)
private val mintPrivacy = Color(0xFF39E5CB)
private val mutedPrivacy = Color(0xFF9BB3C6)

/**
 * All actions below require user taps. The screen never performs a
 * stealer-log lookup or sends a third-party email merely because it was opened.
 */
@Composable
fun PrivacyAutomationPanel(endpoint: String) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val token = VerifiedSession.get(ctx)
    var note by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var consentScan by remember { mutableStateOf(false) }
    var stealerResponse by remember { mutableStateOf<JSONObject?>(null) }
    var optery by remember { mutableStateOf<JSONObject?>(null) }
    var site by remember { mutableStateOf("") }
    var contact by remember { mutableStateOf("") }
    var consentSend by remember { mutableStateOf(false) }
    var optouts by remember { mutableStateOf<JSONObject?>(null) }
    var clearLogs by remember { mutableStateOf(false) }

    fun action(
        path: String,
        method: String = "GET",
        payload: JSONObject? = null,
        success: (JSONObject) -> Unit
    ) {
        if (busy || token == null) return
        busy = true
        note = ""
        scope.launch {
            PrivacyAutomationApi.request(endpoint, path, token, method, payload).fold(
                onSuccess = success,
                onFailure = { note = it.message ?: "The privacy service could not be reached." }
            )
            busy = false
        }
    }

    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        HorizontalDivider()
        Text("LICENSED THREAT INTELLIGENCE", color = mintPrivacy)
        Text("Have I Been Pwned stealer-log lookups require a paid Pro API license and " +
            "verified control of your email domain. Only your already verified email " +
            "can be searched. This does not retrieve stolen passwords.",
            color = mutedPrivacy)
        if (token == null) {
            Text("Verify your email in the Breaches tab first.", color = amberPrivacy)
        } else {
            Row(Modifier.fillMaxWidth()) {
                Checkbox(checked = consentScan, onCheckedChange = { consentScan = it })
                Text("I authorize a licensed stealer-log lookup for my verified email. " +
                    "The server will disclose that email to Have I Been Pwned.",
                    color = mutedPrivacy, modifier = Modifier.padding(top = 9.dp))
            }
            Button(onClick = {
                action("/api/v1/privacy/stealer-logs", "POST",
                    JSONObject().put("consent", true)) { stealerResponse = it }
                consentScan = false
            }, enabled = consentScan && !busy, modifier = Modifier.fillMaxWidth()) {
                Text("CHECK LICENSED STEALER-LOG FEED")
            }
            stealerResponse?.let { report ->
                val checked = report.optBoolean("checked", false)
                Text("Source: " + report.optString("provider", "HIBP"), color = mutedPrivacy)
                Text((if (checked) "Provider checked • " else "Not checked • ") +
                    report.optString("status", "unavailable"), color = amberPrivacy)
                Text(report.optString("note"), color = mutedPrivacy)
                val domains = report.optJSONArray("domains")
                if (checked && domains != null) {
                    if (domains.length() == 0) {
                        Text("No domains listed in this provider. This does not establish that " +
                            "your credentials have never been stolen.", color = amberPrivacy)
                    } else {
                        Text("Websites observed in licensed stealer logs:", color = amberPrivacy)
                        for (i in 0 until minOf(domains.length(), 40)) {
                            Text("• " + domains.optString(i).take(253), color = mutedPrivacy)
                        }
                    }
                }
            }
        }
        OutlinedButton(onClick = {
            action("/api/v1/privacy/optery-status") { optery = it }
        }, enabled = token != null && !busy, modifier = Modifier.fillMaxWidth()) {
            Text("CHECK OPTERY BUSINESS API CONNECTION")
        }
        optery?.let { report ->
            Text("Data broker removal provider: Optery • " +
                report.optString("status", "not configured"), color = amberPrivacy)
            Text(report.optString("note", "A connected account is not an active removal plan."),
                color = mutedPrivacy)
            Text("Automatic Optery broker removal subscription: " +
                (if (report.optBoolean("automated_removals_active", false)) "Active" else "Not active"),
                color = mutedPrivacy)
        }

        HorizontalDivider()
        Text("AUTHORIZED AUTOMATED OPT-OUT EMAIL", color = mintPrivacy)
        Text("GhostForge can submit a standard deletion request from your configured " +
            "server mail account to a privacy contact you have verified at the listing site. " +
            "Only your verified email is referenced, not your phone, name or home address. " +
            "Sending a request does NOT erase data from the site.",
            color = mutedPrivacy)
        OutlinedTextField(value = site, onValueChange = {
            site = it.take(253)
            consentSend = false
        }, label = { Text("Data broker domain (e.g. broker.example.com)") },
            modifier = Modifier.fillMaxWidth(), singleLine = true)
        OutlinedTextField(value = contact, onValueChange = {
            contact = it.take(254)
            consentSend = false
        }, label = { Text("Official privacy mailbox at the SAME domain") },
            modifier = Modifier.fillMaxWidth(), singleLine = true)
        Row(Modifier.fillMaxWidth()) {
            Checkbox(checked = consentSend, onCheckedChange = { consentSend = it })
            Text("I own the verified email being referenced, I checked that this is the " +
                "broker's official privacy mailbox, and I authorize this one deletion request. " +
                "The recipient will receive my email address.",
                color = mutedPrivacy, modifier = Modifier.padding(top = 8.dp))
        }
        Button(onClick = {
            val body = JSONObject().put("site", site.trim())
                .put("contact", contact.trim())
                .put("consent", true)
            consentSend = false
            action("/api/v1/privacy/optout", "POST", body) { reply ->
                note = reply.optString("message") +
                    " Status: " + reply.optString("status") +
                    ". Removed? " + reply.optBoolean("removal_confirmed", false)
                optouts = null
            }
        }, enabled = token != null && consentSend && site.isNotBlank() &&
            contact.isNotBlank() && !busy, modifier = Modifier.fillMaxWidth()) {
            Text("SUBMIT ONE VERIFIED OPT-OUT REQUEST")
        }
        OutlinedButton(onClick = {
            action("/api/v1/privacy/optouts") { optouts = it }
        }, enabled = token != null && !busy, modifier = Modifier.fillMaxWidth()) {
            Text("REFRESH AUTOMATED REQUEST HISTORY")
        }
        optouts?.optJSONArray("items")?.let { arr ->
            for (i in 0 until minOf(arr.length(), 30)) {
                val it = arr.optJSONObject(i) ?: continue
                Text(it.optString("site") + " — " + it.optString("status") +
                    " (removal unconfirmed)", color = mutedPrivacy)
            }
        }
        Row(Modifier.fillMaxWidth()) {
            Checkbox(checked = clearLogs, onCheckedChange = { clearLogs = it })
            Text("Delete only GhostForge's server-side opt-out request history. " +
                "This does NOT cancel a sent request or remove broker records.",
                color = mutedPrivacy, modifier = Modifier.padding(top = 8.dp))
        }
        OutlinedButton(onClick = {
            clearLogs = false
            action("/api/v1/privacy/optouts", "DELETE") {
                optouts = null
                note = it.optString("note", "Server-side request history deleted.")
            }
        }, enabled = clearLogs && token != null && !busy) {
            Text("DELETE SERVER REQUEST HISTORY")
        }
        if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
        if (note.isNotBlank()) Text(note, color = amberPrivacy)
        Text("All licensed providers need their own contracts/keys on your Ubuntu server. " +
            "Optery partner onboarding for full broker scanning/removals is not provisioned " +
            "by installing an APK. Emails accepted by SMTP are not confirmed deletions.",
            color = amberPrivacy)
    }
}
