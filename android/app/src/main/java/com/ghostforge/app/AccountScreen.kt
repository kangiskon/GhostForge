package com.ghostforge.app

import android.content.Context
import android.content.Intent
import android.os.Build
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
import java.util.UUID

/** All account endpoints require a verified email Bearer token over HTTPS. */
object AccountApi {
    suspend fun call(base: String, path: String, token: String?, method: String = "GET",
                     data: JSONObject? = null): Result<JSONObject> =
        withContext(Dispatchers.IO) { runCatching {
            val host = base.trim().trimEnd('/')
            require(host.startsWith("https://") && !host.endsWith(".invalid")) {
                "Configure the HTTPS backend in Settings."
            }
            val bearer = token ?: error("Verify your email in the Breaches tab before using an account.")
            require(path.startsWith("/api/v1/")) { "Invalid API route." }
            val c = URL(host + path).openConnection() as HttpURLConnection
            try {
                c.connectTimeout = 12000
                c.readTimeout = 12000
                c.instanceFollowRedirects = false
                c.requestMethod = method
                c.setRequestProperty("Authorization", "Bearer " + bearer)
                c.setRequestProperty("Accept", "application/json")
                if (data != null) {
                    c.doOutput = true
                    c.setRequestProperty("Content-Type", "application/json")
                    c.outputStream.use { it.write(data.toString().toByteArray(Charsets.UTF_8)) }
                }
                val status = c.responseCode
                val body = if (status in 200..299) c.inputStream else c.errorStream
                val value = body?.bufferedReader()?.use { it.readText() }.orEmpty()
                require(status in 200..299) {
                    when (status) {
                        400 -> "Invalid or expired invite code."
                        401 -> "Session expired; verify your email again."
                        403 -> "You aren't permitted to perform that action."
                        404 -> "No matching account or device was found."
                        409 -> "This account, household or device conflicts with an existing record."
                        429 -> "Too many requests. Try again later."
                        else -> "Account server returned HTTP " + status
                    }
                }
                JSONObject(value)
            } finally { c.disconnect() }
        } }

    fun localDeviceId(context: Context): String {
        val prefs = context.getSharedPreferences("ghostforge_settings", Context.MODE_PRIVATE)
        val found = prefs.getString("device_guid", null)
        if (found != null) return found
        val id = UUID.randomUUID().toString()
        prefs.edit().putString("device_guid", id).apply()
        return id
    }
}

@Composable
fun AccountScreen(endpoint: String, onVerifyEmail: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var token by remember { mutableStateOf(VerifiedSession.get(ctx)) }
    var profile by remember { mutableStateOf<JSONObject?>(null) }
    var household by remember { mutableStateOf<JSONObject?>(null) }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("") }
    var inviteCode by remember { mutableStateOf("") }
    var joinCode by remember { mutableStateOf("") }
    var confirmDelete by remember { mutableStateOf(false) }
    val accent = Color(0xFF39E5CB)
    val muted = Color(0xFF9BB3C6)
    val warning = Color(0xFFFFCA75)

    fun refresh() {
        val t = VerifiedSession.get(ctx) ?: return
        token = t
        scope.launch {
            AccountApi.call(endpoint, "/api/v1/account/me", t).fold(
                { profile = it }, { message = it.message ?: "Could not load account" })
            AccountApi.call(endpoint, "/api/v1/family", t).fold(
                { household = it }, { message = it.message ?: "Could not load household" })
        }
    }
    fun apply(path: String, method: String = "POST", data: JSONObject? = null,
              onSuccess: (JSONObject) -> Unit = {}) {
        val t = token ?: return
        busy = true; message = ""
        scope.launch {
            AccountApi.call(endpoint, path, t, method, data).fold(
                onSuccess = {
                    message = "Account update completed."
                    onSuccess(it)
                    if (token != null) refresh()
                },
                onFailure = { message = it.message ?: "Account request failed" }
            )
            busy = false
        }
    }
    LaunchedEffect(endpoint, token) { if (token != null) refresh() }
    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Text("My GhostForge Account", style = MaterialTheme.typography.headlineSmall)
        Text("Manage verified identity, tablets, and family members.", color = muted)
        if (token == null) {
            Text("Sign in by verifying your email address first.", color = warning)
            Button(onClick = onVerifyEmail) { Text("VERIFY EMAIL TO SIGN IN") }
        } else {
            Text("Verified: " + VerifiedSession.email(ctx), color = accent)
            OutlinedButton(onClick = { refresh() }) { Text("REFRESH ACCOUNT") }
            Text("YOUR DEVICES", color = accent)
            Button(onClick = {
                apply("/api/v1/account/devices", "POST",
                    JSONObject().put("device_id", AccountApi.localDeviceId(ctx))
                        .put("label", (Build.MANUFACTURER + " " + Build.MODEL).take(60)))
            }, enabled = !busy) { Text("REGISTER THIS DEVICE") }
            val devices = profile?.optJSONArray("devices")
            if (devices != null) for (i in 0 until devices.length()) {
                val dev = devices.optJSONObject(i) ?: continue
                val id = dev.optString("id")
                val label = dev.optString("label")
                Surface(color = MaterialTheme.colorScheme.surface,
                    border = BorderStroke(1.dp, muted.copy(alpha = 0.3f))) {
                    Row(Modifier.fillMaxWidth().padding(12.dp), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text(label, color = Color.White, modifier = Modifier.weight(1f))
                        TextButton(onClick = {
                            apply("/api/v1/account/devices/" + id, "DELETE")
                        }, enabled = !busy) { Text("Remove") }
                    }
                }
            }
            HorizontalDivider()
            Text("FAMILY GROUP", color = accent)
            val role = household?.optString("role") ?: "none"
            if (role == "none") {
                Text("No family group joined. Group management is available in this beta; no paid benefits are implied.",
                    color = muted)
                Button(onClick = { apply("/api/v1/family") }, enabled = !busy) { Text("CREATE FAMILY GROUP") }
                OutlinedTextField(value = joinCode, onValueChange = { joinCode = it.trim().take(128) },
                    modifier = Modifier.fillMaxWidth(), label = { Text("Invite code") })
                OutlinedButton(onClick = {
                    apply("/api/v1/family/join", data = JSONObject().put("invite_code",joinCode)) {
                        joinCode = ""
                    }
                }, enabled = !busy && joinCode.length >= 18) { Text("JOIN FAMILY") }
            } else {
                Text("Role: " + role.uppercase(), color = Color.White)
                val members = household?.optJSONArray("members")
                if (members != null) for (i in 0 until members.length()) {
                    val member = members.optJSONObject(i) ?: continue
                    val mail = member.optString("email")
                    val memberRole = member.optString("role")
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text(mail + " (" + memberRole + ")", color = muted,
                            modifier = Modifier.weight(1f))
                        if (role == "owner" && memberRole != "owner") {
                            TextButton(onClick = {
                                apply("/api/v1/family/members/" +
                                    java.net.URLEncoder.encode(mail,"UTF-8"), "DELETE")
                            }, enabled = !busy) { Text("Remove") }
                        }
                    }
                }
                if (role == "owner") {
                    Button(onClick = {
                        apply("/api/v1/family/invite") { inviteCode = it.optString("invite_code") }
                    }, enabled = !busy) { Text("CREATE 1-HOUR INVITE") }
                    if (inviteCode.isNotBlank()) {
                        Text("Invite (one-time): " + inviteCode, color = warning)
                        OutlinedButton(onClick = {
                            val share = Intent(Intent.ACTION_SEND).apply {
                                type = "text/plain"
                                putExtra(Intent.EXTRA_TEXT,"Join my GhostForge family group using this invite: " + inviteCode)
                            }
                            ctx.startActivity(Intent.createChooser(share,"Share invitation"))
                        }) { Text("SHARE INVITE") }
                    }
                    OutlinedButton(onClick = { apply("/api/v1/family","DELETE") },
                        enabled = !busy) { Text("DELETE FAMILY GROUP") }
                } else {
                    OutlinedButton(onClick = {
                        apply("/api/v1/family/members/" +
                            java.net.URLEncoder.encode(VerifiedSession.email(ctx),"UTF-8"), "DELETE")
                    }, enabled = !busy) { Text("LEAVE FAMILY GROUP") }
                }
            }
            HorizontalDivider()
            Row {
                Checkbox(checked = confirmDelete, onCheckedChange = { confirmDelete = it })
                Text("I understand deleting my account revokes GhostForge sessions and removes family/device records. It does not cancel Google Play subscriptions.",
                    color = warning, modifier = Modifier.padding(top = 6.dp))
            }
            OutlinedButton(onClick = {
                apply("/api/v1/account", "DELETE") {
                    VerifiedSession.clear(ctx)
                    token = null
                    profile = null
                    household = null
                    confirmDelete = false
                }
            }, enabled = confirmDelete && !busy) { Text("DELETE MY ACCOUNT DATA") }
        }
        if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
        if (message.isNotBlank()) Text(message, color = warning)
        Text("Email sessions expire after 30 days. This beta requires your own securely hosted HTTPS API.",
            color = muted)
    }
}
