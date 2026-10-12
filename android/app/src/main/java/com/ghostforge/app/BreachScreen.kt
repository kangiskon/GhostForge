package com.ghostforge.app

import android.Manifest
import android.content.Context
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.work.*
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.util.concurrent.TimeUnit

private val secondary = Color(0xFF9BB3C6)
private val highlight = Color(0xFF39E5CB)
private val caution = Color(0xFFFFCA75)
private val threat = Color(0xFFFF747B)

@Composable private fun Notice(message: String, color: Color = secondary) {
    Surface(color = MaterialTheme.colorScheme.surface, border = BorderStroke(1.dp, color.copy(alpha = 0.35f))) {
        Text(message, color = color, modifier = Modifier.fillMaxWidth().padding(14.dp))
    }
}

@Composable
fun BreachScreen(endpoint: String) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var email by rememberSaveable { mutableStateOf(VerifiedSession.email(ctx)) }
    var code by rememberSaveable { mutableStateOf("") }
    var token by remember { mutableStateOf(VerifiedSession.get(ctx)) }
    var feedback by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var data by remember { mutableStateOf<JSONObject?>(null) }
    var enabled by remember {
        mutableStateOf(ctx.getSharedPreferences("ghostforge_settings", Context.MODE_PRIVATE)
            .getBoolean("breach_monitor", false))
    }
    val notifications = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (!granted) feedback = "Notification permission not granted. Background checking may run without alerts."
    }
    fun schedule(wanted: Boolean) {
        enabled = wanted
        ctx.getSharedPreferences("ghostforge_settings", Context.MODE_PRIVATE)
            .edit().putBoolean("breach_monitor", wanted).apply()
        val work = WorkManager.getInstance(ctx)
        if (wanted) {
            val request = PeriodicWorkRequestBuilder<BreachMonitorWorker>(12, TimeUnit.HOURS)
                .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                .build()
            work.enqueueUniquePeriodicWork("ghostforge-breach-monitor", ExistingPeriodicWorkPolicy.UPDATE, request)
        } else work.cancelUniqueWork("ghostforge-breach-monitor")
    }
    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Text("Verified Breach Monitoring", style = MaterialTheme.typography.headlineSmall)
        Text("Confirm ownership of an email before its breach records can be checked.", color = secondary)
        if (token == null) {
            OutlinedTextField(value = email, onValueChange = { email = it.trim().take(254) },
                label = { Text("Email address") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            Button(onClick = {
                busy = true; feedback = ""
                scope.launch {
                    SecurityApi.sendCode(endpoint, email).fold(
                        onSuccess = { feedback = "Check your email for the 6-digit code." },
                        onFailure = { feedback = it.message ?: "Verification email unavailable" })
                    busy = false
                }
            }, enabled = !busy && email.contains("@")) { Text("SEND CODE") }
            OutlinedTextField(value = code, onValueChange = { code = it.filter(Char::isDigit).take(6) },
                label = { Text("Email verification code") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            Button(onClick = {
                busy = true; feedback = ""
                scope.launch {
                    SecurityApi.verify(endpoint, email, code).fold(
                        onSuccess = {
                            val newToken = it.optString("token")
                            if (newToken.isNotBlank()) {
                                VerifiedSession.save(ctx, newToken, email)
                                token = newToken
                                feedback = "Address verified."
                            } else feedback = "The server did not return a session."
                        },
                        onFailure = { feedback = it.message ?: "Verification failed" })
                    busy = false
                }
            }, enabled = !busy && code.length == 6) { Text("VERIFY ADDRESS") }
        } else {
            Notice("Verified address: " + VerifiedSession.email(ctx), highlight)
            Button(onClick = {
                busy = true; feedback = ""; data = null
                scope.launch {
                    SecurityApi.breaches(endpoint, token!!).fold(
                        onSuccess = { data = it },
                        onFailure = { feedback = it.message ?: "Breach lookup failed" })
                    busy = false
                }
            }, enabled = !busy, modifier = Modifier.fillMaxWidth()) { Text("CHECK BREACHES") }
            Row(modifier = Modifier.fillMaxWidth()) {
                Checkbox(checked = enabled, onCheckedChange = {
                    schedule(it)
                    if (it && Build.VERSION.SDK_INT >= 33)
                        notifications.launch(Manifest.permission.POST_NOTIFICATIONS)
                })
                Text("Check periodically and alert me if new breaches are reported.",
                    color = secondary, modifier = Modifier.padding(top = 6.dp))
            }
            OutlinedButton(onClick = {
                if (enabled) schedule(false)
                busy = true
                scope.launch {
                    SecurityApi.delete(endpoint, token!!).fold(
                        onSuccess = {
                            VerifiedSession.clear(ctx)
                            token = null
                            data = null
                            feedback = "Server-side verification records deleted."
                        },
                        onFailure = { feedback = it.message ?: "Deletion failed. Try again." })
                    busy = false
                }
            }, enabled = !busy) { Text("DELETE VERIFIED SESSION") }
        }
        if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
        if (feedback.isNotBlank()) Notice(feedback, caution)
        data?.let { result ->
            val checked = result.optBoolean("checked", false)
            val list = result.optJSONArray("breaches")
            when {
                !checked -> Notice("Provider unavailable: " + result.optString("status"), caution)
                list == null || list.length() == 0 ->
                    Notice("No matching breaches found by the configured service. This does not prove your account is secure.", highlight)
                else -> {
                    Notice("Reported exposure in " + list.length() + " breaches:", threat)
                    for (i in 0 until list.length())
                        Text("• " + list.optString(i), color = caution)
                    Notice("Change reused passwords, use MFA, and review exposed accounts.")
                }
            }
        }
        Notice("The server requires SMTP verification, a paid HIBP API key, and secure deployment. Verification sessions expire in 30 days; background checks can be delayed by Android.")
    }
}
