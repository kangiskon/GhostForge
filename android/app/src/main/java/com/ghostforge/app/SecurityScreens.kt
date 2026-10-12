package com.ghostforge.app

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.provider.Settings
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.time.LocalDate
import java.time.temporal.ChronoUnit

private val mint = Color(0xFF39E5CB)
private val muted = Color(0xFF9BB3C6)
private val warn = Color(0xFFFFCA75)
private val danger = Color(0xFFFF747B)

@Composable private fun Detail(message: String, color: Color = muted) {
    Surface(color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, color.copy(alpha = 0.35f))) {
        Text(message, color = color, modifier = Modifier.fillMaxWidth().padding(14.dp))
    }
}
@Composable private fun Heading(name: String, detail: String) {
    Text(name, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
    Text(detail, color = muted)
}

@Composable
fun ScamScreen(endpoint: String, shared: String) {
    var content by rememberSaveable { mutableStateOf(shared) }
    var usingAi by rememberSaveable { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var feedback by remember { mutableStateOf("") }
    var data by remember { mutableStateOf<JSONObject?>(null) }
    val scope = rememberCoroutineScope()
    LaunchedEffect(shared) { if (shared.isNotBlank()) content = shared }
    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Heading("Scam Investigator", "Paste or share a suspicious SMS, email, social message, or online offer. Links are never opened.")
        OutlinedTextField(value = content, onValueChange = { content = it.take(5000) },
            modifier = Modifier.fillMaxWidth().heightIn(min = 150.dp),
            label = { Text("Message to inspect") }, minLines = 5, maxLines = 12)
        Row(modifier = Modifier.fillMaxWidth()) {
            Checkbox(checked = usingAi, onCheckedChange = { usingAi = it })
            Text("Opt in to external AI analysis. Sends your selected text to the configured AI provider.",
                color = muted, modifier = Modifier.padding(top = 7.dp))
        }
        Button(onClick = {
            feedback = ""; data = null; busy = true
            scope.launch {
                SecurityApi.analyze(endpoint, content, usingAi).fold(
                    onSuccess = { data = it },
                    onFailure = { feedback = it.message ?: "Analysis unavailable" }
                )
                busy = false
            }
        }, enabled = !busy && content.length >= 3, modifier = Modifier.fillMaxWidth()) {
            Text("INVESTIGATE MESSAGE")
        }
        if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
        if (feedback.isNotBlank()) Detail(feedback, danger)
        data?.let { result ->
            val risk = result.optString("risk", "unverified")
            Detail("RESULT: " + risk.replace('_', ' ').uppercase(), if (risk == "high_warning") danger else warn)
            Text(result.optString("summary"), color = Color.White)
            Text("Analysis mode: " + result.optString("mode"), color = muted)
            val reasons = result.optJSONArray("reasons")
            if (reasons != null) for (i in 0 until reasons.length()) {
                Text("• " + reasons.optString(i), color = warn)
            }
            val advice = result.optJSONArray("advice")
            if (advice != null) for (i in 0 until advice.length()) {
                Text("✓ " + advice.optString(i), color = Color.White)
            }
            Detail(result.optString("privacy"), muted)
        }
        Detail("This is risk guidance, not proof a message is authentic. Heuristic and AI modes require a configured HTTPS backend.", warn)
    }
}

@Composable
fun DeviceScreen() {
    val ctx = LocalContext.current
    val manager = ctx.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
    val locked = manager.isDeviceSecure
    val patch = Build.VERSION.SECURITY_PATCH
    val days = try { ChronoUnit.DAYS.between(LocalDate.parse(patch), LocalDate.now()) } catch (_: Exception) { -1L }
    val adb = Settings.Global.getInt(ctx.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Heading("Device Security Check", "Local Android configuration audit; device identifiers are not uploaded.")
        Detail("Device: " + Build.MANUFACTURER + " " + Build.MODEL +
            "\nAndroid: " + Build.VERSION.RELEASE + " (API " + Build.VERSION.SDK_INT + ")" +
            "\nSecurity patch: " + patch, mint)
        Detail(if (locked) "✓ Screen-lock authentication is configured."
            else "Action recommended: Configure a PIN, password, or biometric-backed screen lock.",
            if (locked) mint else danger)
        Detail(if (days < 0) "Security patch age unavailable."
            else if (days <= 90) "✓ Security patch age: " + days + " days"
            else "Security patch age: " + days + " days. Check for system updates.",
            if (days in 0..90) mint else warn)
        Detail(if (adb) "USB debugging is enabled. Turn it off when it is not needed."
            else "✓ USB debugging is disabled.", if (adb) warn else mint)
        Detail("GhostForge cannot read private app data or Play Protect malware results. Passing these checks does not prove a device is malware-free.")
    }
}
