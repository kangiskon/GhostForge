package com.ghostforge.app

import android.content.Intent
import android.net.Uri
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

private val qrMint = Color(0xFF39E5CB)
private val qrAmber = Color(0xFFFFCA75)
private val qrDanger = Color(0xFFFF747B)
private val qrMuted = Color(0xFF9BB3C6)

@Composable
fun QrSafetyReviewScreen(
    payload: String,
    endpoint: String,
    onScanAgain: () -> Unit,
    onManualWebpageInspection: (String) -> Unit
) {
    val ctx = LocalContext.current
    var verdict by remember(payload) { mutableStateOf<QrAssessment?>(null) }
    var checking by remember(payload) { mutableStateOf(false) }
    var browserConsent by rememberSaveable(payload) { mutableStateOf(false) }
    var openError by remember(payload) { mutableStateOf("") }

    // The QR scan merely decodes text and navigates here. It never opens the QR payload.
    LaunchedEffect(payload, endpoint) {
        browserConsent = false
        openError = ""
        checking = true
        val local = QrSafetyGate.inspect(payload)
        verdict = local
        val liveAvailable = endpoint.startsWith("https://") && !endpoint.endsWith(".invalid")
        if (liveAvailable && local.canOfferOpen) {
            val response = ScannerApi.scan(endpoint, payload)
            if (response.isSuccess) {
                verdict = QrSafetyGate.applyReputation(local, response.getOrThrow())
            }
            // Timeout or no Web Risk credentials -> stays UNVERIFIED. NEVER "SAFE".
        }
        checking = false
    }

    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Text("QR Safety Check", style = MaterialTheme.typography.headlineSmall)
        Text("The QR code has been decoded, but its destination has NOT been opened.",
            color = qrMuted)
        OutlinedButton(onClick = onScanAgain, modifier = Modifier.fillMaxWidth()) {
            Text("SCAN ANOTHER QR CODE")
        }
        if (checking) {
            LinearProgressIndicator(Modifier.fillMaxWidth())
            Text("Checking QR format, URL warning signs and available reputation service…",
                color = qrMuted)
        }
        verdict?.let { result ->
            val color = when (result.verdict) {
                QrVerdict.BLOCKED -> qrDanger
                QrVerdict.WARNING -> qrAmber
                QrVerdict.UNVERIFIED -> qrAmber
                QrVerdict.NOT_LISTED -> qrMint
            }
            Surface(color = MaterialTheme.colorScheme.surface,
                border = BorderStroke(1.dp, color.copy(alpha = 0.65f))) {
                Column(Modifier.fillMaxWidth().padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(result.title.uppercase(), color = color, fontWeight = FontWeight.Bold,
                        style = MaterialTheme.typography.titleLarge)
                    Text(result.explanation, color = Color.White)
                    Text("QR contents: " + payload.take(300), color = qrMuted)
                    if (result.host != null) {
                        Text("Website hostname: " + result.host, color = Color.White)
                    }
                    Text(
                        if (result.checkedThreatLists) "Online threat-list response received."
                        else "No confirmed live threat-list clearance. Local checks only or reputation unavailable.",
                        color = qrMuted
                    )
                    result.reasons.forEach { reason -> Text("• " + reason, color = color) }
                }
            }

            if (!checking && result.canOfferOpen) {
                Row(Modifier.fillMaxWidth()) {
                    Checkbox(checked = browserConsent, onCheckedChange = { browserConsent = it })
                    Text("I understand this link isn't guaranteed safe. Open it in my browser " +
                        "only because I explicitly choose to continue.",
                        color = qrMuted, modifier = Modifier.padding(top = 8.dp))
                }
                Button(onClick = {
                    val url = result.url
                    // Defense in depth: never trust an unvalidated or changed payload here.
                    if (url == null || url != payload.trim() ||
                        !result.canOfferOpen || checking || !browserConsent) {
                        openError = "Website opening blocked. Scan the QR code again."
                    } else {
                        runCatching {
                            val destination = Uri.parse(url)
                            require(destination.scheme.equals("https", true)) {
                                "Only HTTPS links can be opened."
                            }
                            ctx.startActivity(
                                Intent(Intent.ACTION_VIEW, destination)
                                    .addCategory(Intent.CATEGORY_BROWSABLE)
                            )
                        }.onFailure { openError = it.message ?: "No browser available." }
                    }
                }, enabled = browserConsent && !checking,
                    modifier = Modifier.fillMaxWidth()) {
                    Text(if (result.verdict == QrVerdict.NOT_LISTED)
                        "OPEN WEBSITE — NOT GUARANTEED SAFE" else
                        "OPEN UNVERIFIED WEBSITE — I ACCEPT THE RISK")
                }
                OutlinedButton(onClick = {
                    result.url?.let(onManualWebpageInspection)
                }, enabled = result.url?.startsWith("https://",true) == true,
                    modifier = Modifier.fillMaxWidth()) {
                    Text("INSPECT PAGE HTML BEFORE OPENING")
                }
            } else if (!checking) {
                Text("GhostForge has disabled the Open Website action. " +
                    "Scan a different code or verify the destination through another trusted source.",
                    color = qrDanger)
            }
            if (openError.isNotBlank()) Text(openError, color = qrDanger)
            Text("QR safety checks cannot prove a website is harmless. Redirects, " +
                "dynamic scripts and newly created phishing pages may hide threats; " +
                "opening a link gives its website your network address.",
                color = qrAmber)
        }
    }
}
