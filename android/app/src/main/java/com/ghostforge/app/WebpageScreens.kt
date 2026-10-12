package com.ghostforge.app

import android.content.Intent
import android.provider.Settings
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

private val ghostMint = Color(0xFF39E5CB)
private val ghostMuted = Color(0xFF9BB3C6)
private val ghostAmber = Color(0xFFFFCA75)

@Composable
fun WebpageInspectorScreen(initialUrl: String = "") {
    var url by rememberSaveable(initialUrl) { mutableStateOf(initialUrl) }
    var consent by rememberSaveable { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var feedback by remember { mutableStateOf("") }
    var report by remember { mutableStateOf<WebpageReport?>(null) }
    val scope = rememberCoroutineScope()

    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Text("Webpage Inspector", style = MaterialTheme.typography.headlineSmall)
        Text("Explicitly inspect the first HTML response of a public HTTPS webpage. " +
            "GhostForge does not launch the webpage, execute JavaScript, load images or follow redirects.",
            color = ghostMuted)
        OutlinedTextField(
            value = url, onValueChange = { url = it.take(2048) },
            label = { Text("Public HTTPS webpage") },
            placeholder = { Text("https://example.com") },
            modifier = Modifier.fillMaxWidth(), minLines = 2, maxLines = 4
        )
        Row(Modifier.fillMaxWidth()) {
            Checkbox(checked = consent, onCheckedChange = { consent = it })
            Text("I agree that GhostForge will send an HTTPS request directly from this phone " +
                "to the entered website to read its publicly accessible HTML. " +
                "Do not inspect private, logged-in, or sensitive URLs.",
                color = ghostMuted, modifier = Modifier.padding(top = 10.dp))
        }
        Button(onClick = {
            busy = true
            feedback = ""
            report = null
            scope.launch {
                WebpageInspector.inspect(url).fold(
                    onSuccess = { report = it },
                    onFailure = { feedback = it.message ?: "Unable to inspect this page." }
                )
                busy = false
            }
        }, enabled = consent && !busy && url.startsWith("https://", true),
            modifier = Modifier.fillMaxWidth()) {
            Text(if (busy) "INSPECTING…" else "INSPECT WEBPAGE HTML")
        }
        if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
        if (feedback.isNotBlank()) {
            Surface(color = MaterialTheme.colorScheme.surface,
                border = BorderStroke(1.dp, ghostAmber)) {
                Text(feedback, color = ghostAmber, modifier = Modifier.fillMaxWidth().padding(14.dp))
            }
        }
        report?.let { result ->
            Surface(color = MaterialTheme.colorScheme.surface,
                border = BorderStroke(1.dp, ghostAmber.copy(alpha=0.5f))) {
                Column(Modifier.fillMaxWidth().padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(9.dp)) {
                    Text(result.verdict.uppercase().replace('_',' '),
                        color = ghostAmber, style = MaterialTheme.typography.titleLarge)
                    Text("Website: " + result.host, color = Color.White)
                    Text("Page title: " + result.title, color = Color.White)
                    Text("HTTP: " + result.httpCode +
                        " • Analyzed text characters: " + result.sampleChars, color = ghostMuted)
                    if (result.signals.isEmpty()) {
                        Text("No listed warning signs found. This is NOT a safety verdict.",
                            color = ghostAmber)
                    } else {
                        result.signals.forEach { signal ->
                            Text("• " + signal, color = ghostAmber)
                        }
                    }
                    Text(result.notice, color = ghostMuted)
                }
            }
        }
        Text("Fetching a suspicious site can reveal your IP address to that site and " +
            "could trigger tracking. This is manual inspection only, not automatic " +
            "scanning of pages you visit in other browsers.",
            color = ghostAmber)
    }
}

@Composable
fun EncryptedDnsAuditScreen() {
    val context = LocalContext.current
    var refresh by remember { mutableIntStateOf(0) }
    val privateDnsMode = remember(refresh) {
        try {
            Settings.Global.getString(context.contentResolver, "private_dns_mode").orEmpty()
        } catch (_: Exception) { "unavailable" }
    }
    val privateDnsProvider = remember(refresh) {
        try {
            Settings.Global.getString(context.contentResolver, "private_dns_specifier").orEmpty()
        } catch (_: Exception) { "" }
    }
    val dnsDescription = when (privateDnsMode) {
        "hostname" -> "Custom DNS-over-TLS is enabled; it can bypass GhostForge's DNS-only filter."
        "opportunistic" -> "Android Private DNS is Automatic. DNS-over-TLS may be in use."
        "off" -> "Android Private DNS is off. Apps can still use their own encrypted DNS."
        else -> "The phone did not report an identifiable Private DNS configuration."
    }

    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Text("Encrypted DNS Audit", style = MaterialTheme.typography.headlineSmall)
        Text("See what Android exposes about encrypted DNS and protection gaps.",
            color = ghostMuted)
        Text(if (DnsGuardService.running)
            "GhostForge DNS Guard: ACTIVE (IPv4 UDP DNS only)"
            else "GhostForge DNS Guard: NOT RUNNING",
            color = if (DnsGuardService.running) ghostMint else ghostAmber)
        Text("Android Private DNS mode: " + privateDnsMode.ifBlank { "unknown" },
            color = Color.White)
        Text(dnsDescription, color = ghostAmber)
        if (privateDnsMode == "hostname" && privateDnsProvider.isNotBlank()) {
            Text("Configured DNS provider: " + privateDnsProvider.take(200), color = ghostMuted)
        }
        HorizontalDivider()
        Text("What GhostForge can observe", color = ghostMint)
        Text("• System Private DNS mode and whether GhostForge DNS Guard is active.\n" +
            "• Ordinary DNS packets redirected by the existing DNS-only VPN.\n" +
            "• Domains blocked by your custom DNS list.",
            color = Color.White)
        Text("What it cannot inspect yet", color = ghostAmber)
        Text("• Encrypted DNS-over-HTTPS requests made inside Chrome, Firefox or other apps.\n" +
            "• DNS-over-TLS packets sent by an app directly to an encrypted resolver.\n" +
            "• HTTPS page contents in unrelated apps, TLS certificate-pinned requests, " +
            "or apps' private traffic.",
            color = ghostMuted)
        OutlinedButton(onClick = { refresh++ }, modifier=Modifier.fillMaxWidth()) {
            Text("REFRESH DNS AUDIT")
        }
        OutlinedButton(onClick = {
            val intent = Intent(Settings.ACTION_WIRELESS_SETTINGS)
            runCatching { context.startActivity(intent) }
        }, modifier=Modifier.fillMaxWidth()) {
            Text("OPEN ANDROID NETWORK SETTINGS")
        }
        Text("No interception certificate is installed. This screen does not secretly " +
            "intercept or decrypt another app's DNS or HTTPS sessions. " +
            "Full traffic metadata monitoring requires a separately tested full-tunnel VPN.",
            color = ghostAmber)
    }
}
