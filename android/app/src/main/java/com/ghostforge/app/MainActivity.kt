package com.ghostforge.app

import android.content.Intent
import android.app.Activity
import android.net.VpnService
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import kotlinx.coroutines.delay
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import kotlinx.coroutines.launch

private val ink = Color(0xFF08101D)
private val panel = Color(0xFF122136)
private val mint = Color(0xFF39E5CB)
private val muted = Color(0xFF9BB3C6)
private val amber = Color(0xFFFFCA75)
private val danger = Color(0xFFFF747B)

class MainActivity : ComponentActivity() {
    private var sharedText by mutableStateOf("")
    private fun incoming(intent: Intent?): String {
        if (intent?.action != Intent.ACTION_SEND || intent.type != "text/plain") return ""
        val value = intent.getStringExtra(Intent.EXTRA_TEXT).orEmpty().take(2048)
        return Regex("""https?://[^\s<>()]+""").find(value)?.value ?: value
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        sharedText = incoming(intent)
        setContent {
            MaterialTheme(colorScheme = darkColorScheme(primary = mint, background = ink, surface = panel)) {
                GhostForgeScreen(sharedText, onQr = { onCode ->
                    GmsBarcodeScanning.getClient(this).startScan()
                        .addOnSuccessListener { barcode -> barcode.rawValue?.let(onCode) }
                })
            }
        }
    }
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        sharedText = incoming(intent)
    }
}

@Composable
private fun GhostForgeScreen(shared: String, onQr: ((String) -> Unit) -> Unit) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val prefs = remember { context.getSharedPreferences("ghostforge_settings", 0) }
    var endpoint by rememberSaveable { mutableStateOf(prefs.getString("endpoint", "https://api.example.invalid") ?: "https://api.example.invalid") }
    var endpointDraft by rememberSaveable { mutableStateOf(endpoint) }
    var tab by rememberSaveable { mutableIntStateOf(0) }
    var link by rememberSaveable { mutableStateOf(shared) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf("") }
    var result by remember { mutableStateOf<ScanFinding?>(null) }
    val history = remember { mutableStateListOf<ScanFinding>() }
    val scope = rememberCoroutineScope()
    var consent by rememberSaveable { mutableStateOf(false) }
    var blockedDomains by rememberSaveable { mutableStateOf(prefs.getString("blocked_domains", "") ?: "") }
    var guardRunning by remember { mutableStateOf(DnsGuardService.running) }
    var blocks by remember { mutableIntStateOf(DnsGuardService.blockedCount) }
    var apkReport by remember { mutableStateOf<ApkReport?>(null) }
    var apkError by remember { mutableStateOf("") }
    var apkBusy by remember { mutableStateOf(false) }
    val vpnPermission = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            context.startForegroundService(Intent(context, DnsGuardService::class.java).setAction(DnsGuardService.START))
        } else error = "Android VPN permission was not granted."
    }
    val apkPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            apkBusy = true; apkError = ""; apkReport = null
            scope.launch {
                ApkInspector.inspect(context, uri, endpoint).fold(
                    onSuccess = { apkReport = it },
                    onFailure = { apkError = it.message ?: "APK inspection failed." }
                )
                apkBusy = false
            }
        }
    }
    LaunchedEffect(Unit) {
        while (true) {
            guardRunning = DnsGuardService.running
            blocks = DnsGuardService.blockedCount
            delay(1200L)
        }
    }

    LaunchedEffect(shared) {
        if (shared.isNotBlank()) { link = shared; tab = 1 }
    }
    fun scan(text: String) {
        if (busy) return
        if (text.isBlank()) { error = "Paste a website link."; tab = 1; return }
        error = ""; result = null; busy = true; tab = 1
        scope.launch {
            ScannerApi.scan(endpoint, text).fold(
                onSuccess = { item ->
                    result = item; history.add(0, item)
                    if (history.size > 20) history.removeAt(history.lastIndex)
                },
                onFailure = { error = it.message ?: "Scanner unavailable. Check your backend." }
            )
            busy = false
        }
    }
    Scaffold(containerColor = ink, bottomBar = {
        Row(Modifier.fillMaxWidth().background(panel).navigationBarsPadding().horizontalScroll(rememberScrollState()).padding(10.dp), horizontalArrangement = Arrangement.spacedBy(9.dp)) {
            listOf(0 to "Home", 1 to "Links", 4 to "DNS Guard", 5 to "APK Scan", 2 to "History", 3 to "Settings").forEach { (i, name) ->
                Text(name, modifier = Modifier.clickable { tab = i }.padding(10.dp),
                    color = if (tab == i) mint else muted, fontSize = 13.sp)
            }
        }
    }) { inner ->
        Column(Modifier.fillMaxSize().padding(inner).verticalScroll(rememberScrollState()).padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("⬡", color = mint, fontSize = 38.sp)
                Spacer(Modifier.width(10.dp))
                Column {
                    Text("GHOSTFORGE", fontWeight = FontWeight.Black, color = Color.White, fontSize = 25.sp)
                    Text("ANDROID SECURITY LAB  •  BETA", color = mint, fontSize = 10.sp)
                }
            }
            when (tab) {
                0 -> {
                    Surface(color = panel, shape = RoundedCornerShape(20.dp), border = BorderStroke(1.dp, mint.copy(alpha = 0.4f))) {
                        Column(Modifier.fillMaxWidth().background(Brush.verticalGradient(listOf(Color(0xFF1A4250), panel))).padding(22.dp),
                            verticalArrangement = Arrangement.spacedBy(10.dp)) {
                            Text("◈ SECURITY STATUS", color = mint, fontSize = 13.sp)
                            Text("Ready to investigate", color = Color.White, fontSize = 24.sp, fontWeight = FontWeight.Bold)
                            Text(if (guardRunning) "DNS Guard is running. DNS filtering is active for matching domains." else "Manual scanning works; DNS Guard is off.", color = muted)
                            Button(onClick = { tab = 1 }, modifier = Modifier.fillMaxWidth()) { Text("SCAN A SUSPICIOUS LINK") }
                        }
                    }
                    Section("Your security toolkit", "Analyze links shared from other apps or encoded in QR codes.")
                    Text("Links scanned this session: " + history.size, color = mint)
                    Text("Local DNS Guard can only block listed domains; it does not inspect encrypted URLs or replace Google Play Protect.", color = amber)
                }
                1 -> {
                    Section("Link investigator", "Check a suspicious URL before opening it.")
                    Surface(color = panel, shape = RoundedCornerShape(18.dp)) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            OutlinedTextField(value = link, onValueChange = { link = it }, label = { Text("Website link") },
                                modifier = Modifier.fillMaxWidth(), maxLines = 4)
                            Button(onClick = { scan(link) }, enabled = !busy, modifier = Modifier.fillMaxWidth()) { Text("ANALYZE LINK") }
                            OutlinedButton(onClick = { onQr { code -> link = code; scan(code) } }, modifier = Modifier.fillMaxWidth()) {
                                Text("SCAN QR CODE")
                            }
                        }
                    }
                    if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
                    if (error.isNotBlank()) Note(error, danger)
                    result?.let { finding ->
                        val color = when (finding.verdict) { "malicious" -> danger; "suspicious" -> amber; else -> muted }
                        Surface(color = panel, shape = RoundedCornerShape(18.dp), border = BorderStroke(1.dp, color)) {
                            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(9.dp)) {
                                Text(finding.verdict.uppercase().replace("_", " "), color = color, fontSize = 23.sp, fontWeight = FontWeight.Bold)
                                Text(finding.host, color = Color.White, fontWeight = FontWeight.Bold)
                                Text(finding.message, color = Color.White)
                                Text("Reputation lookup: " + finding.lookup, color = muted)
                                finding.signals.forEach { Text("• " + it, color = amber) }
                                if (finding.threats.isNotEmpty()) Text("Threat lists: " + finding.threats.joinToString(), color = danger)
                            }
                        }
                        Note("No automated scan guarantees safety. GhostForge never visits the entered URL.", muted)
                    }
                }
                2 -> {
                    Section("Recent checks", "Stored only while the app process runs.")
                    if (history.isEmpty()) Note("No scans yet.", muted)
                    history.forEach { item ->
                        Surface(color = panel, shape = RoundedCornerShape(14.dp), modifier = Modifier.fillMaxWidth().clickable {
                            result = item; link = item.url; tab = 1
                        }) {
                            Column(Modifier.padding(14.dp)) {
                                Text(item.host, color = Color.White)
                                Text(item.verdict.uppercase(), color = muted, fontSize = 12.sp)
                            }
                        }
                    }
                    TextButton(onClick = { history.clear() }) { Text("Clear history") }
                }

                4 -> {
                    Section("DNS Guard", "Optional background blocking of domains on your blocklist and configured GhostForge feed.")
                    Surface(color = panel, shape = RoundedCornerShape(16.dp)) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            Text(if (guardRunning) "ACTIVE • $blocks DNS queries blocked this session" else "NOT RUNNING",
                                color = if (guardRunning) mint else amber, fontWeight = FontWeight.Bold)
                            Text("This creates an Android VPN that handles only DNS requests. DNS questions not blocked locally are sent to Cloudflare over HTTPS. GhostForge does not inspect webpage contents, and some apps' encrypted DNS traffic can bypass filtering. Android allows one VPN at a time. Turning this on can interfere with another VPN or some networks.",
                                color = muted, fontSize = 13.sp)
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Checkbox(checked = consent, onCheckedChange = { consent = it })
                                Text("I understand and consent to the VPN and Cloudflare DNS handling.", color = Color.White, fontSize = 12.sp)
                            }
                            if (!guardRunning) Button(onClick = {
                                error = ""
                                val permission = VpnService.prepare(context)
                                if (permission != null) vpnPermission.launch(permission)
                                else context.startForegroundService(
                                    Intent(context, DnsGuardService::class.java).setAction(DnsGuardService.START)
                                )
                            }, enabled = consent, modifier = Modifier.fillMaxWidth()) { Text("START DNS GUARD") }
                            else OutlinedButton(onClick = {
                                context.startService(Intent(context, DnsGuardService::class.java).setAction(DnsGuardService.STOP))
                            }, modifier = Modifier.fillMaxWidth()) { Text("STOP DNS GUARD") }
                            if (DnsGuardService.lastError.isNotBlank()) Note(DnsGuardService.lastError, danger)
                        }
                    }
                    Section("Custom blocked domains", "One domain per line. For example: malware.test (safe test-only domain).")
                    OutlinedTextField(value = blockedDomains, onValueChange = { blockedDomains = it },
                        label = { Text("Blocklist") }, minLines = 3, maxLines = 8, modifier = Modifier.fillMaxWidth())
                    OutlinedButton(onClick = {
                        prefs.edit().putString("blocked_domains", blockedDomains).apply()
                        error = "Saved. Stop and restart DNS Guard to apply changes."
                    }) { Text("SAVE BLOCKLIST") }
                    if (error.isNotBlank()) Note(error, muted)
                    Note("Only malware.test is preloaded as a demonstration rule. Configure a vetted backend threat feed to block real-world threats. Failure to resolve DNS can also indicate a network issue, not a confirmed threat.", amber)
                }
                5 -> {
                    Section("APK File Inspector", "Inspect an APK you choose. Files are not uploaded.")
                    Surface(color = panel, shape = RoundedCornerShape(16.dp)) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            Text("Checks archive format, reads package permissions, calculates SHA-256 and optionally asks your backend whether the hash matches a known-malicious file.",
                                color = muted)
                            Button(onClick = { apkPicker.launch(arrayOf("*/*")) },
                                enabled = !apkBusy, modifier = Modifier.fillMaxWidth()) { Text("CHOOSE APK TO INSPECT") }
                            if (apkBusy) LinearProgressIndicator(Modifier.fillMaxWidth())
                            if (apkError.isNotBlank()) Note(apkError, danger)
                        }
                    }
                    apkReport?.let { report ->
                        Surface(color = panel, shape = RoundedCornerShape(16.dp)) {
                            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                Text(if (report.reputation == "known_malicious") "KNOWN MALICIOUS HASH"
                                    else "UNKNOWN REPUTATION", fontWeight = FontWeight.Bold,
                                    color = if (report.reputation == "known_malicious") danger else amber)
                                Text("Package: " + report.packageId, color = Color.White)
                                Text("Version: " + report.version, color = muted)
                                Text("SHA-256: " + report.sha256, color = muted, fontSize = 11.sp)
                                Text(report.details, color = Color.White)
                                if (report.risks.isNotEmpty()) report.risks.forEach { Text("• " + it, color = amber) }
                                else Text("No listed risky permissions found. This does not mean the APK is safe.", color = muted)
                            }
                        }
                    }
                }
                3 -> {
                    Section("Settings", "Connect your trusted HTTPS GhostForge scanner server.")
                    OutlinedTextField(value = endpointDraft, onValueChange = { endpointDraft = it },
                        label = { Text("Backend HTTPS URL") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
                    Button(onClick = {
                        val proposed = endpointDraft.trim().trimEnd('/')
                        if (proposed.startsWith("https://")) {
                            endpoint = proposed
                            prefs.edit().putString("endpoint", proposed).apply()
                            error = "Backend saved."
                        } else error = "Only HTTPS addresses are accepted."
                    }) { Text("Save backend") }
                    if (error.isNotBlank()) Note(error, muted)
                    Note("Version 0.2.0 • DNS filtering is opt-in and only blocks listed domains. APK inspection is heuristic/hash-based, not complete malware detection. Accounts and subscriptions are not built.", amber)
                }
            }
        }
    }
}

@Composable
private fun Section(title: String, detail: String) {
    Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
        Text(title, color = Color.White, fontSize = 23.sp, fontWeight = FontWeight.Bold)
        Text(detail, color = muted, fontSize = 13.sp)
    }
}

@Composable
private fun Note(message: String, color: Color) {
    Surface(shape = RoundedCornerShape(14.dp), color = panel, border = BorderStroke(1.dp, color.copy(alpha = 0.4f))) {
        Text(message, color = color, modifier = Modifier.fillMaxWidth().padding(15.dp))
    }
}
