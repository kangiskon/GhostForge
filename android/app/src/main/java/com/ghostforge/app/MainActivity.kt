package com.ghostforge.app

import android.content.Intent
import android.app.Activity
import android.Manifest
import android.os.Build
import android.content.pm.PackageManager
import androidx.core.content.ContextCompat
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
        return value
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
    val savedHistory = remember { mutableStateListOf<ScanEvent>().apply { addAll(SecurityHistory.read(context)) } }
    val scope = rememberCoroutineScope()
    var consent by rememberSaveable { mutableStateOf(false) }
    var blockedDomains by rememberSaveable { mutableStateOf(prefs.getString("blocked_domains", "") ?: "") }
    var guardRunning by remember { mutableStateOf(DnsGuardService.running) }
    var vpnStatus by remember { mutableStateOf(
        prefs.getString("vpn_status", "Idle. Tap Start to request Android VPN access.").orEmpty()
    ) }
    var vpnFailure by remember { mutableStateOf(DnsGuardService.lastError) }
    var startupMessage by remember { mutableStateOf("") }
    var startupPending by remember { mutableStateOf(false) }
    var blocks by remember { mutableIntStateOf(DnsGuardService.blockedCount) }
    var forwarded by remember { mutableIntStateOf(DnsGuardService.forwardedCount) }
    var failures by remember { mutableIntStateOf(DnsGuardService.resolverErrors) }
    var checkingResolver by remember { mutableStateOf(false) }
    var resolverCheck by remember { mutableStateOf("") }
    var apkReport by remember { mutableStateOf<ApkReport?>(null) }
    var apkError by remember { mutableStateOf("") }
    var apkBusy by remember { mutableStateOf(false) }
    fun launchService() {
        startupPending = true
        startupMessage = "Android VPN permission granted. Starting DNS Guard service…"
        try {
            context.startForegroundService(Intent(context, DnsGuardService::class.java).setAction(DnsGuardService.START))
        } catch (ex: Exception) {
            startupPending = false
            startupMessage = "Unable to start VPN foreground service: " + ex.javaClass.simpleName +
                ": " + (ex.message ?: "Unknown Android error")
        }
    }
    val vpnPermission = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val authorized = try { VpnService.prepare(context) == null } catch (_: Exception) { false }
        if (result.resultCode == Activity.RESULT_OK && authorized) {
            launchService()
        } else if (authorized) {
            // Some OEMs may not deliver the expected result code, but VpnService.prepare
            // is authoritative about whether authorization is now present.
            launchService()
        } else {
            startupPending = false
            startupMessage = "VPN permission was not granted. Open the DNS Guard tab and tap Start again."
        }
    }
    fun requestVpnPermission() {
        startupMessage = "Requesting Android VPN permission…"
        try {
            val permission = VpnService.prepare(context)
            if (permission != null) {
                startupPending = false
                vpnPermission.launch(permission)
            } else launchService()
        } catch (ex: Exception) {
            startupPending = false
            startupMessage = "Unable to request VPN approval: " +
                ex.javaClass.simpleName + ": " + (ex.message ?: "Unknown Android error")
        }
    }
    val notificationPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (!granted) {
            startupMessage = "Notifications are disabled. The ghost icon may not appear; continuing VPN setup…"
        }
        requestVpnPermission()
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
            forwarded = DnsGuardService.forwardedCount
            failures = DnsGuardService.resolverErrors
            vpnFailure = DnsGuardService.lastError
            vpnStatus = prefs.getString("vpn_status", DnsGuardService.lastDiagnostic)
                ?: DnsGuardService.lastDiagnostic
            if (guardRunning || vpnFailure.isNotBlank()) startupPending = false
            delay(1200L)
        }
    }

    LaunchedEffect(startupPending) {
        if (startupPending) {
            delay(18000L)
            if (startupPending && !DnsGuardService.running) {
                startupPending = false
                startupMessage = "VPN startup timed out. Check the status or error shown below."
            }
        }
    }

    LaunchedEffect(shared) {
        if (shared.isNotBlank()) {
            if (shared.trim().matches(Regex("""https?://\S+"""))) { link = shared; tab = 1 }
            else { tab = 6 }
        }
    }
    fun scan(text: String) {
        if (busy) return
        if (text.isBlank()) { error = "Paste a website link."; tab = 1; return }
        error = ""; result = null; busy = true; tab = 1
        scope.launch {
            val useRemote = endpoint.startsWith("https://") && !endpoint.endsWith(".invalid")
            val scanned = if (useRemote) {
                val remote = ScannerApi.scan(endpoint, text)
                if (remote.isSuccess) remote else OfflineScanner.link(text)
            } else OfflineScanner.link(text)
            scanned.fold(
                onSuccess = { item ->
                    result = item; history.add(0, item)
                    if (history.size > 20) history.removeAt(history.lastIndex)
                    runCatching { SecurityHistory.record(context, item) }.onSuccess { event ->
                        savedHistory.add(0, event)
                        if (savedHistory.size > 150) savedHistory.removeAt(savedHistory.lastIndex)
                    }
                },
                onFailure = { error = it.message ?: "Scanner unavailable. Check your backend." }
            )
            busy = false
        }
    }
    Scaffold(containerColor = ink, bottomBar = {
        Row(Modifier.fillMaxWidth().background(panel).navigationBarsPadding().horizontalScroll(rememberScrollState()).padding(10.dp), horizontalArrangement = Arrangement.spacedBy(9.dp)) {
            listOf(0 to "Home", 4 to "DNS Guard", 11 to "Webpage", 12 to "DNS Audit", 13 to "Phone Trace", 1 to "Links", 6 to "Scams", 5 to "APK Scan", 7 to "Device", 8 to "Breaches", 9 to "Account", 10 to "Premium", 2 to "History", 3 to "Settings").forEach { (i, name) ->
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
                    Text("Saved security checks: " + savedHistory.size, color = mint)
                    OutlinedButton(onClick = { tab = 11 }) { Text("INSPECT A WEBPAGE'S HTML") }
                    OutlinedButton(onClick = { tab = 12 }) { Text("AUDIT ENCRYPTED DNS EXPOSURE") }
                    OutlinedButton(onClick = { tab = 13 }) { Text("TRACE A SUSPICIOUS PHONE NUMBER") }
                    OutlinedButton(onClick = { tab = 6 }) { Text("INVESTIGATE A SCAM MESSAGE") }
                    OutlinedButton(onClick = { tab = 7 }) { Text("CHECK DEVICE SECURITY") }
                    OutlinedButton(onClick = { tab = 8 }) { Text("MONITOR VERIFIED EMAIL BREACHES") }
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
                    Section("Saved checks", "Encrypted on your device. Only hostname, verdict and timestamp are retained.")
                    if (savedHistory.isEmpty()) Note("No checks saved yet.", muted)
                    savedHistory.forEach { event ->
                        Surface(color = panel, shape = RoundedCornerShape(14.dp), modifier = Modifier.fillMaxWidth()) {
                            Column(Modifier.padding(14.dp)) {
                                Text(event.host, color = Color.White)
                                Text(event.verdict.uppercase(), color = muted, fontSize = 12.sp)
                                Text(java.text.DateFormat.getDateTimeInstance().format(java.util.Date(event.whenEpochMillis)),
                                    color = muted, fontSize = 12.sp)
                            }
                        }
                    }
                    OutlinedButton(onClick = {
                        history.clear()
                        savedHistory.clear()
                        SecurityHistory.clear(context)
                    }) { Text("DELETE MY SCAN HISTORY") }
                    Note("Full URLs, query strings, scam text and APK files aren't saved in this history.", muted)
                }

                4 -> {
                    Section("DNS Guard", "Optional background blocking of domains on your blocklist and configured GhostForge feed.")
                    Surface(color = panel, shape = RoundedCornerShape(16.dp)) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            Text(if (guardRunning) "ACTIVE • " + blocks + " blocked • " + forwarded + " forwarded"
                                else "NOT RUNNING",
                                color = if (guardRunning) mint else amber, fontWeight = FontWeight.Bold)
                            Text("This Android VPN handles only IPv4 UDP DNS packets. Ordinary DNS " +
                                "requests are forwarded securely to Cloudflare Families. Other apps' DNS-over-HTTPS/TLS " +
                                "requests can bypass this filter. The separate opt-in Webpage Inspector checks " +
                                "public HTML, not other apps' encrypted traffic. Android allows one VPN at a time.",
                                color = muted, fontSize = 13.sp)
                            DnsGuardDiagnostics.privateDnsWarning(context)?.let { Note(it, amber) }
                            OutlinedButton(onClick = { tab = 12 }, modifier = Modifier.fillMaxWidth()) {
                                Text("AUDIT ENCRYPTED DNS BYPASS")
                            }
                            Text("VPN status: " + vpnStatus, color = muted, fontSize = 13.sp)
                            if (failures > 0) Text("Upstream resolver errors: " + failures, color = amber, fontSize = 12.sp)
                            OutlinedButton(onClick = {
                                resolverCheck = ""
                                checkingResolver = true
                                scope.launch {
                                    resolverCheck = DnsGuardDiagnostics.checkConnection()
                                    checkingResolver = false
                                }
                            }, enabled = !checkingResolver, modifier = Modifier.fillMaxWidth()) {
                                Text("CHECK ENCRYPTED DNS CONNECTION")
                            }
                            if (checkingResolver) LinearProgressIndicator(Modifier.fillMaxWidth())
                            if (resolverCheck.isNotBlank()) Note(resolverCheck, muted)
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Checkbox(checked = consent, onCheckedChange = { consent = it })
                                Text("I understand and consent to the VPN and Cloudflare DNS handling.", color = Color.White, fontSize = 12.sp)
                            }
                            if (!guardRunning) Button(onClick = {
                                startupMessage = "Start button tapped."
                                if (Build.VERSION.SDK_INT >= 33 &&
                                    ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) !=
                                    PackageManager.PERMISSION_GRANTED) {
                                    startupMessage = "Allow notifications to display the ghost in the status bar."
                                    notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
                                } else {
                                    requestVpnPermission()
                                }
                            }, enabled = consent && !startupPending, modifier = Modifier.fillMaxWidth()) {
                                Text(if (startupPending) "STARTING…" else "START DNS GUARD")
                            }
                            else OutlinedButton(onClick = {
                                context.startService(Intent(context, DnsGuardService::class.java).setAction(DnsGuardService.STOP))
                            }, modifier = Modifier.fillMaxWidth()) { Text("STOP DNS GUARD") }
                            if (startupPending) LinearProgressIndicator(Modifier.fillMaxWidth())
                            if (startupMessage.isNotBlank()) Note(startupMessage, muted)
                            if (vpnFailure.isNotBlank()) Note("VPN error: " + vpnFailure, danger)
                            Text("If no ghost appears: Android Settings → Apps → GhostForge → Notifications → Allow. " +
                                "Also confirm GhostForge is listed under Settings → Connections → More connection settings → VPN.",
                                color = muted, fontSize = 12.sp)
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
                    Note("If VPN shows connected but websites stop loading, turn DNS Guard off immediately. Only IPv4 UDP DNS is intercepted; Android Private DNS, third-party encrypted DNS, IPv6 and DNS-over-TCP can bypass this beta. Test on Wi-Fi and mobile data before relying on it.", amber)
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
                6 -> ScamScreen(endpoint, shared)
                7 -> DeviceScreen()
                8 -> BreachScreen(endpoint)
                9 -> AccountScreen(endpoint, onVerifyEmail = { tab = 8 })
                10 -> PremiumScreen(endpoint, onVerifyEmail = { tab = 8 })
                11 -> WebpageInspectorScreen(initialUrl = link)
                12 -> EncryptedDnsAuditScreen()
                13 -> PhoneTraceScreen()
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
                    Note("Version 0.6.0 • AI and breach APIs require separately configured credentials. DNS filtering and APK inspection are experimental. Billing and family features aren't active.", amber)
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
