package com.ghostforge.app

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
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
        Row(Modifier.fillMaxWidth().background(panel).navigationBarsPadding().padding(10.dp), horizontalArrangement = Arrangement.SpaceEvenly) {
            listOf("Home", "Scanner", "History", "Settings").forEachIndexed { i, name ->
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
                            Text("Manual scanning only. No VPN or background protection is active.", color = muted)
                            Button(onClick = { tab = 1 }, modifier = Modifier.fillMaxWidth()) { Text("SCAN A SUSPICIOUS LINK") }
                        }
                    }
                    Section("Your security toolkit", "Analyze links shared from other apps or encoded in QR codes.")
                    Text("Links scanned this session: " + history.size, color = mint)
                    Text("This prototype is not an antivirus or a replacement for Google Play Protect.", color = amber)
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
                    Note("Version 0.1.0 • No background web monitoring, malware scanning, account system, or paid subscriptions yet.", amber)
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
