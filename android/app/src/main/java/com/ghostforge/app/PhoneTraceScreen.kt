package com.ghostforge.app

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import java.util.Locale

private val traceMint = Color(0xFF39E5CB)
private val traceMuted = Color(0xFF9BB3C6)
private val traceAmber = Color(0xFFFFCA75)

@Composable
fun PhoneTraceScreen(initialNumber: String = "") {
    val ctx = LocalContext.current
    var number by rememberSaveable(initialNumber) { mutableStateOf(initialNumber) }
    var country by rememberSaveable {
        mutableStateOf(Locale.getDefault().country.takeIf { it.length == 2 } ?: "CA")
    }
    var result by remember { mutableStateOf<PhoneTraceReport?>(null) }
    var error by remember { mutableStateOf("") }
    var publicSearchConsent by rememberSaveable { mutableStateOf(false) }

    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Text("Phone Number Trace", style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold)
        Text("Investigate a suspicious caller or text number using offline international " +
            "numbering-plan metadata. No contacts, call logs, SMS or location permissions.",
            color = traceMuted)
        OutlinedTextField(
            value = number, onValueChange = {
                number = it.take(40)
                result = null; error = ""; publicSearchConsent = false
            },
            label = { Text("Caller phone number") },
            placeholder = { Text("+1 416 555 0100") },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Phone),
            modifier = Modifier.fillMaxWidth(), singleLine = true
        )
        OutlinedTextField(
            value = country, onValueChange = {
                country = it.filter { c -> c.isLetter() }.take(2).uppercase(Locale.ROOT)
                result = null; error = ""; publicSearchConsent = false
            },
            label = { Text("Default country (two-letter code)") },
            supportingText = { Text("e.g., CA for Canada, US for USA, GB for United Kingdom. " +
                "Used only if the number lacks a + country code.") },
            modifier = Modifier.fillMaxWidth(), singleLine = true
        )
        Button(onClick = {
            PhoneTraceAnalyzer.inspect(number, country).fold(
                onSuccess = { result = it; error = "" },
                onFailure = { result = null; error = it.message ?: "Number analysis failed." }
            )
        }, enabled = number.isNotBlank() && country.length == 2,
            modifier = Modifier.fillMaxWidth()) {
            Text("TRACE NUMBER DETAILS")
        }
        if (error.isNotBlank()) {
            Text(error, color = traceAmber)
        }
        result?.let { report ->
            Surface(color = MaterialTheme.colorScheme.surface,
                border = BorderStroke(1.dp, traceMint.copy(alpha = 0.45f))) {
                Column(Modifier.fillMaxWidth().padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("OFFLINE NUMBER REPORT", color = traceMint, fontWeight = FontWeight.Bold)
                    Text(report.international, color = Color.White,
                        style = MaterialTheme.typography.titleLarge)
                    Text("Numbering region: " + report.numberingRegion, color = Color.White)
                    Text("Country calling code: " + report.countryCallingCode, color = traceMuted)
                    Text("Number type: " + report.category, color = traceMuted)
                    Text("Possible length: " + if (report.possible) "Yes" else "No", color = traceMuted)
                    Text("Valid numbering pattern: " + if (report.validPattern) "Yes" else "No",
                        color = traceMuted)
                    report.geographicPrefix?.let { prefix ->
                        Text("North American area prefix: " + prefix +
                            " (NOT the phone's current location)", color = traceMuted)
                    }
                    report.warnings.forEach { warning -> Text("• " + warning, color = traceAmber) }
                    HorizontalDivider()
                    Text(report.disclaimer, color = traceAmber)
                }
            }
            Row(Modifier.fillMaxWidth()) {
                Checkbox(checked = publicSearchConsent,
                    onCheckedChange = { publicSearchConsent = it })
                Text("I understand this opens a public search engine and sends the " +
                    "number in a search query. GhostForge won't upload it automatically.",
                    color = traceMuted, modifier = Modifier.padding(top = 8.dp))
            }
            OutlinedButton(onClick = {
                val query = "\"" + report.e164 + "\" scam spam caller reports"
                val uri = Uri.parse("https://www.google.com/search?q=" + Uri.encode(query))
                runCatching {
                    ctx.startActivity(Intent(Intent.ACTION_VIEW, uri))
                }.onFailure { error = "No browser was available for the public lookup." }
            }, enabled = publicSearchConsent, modifier = Modifier.fillMaxWidth()) {
                Text("SEARCH PUBLIC SCAM REPORTS")
            }
            Text("Public search results are unverified and can misidentify people. " +
                "Never treat a name or location from a search result as confirmed.",
                color = traceAmber)
        }
        Text("GhostForge cannot trace a person's live whereabouts, current phone carrier, " +
            "identity or actual caller solely from a phone number. Spoofed caller ID, " +
            "shared numbers and number portability limit all number lookups.",
            color = traceMuted)
    }
}
