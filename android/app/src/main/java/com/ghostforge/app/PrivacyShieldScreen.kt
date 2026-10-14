package com.ghostforge.app

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.util.UUID

private val shieldMint = Color(0xFF39E5CB)
private val shieldMuted = Color(0xFF9BB3C6)
private val shieldAmber = Color(0xFFFFCA75)

@Composable
fun PrivacyShieldScreen(endpoint: String, onVerifyEmail: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val cases = remember { mutableStateListOf<PrivacyCase>() }
    var vaultError by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("") }
    var searchValue by remember { mutableStateOf("") }
    var authorizeSearch by remember { mutableStateOf(false) }
    var searches by remember { mutableStateOf<List<PrivacySearch>>(emptyList()) }
    var breachReport by remember { mutableStateOf<JSONObject?>(null) }
    var breachLoading by remember { mutableStateOf(false) }
    var siteValue by remember { mutableStateOf("") }
    var selectedType by remember { mutableStateOf(PrivacyShieldPlanner.types.first()) }
    var categoryMenu by remember { mutableStateOf(false) }
    var recipientEmail by remember { mutableStateOf("") }
    var senderName by remember { mutableStateOf("") }
    var replyEmail by remember { mutableStateOf(VerifiedSession.email(context)) }
    var ownerConsent by remember { mutableStateOf(false) }
    var confirmRemoval by remember { mutableStateOf<String?>(null) }
    var confirmClear by remember { mutableStateOf(false) }

    fun refreshCases() {
        PrivacyCaseVault.load(context).fold(
            onSuccess = {
                cases.clear()
                cases.addAll(it)
                vaultError = ""
            },
            onFailure = {
                vaultError = "Encrypted case vault cannot be read. Existing entries were not overwritten. " +
                    (it.message ?: "Local encryption error.")
            }
        )
    }
    LaunchedEffect(Unit) { refreshCases() }

    fun applyCaseChange(value: Result<List<PrivacyCase>>, successMessage: String) {
        value.fold(
            onSuccess = {
                cases.clear()
                cases.addAll(it)
                message = successMessage
            },
            onFailure = { message = it.message ?: "Could not update the encrypted vault." }
        )
    }

    fun openBrowser(url: String) {
        runCatching {
            val uri = Uri.parse(url)
            require(uri.scheme.equals("https", true) && uri.host == "www.google.com") {
                "Only the search provider's HTTPS search page is allowed."
            }
            context.startActivity(Intent(Intent.ACTION_VIEW, uri)
                .addCategory(Intent.CATEGORY_BROWSABLE))
        }.onFailure {
            message = "Couldn't open the public search: " + (it.message ?: "No browser available.")
        }
    }

    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Text("Privacy Shield", style = MaterialTheme.typography.headlineSmall)
        Text("Find public exposure clues, check reported breaches of your verified email, " +
            "and prepare opt-out requests. Your information is never searched or shared without action.",
            color = shieldMuted)
        Surface(color = MaterialTheme.colorScheme.surface,
            border = BorderStroke(1.dp, shieldAmber.copy(alpha = 0.5f))) {
            Text("Dark-web monitoring is limited to licensed breach-intelligence sources. " +
                "GhostForge currently supports Have I Been Pwned when your server is configured. " +
                "It does not crawl hidden marketplaces, purchase stolen records or delete dark-web copies.",
                modifier = Modifier.fillMaxWidth().padding(14.dp), color = shieldAmber)
        }

        Text("1. VERIFIED EMAIL BREACH CHECK", color = shieldMint)
        val token = VerifiedSession.get(context)
        if (token == null) {
            Text("Verify your email in the Breaches tab to check known breach reports.",
                color = shieldMuted)
            Button(onClick = onVerifyEmail) { Text("VERIFY EMAIL") }
        } else {
            val storedEmail = VerifiedSession.email(context)
            Text("Account email: " + storedEmail, color = shieldMuted)
            Button(onClick = {
                breachLoading = true
                message = ""
                scope.launch {
                    SecurityApi.breaches(endpoint, token).fold(
                        onSuccess = { breachReport = it },
                        onFailure = { message = it.message ?: "Breach lookup failed." }
                    )
                    breachLoading = false
                }
            }, enabled = !breachLoading) {
                Text(if (breachLoading) "CHECKING…" else "CHECK KNOWN BREACH REPORTS")
            }
            if (breachLoading) LinearProgressIndicator(Modifier.fillMaxWidth())
            breachReport?.let { report ->
                val checked = report.optBoolean("checked", false)
                val status = report.optString("status", "unavailable")
                Text(if (checked) "Provider responded: " + status
                    else "Not checked. Provider status: " + status, color = shieldAmber)
                val arr = report.optJSONArray("breaches")
                if (checked && arr != null && arr.length() > 0) {
                    Text("Reported breach names (not necessarily dark-web listings):", color = shieldMuted)
                    for (i in 0 until minOf(arr.length(), 25)) {
                        Text("• " + arr.optString(i), color = shieldAmber)
                    }
                }
                if (checked && (arr == null || arr.length() == 0)) {
                    Text("No entries were found in this checked provider. That doesn't prove " +
                        "your information is absent elsewhere.", color = shieldMuted)
                }
            }
            Text("Recurring breach notifications can be enabled separately in the Breaches tab. " +
                "Their timing is approximate and requires server credentials.",
                color = shieldMuted)
        }
        HorizontalDivider()

        Text("2. PUBLIC WEB EXPOSURE SEARCH", color = shieldMint)
        Text("Enter your own name, phone number or email to generate public search links. " +
            "No searches run until you choose a result category. Never use this for someone else's data.",
            color = shieldMuted)
        OutlinedTextField(value = searchValue, onValueChange = {
            searchValue = it.take(160)
            searches = emptyList()
            authorizeSearch = false
        }, label = { Text("My information to check") },
            modifier = Modifier.fillMaxWidth(), maxLines = 3)
        Row(Modifier.fillMaxWidth()) {
            Checkbox(checked = authorizeSearch, onCheckedChange = { authorizeSearch = it })
            Text("This is my information or I am authorized to manage it. " +
                "Opening a search sends my search terms to Google.",
                modifier = Modifier.padding(top = 8.dp), color = shieldMuted)
        }
        Button(onClick = {
            runCatching { PrivacyShieldPlanner.searches(searchValue) }.fold(
                onSuccess = { searches = it; message = "Public searches prepared locally. Select one to open." },
                onFailure = { message = it.message ?: "Invalid search text." }
            )
        }, enabled = authorizeSearch && searchValue.trim().length >= 3) {
            Text("PREPARE PUBLIC WEB SEARCHES")
        }
        searches.forEach { search ->
            OutlinedButton(onClick = {
                if (authorizeSearch) openBrowser(search.url)
            }, enabled = authorizeSearch, modifier = Modifier.fillMaxWidth()) {
                Text(search.title.uppercase())
            }
            Text(search.description, color = shieldMuted)
        }
        Text("Public search results may be stale, false or incomplete. An indexed result is " +
            "not proof of exposure, and no results doesn't prove you aren't exposed.",
            color = shieldAmber)
        HorizontalDivider()

        Text("3. TRACK PERSONAL DATA REMOVAL", color = shieldMint)
        Text("Add a public website where you found your information. GhostForge saves " +
            "only the website domain, exposure category and request status in an encrypted " +
            "on-device vault—not the actual personal information.",
            color = shieldMuted)
        OutlinedTextField(value = siteValue, onValueChange = { siteValue = it.take(250) },
            label = { Text("Listing website domain or HTTPS URL") },
            placeholder = { Text("example.com") }, modifier = Modifier.fillMaxWidth())
        Box {
            OutlinedButton(onClick = { categoryMenu = true }) {
                Text("Information type: " + selectedType)
            }
            DropdownMenu(expanded = categoryMenu, onDismissRequest = { categoryMenu = false }) {
                PrivacyShieldPlanner.types.forEach { type ->
                    DropdownMenuItem(text = { Text(type) }, onClick = {
                        selectedType = type
                        categoryMenu = false
                    })
                }
            }
        }
        Button(onClick = {
            runCatching {
                PrivacyShieldPlanner.case(siteValue, selectedType,
                    UUID.randomUUID().toString(), System.currentTimeMillis())
            }.fold(
                onSuccess = { item ->
                    applyCaseChange(PrivacyCaseVault.add(context, item),
                        "Listing added to encrypted case tracker.")
                    siteValue = ""
                },
                onFailure = { message = it.message ?: "Website address not accepted." }
            )
        }, enabled = siteValue.isNotBlank() && vaultError.isBlank()) {
            Text("ADD EXPOSURE CASE")
        }
        if (vaultError.isNotBlank()) Text(vaultError, color = shieldAmber)
        Text("Tracked: " + cases.size + " • Requests sent: " +
            cases.count { it.status in listOf(PrivacyShieldPlanner.SENT, PrivacyShieldPlanner.RESPONSE) } +
            " • Verified removed: " + cases.count { it.status == PrivacyShieldPlanner.REMOVED },
            color = shieldMuted)

        Text("4. PREPARE YOUR OWN REMOVAL REQUEST", color = shieldMint)
        OutlinedTextField(value = senderName, onValueChange = { senderName = it.take(120) },
            label = { Text("Your name (used only in the draft)") },
            modifier = Modifier.fillMaxWidth(), singleLine = true)
        OutlinedTextField(value = replyEmail, onValueChange = { replyEmail = it.take(254) },
            label = { Text("Your reply email (used only in the draft)") },
            modifier = Modifier.fillMaxWidth(), singleLine = true)
        OutlinedTextField(value = recipientEmail, onValueChange = { recipientEmail = it.take(254) },
            label = { Text("Official privacy/opt-out contact email of listing website") },
            modifier = Modifier.fillMaxWidth(), singleLine = true)
        Row(Modifier.fillMaxWidth()) {
            Checkbox(checked = ownerConsent, onCheckedChange = { ownerConsent = it })
            Text("I control the information in my request. I will confirm the website's " +
                "official privacy contact and review the draft before sending it.",
                color = shieldMuted, modifier = Modifier.padding(top = 8.dp))
        }

        cases.forEach { item ->
            Surface(color = MaterialTheme.colorScheme.surface,
                border = BorderStroke(1.dp, shieldMint.copy(alpha = 0.25f))) {
                Column(Modifier.fillMaxWidth().padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(7.dp)) {
                    Text(item.site, color = Color.White,
                        style = MaterialTheme.typography.titleMedium)
                    Text(item.dataType + " • " + item.status.replace('_', ' ').uppercase(),
                        color = shieldMuted)
                    Text("Updated: " +
                        java.text.DateFormat.getDateInstance().format(java.util.Date(item.updatedAt)),
                        color = shieldMuted)
                    OutlinedButton(onClick = {
                        if (!ownerConsent) {
                            message = "Confirm ownership and review consent before preparing a request."
                        } else {
                            runCatching {
                                require(recipientEmail.trim().matches(
                                    Regex("""^[^@\s]+@[^@\s]+\.[^@\s]+$"""))) {
                                    "Enter the verified site's official privacy email address."
                                }
                                val body = PrivacyShieldPlanner.draft(item, senderName, replyEmail)
                                val recipient = recipientEmail.trim()
                                val uri = Uri.parse("mailto:" + Uri.encode(recipient) +
                                    "?subject=" + Uri.encode(PrivacyShieldPlanner.subject(item)) +
                                    "&body=" + Uri.encode(body))
                                context.startActivity(Intent(Intent.ACTION_SENDTO, uri))
                            }.onFailure {
                                message = it.message ?: "Could not open your email app."
                            }
                        }
                    }, enabled = ownerConsent && vaultError.isBlank()) {
                        Text("OPEN EDITABLE REMOVAL EMAIL")
                    }
                    Text("Only opening your email app: this does NOT send a request or " +
                        "change the case status.", color = shieldMuted)
                    if (item.status != PrivacyShieldPlanner.SENT) {
                        TextButton(onClick = {
                            applyCaseChange(
                                PrivacyCaseVault.update(context, item.id, PrivacyShieldPlanner.SENT),
                                "Marked sent on your confirmation. GhostForge has not independently verified delivery.")
                        }) { Text("I SENT THE REQUEST") }
                    }
                    if (item.status == PrivacyShieldPlanner.SENT) {
                        TextButton(onClick = {
                            applyCaseChange(
                                PrivacyCaseVault.update(context, item.id, PrivacyShieldPlanner.RESPONSE),
                                "Marked acknowledged based on your confirmation.")
                        }) { Text("I RECEIVED A RESPONSE") }
                    }
                    if (item.status == PrivacyShieldPlanner.SENT ||
                        item.status == PrivacyShieldPlanner.RESPONSE) {
                        if (confirmRemoval == item.id) {
                            Text("Only mark removed if you independently verified " +
                                "the listing is no longer visible.", color = shieldAmber)
                            Button(onClick = {
                                applyCaseChange(
                                    PrivacyCaseVault.update(context, item.id, PrivacyShieldPlanner.REMOVED),
                                    "Marked verified removed based on your explicit confirmation.")
                                confirmRemoval = null
                            }) { Text("CONFIRM I'VE VERIFIED REMOVAL") }
                        } else {
                            TextButton(onClick = { confirmRemoval = item.id }) {
                                Text("VERIFY REMOVAL")
                            }
                        }
                    }
                    TextButton(onClick = {
                        applyCaseChange(PrivacyCaseVault.remove(context, item.id),
                            "Case deleted from this device.")
                    }) { Text("DELETE THIS CASE") }
                }
            }
        }
        Row(Modifier.fillMaxWidth()) {
            Checkbox(checked = confirmClear, onCheckedChange = { confirmClear = it })
            Text("I want to permanently erase all encrypted removal cases from this device.",
                color = shieldAmber, modifier = Modifier.padding(top = 8.dp))
        }
        OutlinedButton(onClick = {
            PrivacyCaseVault.deleteAll(context)
            confirmClear = false
            refreshCases()
            message = "Local privacy case vault cleared."
        }, enabled = confirmClear && vaultError.isBlank()) {
            Text("DELETE ALL PRIVACY CASES")
        }

        if (message.isNotBlank()) Text(message, color = shieldAmber)
        PrivacyAutomationPanel(endpoint)

        Text("IMPORTANT: GhostForge doesn't automatically erase information from " +
            "other websites or uncooperative dark-web sources. Removal requests require " +
            "the site owner's cooperation; each submission requires your approval. " +
            "Don't send IDs, passwords or verification codes through an unverified contact.",
            color = shieldAmber)
    }
}
