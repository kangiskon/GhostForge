package com.ghostforge.app

import android.app.Activity
import android.content.Context
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.android.billingclient.api.*
import kotlinx.coroutines.launch
import org.json.JSONObject

/**
 * Real Google Play subscription UI, intentionally disabled until the operator
 * configures Play products and server-side token verification.
 * Local purchase state NEVER unlocks premium on its own.
 */
@Composable
fun PremiumScreen(endpoint: String, onVerifyEmail: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val token = VerifiedSession.get(ctx)
    val emerald = Color(0xFF39E5CB)
    val muted = Color(0xFF9BB3C6)
    val warning = Color(0xFFFFCA75)
    var status by remember { mutableStateOf("Checking availability…") }
    var plan by remember { mutableStateOf("Free") }
    var enabled by remember { mutableStateOf(false) }
    var supportedIds by remember { mutableStateOf<List<String>>(emptyList()) }
    val products = remember { mutableStateListOf<ProductDetails>() }
    var client by remember { mutableStateOf<BillingClient?>(null) }
    var busy by remember { mutableStateOf(false) }

    fun refreshStatus() {
        val account = token ?: return
        scope.launch {
            AccountApi.call(endpoint, "/api/v1/billing/status", account).fold(
                onSuccess = { result ->
                    plan = result.optString("plan","free")
                    status = "Server status: " + result.optString("status","unavailable")
                },
                onFailure = { status = it.message ?: "Subscription status unavailable." }
            )
        }
    }
    fun verifyPurchase(purchase: Purchase) {
        if (purchase.purchaseState == Purchase.PurchaseState.PENDING) {
            status = "Purchase pending. No premium access is active."
            return
        }
        if (purchase.purchaseState != Purchase.PurchaseState.PURCHASED) return
        val account = token
        if (account == null) {
            status = "Verify your email to connect this purchase to your account."
            return
        }
        busy = true
        scope.launch {
            val payload = JSONObject().put("token",purchase.purchaseToken)
            AccountApi.call(endpoint, "/api/v1/billing/verify", account, "POST", payload).fold(
                onSuccess = {
                    plan = it.optString("plan", "free")
                    status = "Google Play purchase verified by your backend."
                    if (!purchase.isAcknowledged) {
                        val request = AcknowledgePurchaseParams.newBuilder()
                            .setPurchaseToken(purchase.purchaseToken).build()
                        client?.acknowledgePurchase(request) { result ->
                            if (result.responseCode != BillingClient.BillingResponseCode.OK) {
                                status = "Purchase verified, but Play acknowledgement needs retry."
                            }
                        }
                    }
                },
                onFailure = {
                    status = "No access granted: " + (it.message ?: "Server verification failed.")
                }
            )
            busy = false
        }
    }
    fun restore() {
        val c = client ?: return
        status = "Checking Google Play purchases…"
        c.queryPurchasesAsync(QueryPurchasesParams.newBuilder()
            .setProductType(BillingClient.ProductType.SUBS).build()) { response, purchases ->
            if (response.responseCode != BillingClient.BillingResponseCode.OK) {
                status = "Google Play restoration unavailable: " + response.debugMessage
            } else if (purchases.isEmpty()) {
                status = "No current Google Play subscriptions found."
            } else {
                purchases.forEach { verifyPurchase(it) }
            }
        }
    }

    LaunchedEffect(endpoint, token) {
        if (token != null) {
            refreshStatus()
            AccountApi.call(endpoint,"/api/v1/billing/config",token).fold(
                onSuccess = {
                    enabled = it.optBoolean("enabled", false)
                    val ids = it.optJSONArray("product_ids")
                    supportedIds = if (ids == null) emptyList()
                    else (0 until ids.length()).map { index -> ids.optString(index) }
                        .filter { id -> id.isNotBlank() }
                    if (!enabled) status = "Subscriptions aren't enabled on this server yet."
                },
                onFailure = { status = it.message ?: "Cannot load subscription configuration." }
            )
        } else status = "Verify your email first."
    }

    DisposableEffect(enabled, supportedIds, token) {
        if (!enabled || supportedIds.isEmpty() || token == null) {
            onDispose { }
        } else {
            val listener = PurchasesUpdatedListener { result, purchases ->
                when (result.responseCode) {
                    BillingClient.BillingResponseCode.OK -> purchases?.forEach { verifyPurchase(it) }
                    BillingClient.BillingResponseCode.USER_CANCELED -> status = "Purchase canceled."
                    else -> status = "Google Play: " + result.debugMessage
                }
            }
            val billing = BillingClient.newBuilder(ctx)
                .setListener(listener)
                .enablePendingPurchases(
                    PendingPurchasesParams.newBuilder().enableOneTimeProducts().build()
                ).build()
            client = billing
            billing.startConnection(object: BillingClientStateListener {
                override fun onBillingSetupFinished(result: BillingResult) {
                    if (result.responseCode != BillingClient.BillingResponseCode.OK) {
                        status = "Google Play Billing unavailable: " + result.debugMessage
                        return
                    }
                    val params = QueryProductDetailsParams.newBuilder()
                        .setProductList(supportedIds.map { id ->
                            QueryProductDetailsParams.Product.newBuilder()
                                .setProductId(id)
                                .setProductType(BillingClient.ProductType.SUBS).build()
                        }).build()
                    billing.queryProductDetailsAsync(params) { response, detail ->
                        if (response.responseCode == BillingClient.BillingResponseCode.OK) {
                            products.clear()
                            products.addAll(detail.productDetailsList)
                            if (products.isEmpty())
                                status = "No eligible Google Play subscription products were found. Verify Play Console setup and closed testing."
                        } else status = "Cannot query Play products: " + response.debugMessage
                    }
                }
                override fun onBillingServiceDisconnected() {
                    status = "Google Play Billing disconnected; reopen the Premium screen to retry."
                }
            })
            onDispose {
                products.clear()
                billing.endConnection()
                client = null
            }
        }
    }

    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Text("GhostForge Premium", style = MaterialTheme.typography.headlineSmall)
        Text("Security subscriptions are verified by Google Play and your own server.", color = muted)
        Text("Current plan: " + plan, color = emerald)
        Text(status, color = warning)
        if (token == null) {
            Button(onClick = onVerifyEmail) { Text("VERIFY EMAIL / SIGN IN") }
        } else {
            if (enabled) {
                products.forEach { product ->
                    val offer = product.subscriptionOfferDetails?.firstOrNull()
                    val price = offer?.pricingPhases?.pricingPhaseList?.firstOrNull()?.formattedPrice
                        ?: "See price in Google Play"
                    Surface(color = MaterialTheme.colorScheme.surface) {
                        Column(Modifier.fillMaxWidth().padding(16.dp)) {
                            Text(product.title, color = Color.White)
                            Text(product.description, color = muted)
                            Text("Starting price: " + price, color = emerald)
                            Button(onClick = {
                                val activity = ctx as? Activity
                                if (activity == null || offer == null) {
                                    status = "A supported subscription offer is unavailable."
                                } else {
                                    val item = BillingFlowParams.ProductDetailsParams.newBuilder()
                                        .setProductDetails(product)
                                        .setOfferToken(offer.offerToken).build()
                                    val params = BillingFlowParams.newBuilder()
                                        .setProductDetailsParamsList(listOf(item)).build()
                                    val outcome = client?.launchBillingFlow(activity, params)
                                    if (outcome?.responseCode != BillingClient.BillingResponseCode.OK) {
                                        status = "Cannot open Google Play checkout: " +
                                            (outcome?.debugMessage ?: "Billing not connected.")
                                    }
                                }
                            }, enabled = !busy && offer != null) { Text("VIEW SUBSCRIPTION OFFER") }
                        }
                    }
                }
                OutlinedButton(onClick = { restore() }, enabled = !busy && client != null) {
                    Text("RESTORE PLAY PURCHASES")
                }
            }
            OutlinedButton(onClick = { refreshStatus() }) { Text("CHECK SERVER ENTITLEMENT") }
        }
        Text("The sideloaded debug APK normally cannot sell subscriptions. Google Play Console " +
            "products, a Play-distributed testing track, and server-side service-account verification " +
            "must be configured first. A completed checkout never enables paid access unless " +
            "the backend verifies its purchase token. To cancel, use Google Play Subscriptions.",
            color = muted)
    }
}
