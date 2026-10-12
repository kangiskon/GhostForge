package com.ghostforge.app

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONObject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Android Keystore AES-GCM encrypted local email verification session.
 * No HIBP key, OpenAI key or SMTP password is ever included in the APK.
 */
object VerifiedSession {
    private const val KEY = "ghostforge_email_token"
    private const val FILE = "ghostforge_secret"
    private fun secretKey(): java.security.Key {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        store.getKey(KEY, null)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(KeyGenParameterSpec.Builder(KEY,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256).build())
        return generator.generateKey()
    }
    fun save(context: Context, token: String, email: String) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey())
        val encrypted = cipher.doFinal(token.toByteArray(Charsets.UTF_8))
        context.getSharedPreferences(FILE, Context.MODE_PRIVATE).edit()
            .putString("token", Base64.encodeToString(cipher.iv + encrypted, Base64.NO_WRAP))
            .putString("email", email)
            .apply()
        context.getSharedPreferences("ghostforge_settings", Context.MODE_PRIVATE)
            .edit().remove("last_breach_list").apply()
    }
    fun get(context: Context): String? {
        return try {
        val encoded = context.getSharedPreferences(FILE, Context.MODE_PRIVATE).getString("token", null)
            ?: return null
        val bytes = Base64.decode(encoded, Base64.DEFAULT)
        if (bytes.size < 29) return null
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(128, bytes.copyOfRange(0, 12)))
        String(cipher.doFinal(bytes.copyOfRange(12, bytes.size)), Charsets.UTF_8)
        } catch (_: Exception) { null }
    }
    fun email(context: Context): String = context.getSharedPreferences(FILE, Context.MODE_PRIVATE)
        .getString("email", "").orEmpty()
    fun clear(context: Context) {
        context.getSharedPreferences(FILE, Context.MODE_PRIVATE).edit().clear().apply()
    }
}

object SecurityApi {
    private fun request(base: String, path: String, body: JSONObject?, token: String? = null): JSONObject {
        val root = base.trim().trimEnd('/')
        require(root.startsWith("https://") && !root.endsWith(".invalid")) {
            "Configure your trusted HTTPS server in Settings."
        }
        val conn = URL(root + path).openConnection() as HttpURLConnection
        try {
            conn.connectTimeout = 10000
            conn.readTimeout = if (path.contains("/scams/")) 26000 else 12000
            conn.instanceFollowRedirects = false
            conn.requestMethod = if (body == null) "GET" else "POST"
            conn.setRequestProperty("Accept", "application/json")
            if (token != null) conn.setRequestProperty("Authorization", "Bearer " + token)
            if (body != null) {
                conn.setRequestProperty("Content-Type", "application/json")
                conn.doOutput = true
                conn.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
            }
            val code = conn.responseCode
            val response = if (code in 200..299) conn.inputStream else conn.errorStream
            val content = response?.bufferedReader()?.use { it.readText() }.orEmpty()
            require(code in 200..299) { when (code) {
                400 -> "Invalid or expired verification code."
                401 -> "Email verification expired. Verify again."
                429 -> "Too many requests; try later."
                503 -> "This backend feature isn't configured yet."
                else -> "Server returned HTTP $code."
            } }
            return JSONObject(content)
        } finally { conn.disconnect() }
    }
    suspend fun analyze(base: String, content: String, ai: Boolean): Result<JSONObject> =
        withContext(Dispatchers.IO) {
            runCatching {
                require(content.length in 3..5000) { "Enter 3 to 5,000 characters." }
                request(base, "/api/v1/scams/analyze", JSONObject()
                    .put("text", content).put("use_ai", ai))
            }
        }
    suspend fun sendCode(base: String, email: String): Result<JSONObject> =
        withContext(Dispatchers.IO) { runCatching {
            request(base, "/api/v1/breach/request-code", JSONObject().put("email", email))
        } }
    suspend fun verify(base: String, email: String, code: String): Result<JSONObject> =
        withContext(Dispatchers.IO) { runCatching {
            request(base, "/api/v1/breach/verify", JSONObject().put("email", email).put("code", code))
        } }
    suspend fun breaches(base: String, token: String): Result<JSONObject> =
        withContext(Dispatchers.IO) { runCatching {
            request(base, "/api/v1/breach/check", null, token)
        } }
    suspend fun delete(base: String, token: String): Result<JSONObject> =
        withContext(Dispatchers.IO) { runCatching {
            request(base, "/api/v1/breach/delete", JSONObject(), token)
        } }
}
