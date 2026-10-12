package com.ghostforge.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyStore
import java.time.Instant
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

data class ScanEvent(val host: String, val verdict: String, val whenEpochMillis: Long)

/**
 * Encrypted local history with minimal personal data.
 *
 * The full URL, query string, submitted scam text and APK bytes are NEVER stored.
 * A compromised hostname may still be sensitive, so encrypt at rest and allow deletion.
 */
object SecurityHistory {
    private const val FILE = "ghostforge_encrypted_history"
    private const val ALIAS = "ghostforge_scan_history_aes_v1"
    private fun key(): java.security.Key {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        ks.getKey(ALIAS, null)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(KeyGenParameterSpec.Builder(ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256).build())
        return gen.generateKey()
    }
    fun read(context: Context): List<ScanEvent> {
        return try {
            val value = context.getSharedPreferences(FILE, Context.MODE_PRIVATE)
                .getString("records", null) ?: return emptyList()
            val encoded = Base64.decode(value, Base64.NO_WRAP)
            if (encoded.size < 29) return emptyList()
            val decrypt = Cipher.getInstance("AES/GCM/NoPadding")
            decrypt.init(Cipher.DECRYPT_MODE,key(),
                GCMParameterSpec(128,encoded.copyOfRange(0,12)))
            val plain = decrypt.doFinal(encoded.copyOfRange(12,encoded.size))
            val arr = JSONArray(String(plain,Charsets.UTF_8))
            (0 until minOf(150, arr.length())).mapNotNull { i ->
                val item=arr.optJSONObject(i) ?: return@mapNotNull null
                ScanEvent(item.optString("host"),item.optString("verdict"),
                    item.optLong("at"))
            }
        } catch (_: Exception) {
            emptyList()
        }
    }
    private fun save(context: Context, records: List<ScanEvent>) {
        val data = JSONArray()
        for (item in records.take(150)) {
            data.put(JSONObject().put("host",item.host).put("verdict",item.verdict)
                .put("at",item.whenEpochMillis))
        }
        val encrypt = Cipher.getInstance("AES/GCM/NoPadding")
        encrypt.init(Cipher.ENCRYPT_MODE,key())
        val cipherText = encrypt.doFinal(data.toString().toByteArray(Charsets.UTF_8))
        val encoded = Base64.encodeToString(encrypt.iv + cipherText,Base64.NO_WRAP)
        context.getSharedPreferences(FILE,Context.MODE_PRIVATE).edit()
            .putString("records",encoded).apply()
    }
    fun record(context: Context, finding: ScanFinding): ScanEvent {
        val item = ScanEvent(finding.host.take(253),finding.verdict.take(40),
            System.currentTimeMillis())
        save(context, listOf(item) + read(context))
        return item
    }
    fun clear(context: Context) {
        context.getSharedPreferences(FILE,Context.MODE_PRIVATE).edit().clear().apply()
    }
}
