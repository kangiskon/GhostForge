package com.ghostforge.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

/**
 * Android Keystore backed, local-only Privacy Shield case vault.
 * Stores public SITE + DATA CATEGORY + STATUS + TIMESTAMPS, never the actual
 * person's email, phone, address, name, listing URL, or removal letter.
 * No account/cloud syncing or analytics.
 */
object PrivacyCaseVault {
    private const val FILE = "ghostforge_privacy_shield_v1"
    private const val KEY = "ghostforge_privacy_cases_aes_v1"
    private const val LIMIT = 100

    private fun key(): java.security.Key {
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

    /**
     * Return an error if the ciphertext cannot be decrypted.
     * Never quietly turn corruption into an empty list and overwrite the vault.
     */
    fun load(ctx: Context): Result<List<PrivacyCase>> = runCatching {
        val source = ctx.getSharedPreferences(FILE, Context.MODE_PRIVATE)
            .getString("items", null) ?: return@runCatching emptyList()
        val bytes = Base64.decode(source, Base64.NO_WRAP)
        require(bytes.size >= 29) { "Encrypted privacy vault is invalid." }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, bytes.copyOfRange(0, 12)))
        val plain = cipher.doFinal(bytes.copyOfRange(12, bytes.size))
        val arr = JSONArray(String(plain, Charsets.UTF_8))
        require(arr.length() <= LIMIT) { "Privacy vault exceeds the maximum supported records." }
        (0 until arr.length()).map { index ->
            val entry = arr.getJSONObject(index)
            val record = PrivacyCase(
                id = entry.getString("id"),
                site = entry.getString("site"),
                dataType = entry.getString("kind"),
                status = entry.getString("status"),
                createdAt = entry.getLong("created"),
                updatedAt = entry.getLong("updated")
            )
            require(record.status in PrivacyShieldPlanner.statuses &&
                record.dataType in PrivacyShieldPlanner.types)
            record
        }
    }

    private fun write(ctx: Context, records: List<PrivacyCase>) {
        require(records.size <= LIMIT) { "Maximum of $LIMIT cases reached. Delete an older case first." }
        val arr = JSONArray()
        for (item in records) {
            arr.put(JSONObject()
                .put("id", item.id)
                .put("site", item.site)
                .put("kind", item.dataType)
                .put("status", item.status)
                .put("created", item.createdAt)
                .put("updated", item.updatedAt))
        }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val encrypted = cipher.iv + cipher.doFinal(arr.toString().toByteArray(Charsets.UTF_8))
        val encoded = Base64.encodeToString(encrypted, Base64.NO_WRAP)
        check(ctx.getSharedPreferences(FILE, Context.MODE_PRIVATE).edit()
            .putString("items", encoded).commit()) { "Could not persist encrypted privacy cases." }
    }

    fun add(ctx: Context, item: PrivacyCase): Result<List<PrivacyCase>> = runCatching {
        val existing = load(ctx).getOrThrow()
        require(existing.none { it.id == item.id }) { "Duplicate privacy case." }
        val next = listOf(item) + existing
        write(ctx, next)
        next
    }

    fun update(ctx: Context, id: String, status: String): Result<List<PrivacyCase>> = runCatching {
        val existing = load(ctx).getOrThrow()
        require(existing.any { it.id == id }) { "Privacy case not found." }
        val next = existing.map {
            if (it.id == id) PrivacyShieldPlanner.update(it, status, System.currentTimeMillis())
            else it
        }
        write(ctx, next)
        next
    }

    fun remove(ctx: Context, id: String): Result<List<PrivacyCase>> = runCatching {
        val next = load(ctx).getOrThrow().filterNot { it.id == id }
        write(ctx, next)
        next
    }

    fun deleteAll(ctx: Context) {
        ctx.getSharedPreferences(FILE, Context.MODE_PRIVATE).edit().clear().commit()
    }
}
