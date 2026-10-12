package com.ghostforge.app

import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.zip.ZipFile

data class ApkReport(
    val filename: String,
    val sha256: String,
    val packageId: String,
    val version: String,
    val risks: List<String>,
    val reputation: String,
    val details: String
)

/**
 * Reads only a file the user chooses in Android's document picker.
 * APK content stays on device. Only its SHA-256 is optionally sent to the HTTPS
 * GhostForge backend. Risky permissions are indicators, NOT proof of malware.
 */
object ApkInspector {
    suspend fun inspect(context: Context, uri: Uri, endpoint: String): Result<ApkReport> =
        withContext(Dispatchers.IO) {
            runCatching {
                val max = 120L * 1024 * 1024
                val tmp = File.createTempFile("ghostforge-", ".apk", context.cacheDir)
                val digest = MessageDigest.getInstance("SHA-256")
                try {
                    val input = context.contentResolver.openInputStream(uri)
                        ?: error("Can't read the selected file.")
                    var size = 0L
                    input.use { source ->
                        FileOutputStream(tmp).use { dest ->
                            val buffer = ByteArray(64 * 1024)
                            while (true) {
                                val n = source.read(buffer)
                                if (n < 0) break
                                size += n
                                require(size <= max) { "APK exceeds the 120 MB scan limit." }
                                digest.update(buffer, 0, n)
                                dest.write(buffer, 0, n)
                            }
                        }
                    }
                    require(size > 0) { "File is empty." }
                    var dex = 0
                    var manifest = false
                    ZipFile(tmp).use { zip ->
                        val entries = zip.entries()
                        var count = 0
                        while (entries.hasMoreElements()) {
                            val entry = entries.nextElement()
                            count++
                            require(count < 25000) { "APK contains too many archive entries." }
                            if (entry.name == "AndroidManifest.xml") manifest = true
                            if (entry.name == "classes.dex" ||
                                Regex("""classes\d+\.dex""").matches(entry.name)) dex++
                        }
                    }
                    require(manifest && dex > 0) { "Selected file is not a normal Android APK." }
                    @Suppress("DEPRECATION")
                    val info = if (Build.VERSION.SDK_INT >= 33) {
                        context.packageManager.getPackageArchiveInfo(
                            tmp.absolutePath,
                            PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong())
                        )
                    } else context.packageManager.getPackageArchiveInfo(tmp.absolutePath, PackageManager.GET_PERMISSIONS)
                    val permissions = info?.requestedPermissions?.toSet().orEmpty()
                    val risks = mutableListOf<String>()
                    fun flagged(permission: String, message: String) {
                        if (permissions.contains(permission)) risks.add(message)
                    }
                    flagged("android.permission.REQUEST_INSTALL_PACKAGES", "Can request installation of other APKs.")
                    flagged("android.permission.SYSTEM_ALERT_WINDOW", "Can request overlays over other apps.")
                    flagged("android.permission.MANAGE_EXTERNAL_STORAGE", "May request broad access to files.")
                    flagged("android.permission.QUERY_ALL_PACKAGES", "Requests broad visibility into installed apps.")
                    flagged("android.permission.READ_SMS", "Requests access to SMS messages.")
                    flagged("android.permission.RECEIVE_SMS", "Can receive SMS messages.")
                    flagged("android.permission.BIND_ACCESSIBILITY_SERVICE", "Declares accessibility-related access (verify actual service declaration).")
                    if (permissions.contains("android.permission.REQUEST_INSTALL_PACKAGES") &&
                        permissions.contains("android.permission.READ_SMS")) {
                        risks.add("High-risk combination: APK installation plus SMS access.")
                    }
                    if (info == null) risks.add("Could not parse the package manifest.")
                    if (dex > 8) risks.add("Many DEX files ($dex); manually review an unusually large app.")
                    val hash = digest.digest().joinToString("") { "%02x".format(it) }
                    // Always report unknown unless a configured feed confirms a hash match.
                    val reputation = ApkReputation.lookup(endpoint, hash)
                    ApkReport(
                        filename = uri.lastPathSegment?.substringAfterLast('/') ?: "Selected APK",
                        sha256 = hash,
                        packageId = info?.packageName ?: "Unknown",
                        version = info?.versionName ?: "Unknown",
                        risks = risks,
                        reputation = reputation,
                        details = if (reputation == "known_malicious") {
                            "The hash is present in the operator's known-malware SHA-256 list."
                        } else {
                            "No conclusive malware scan was performed. Permission warnings alone do not identify malware."
                        }
                    )
                } finally {
                    tmp.delete()
                }
            }
        }
}

object ApkReputation {
    fun lookup(endpoint: String, hash: String): String {
        val base = endpoint.trimEnd('/')
        if (!base.startsWith("https://") || base.endsWith(".invalid")) return "unverified"
        return try {
            val conn = java.net.URL("$base/api/v1/apk/hash").openConnection() as java.net.HttpURLConnection
            conn.requestMethod = "POST"
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            conn.instanceFollowRedirects = false
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/json")
            try {
                conn.outputStream.use { out ->
                    out.write(org.json.JSONObject().put("sha256", hash).toString().toByteArray())
                }
                if (conn.responseCode != 200) "unverified"
                else if (org.json.JSONObject(conn.inputStream.bufferedReader().use { it.readText() })
                        .optString("verdict") == "known_malicious") "known_malicious"
                else "unverified"
            } finally { conn.disconnect() }
        } catch (_: Exception) { "unverified" }
    }
}
