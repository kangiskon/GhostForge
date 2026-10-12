package com.ghostforge.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.IDN
import java.net.URL
import java.util.concurrent.Executors
import java.util.concurrent.Semaphore
import java.util.concurrent.atomic.AtomicBoolean
import org.json.JSONObject

/**
 * DNS-only split-tunnel VPN. Only requests sent to 10.117.0.1 are routed into the TUN.
 * Other IP traffic does not pass through the app. DNS-over-HTTPS goes directly to Cloudflare.
 * This cannot inspect HTTPS URLs, third-party DoH clients, or already-cached DNS answers.
 */
class DnsGuardService : VpnService() {
    companion object {
        const val START = "com.ghostforge.app.START_DNS_GUARD"
        const val STOP = "com.ghostforge.app.STOP_DNS_GUARD"
        @Volatile var running = false
            private set
        @Volatile var blockedCount = 0
            private set
        @Volatile var lastError = ""
            private set
    }

    private val active = AtomicBoolean(false)
    private var tun: ParcelFileDescriptor? = null
    private val workers = Executors.newFixedThreadPool(6)
    private val slots = Semaphore(32)
    @Volatile private var domains: Set<String> = setOf("malware.test")
    private val writeLock = Any()

    override fun onCreate() {
        super.onCreate()
        val channel = NotificationChannel("ghostforge_dns", "GhostForge DNS Guard", NotificationManager.IMPORTANCE_LOW)
        (getSystemService(NOTIFICATION_SERVICE) as NotificationManager).createNotificationChannel(channel)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == STOP) {
            stopGuard()
            return START_NOT_STICKY
        }
        if (intent?.action != START) return START_NOT_STICKY
        if (!active.compareAndSet(false, true)) return START_STICKY
        lastError = ""
        val note = Notification.Builder(this, "ghostforge_dns")
            .setContentTitle("GhostForge DNS Guard")
            .setContentText("DNS filtering active • Tap GhostForge to manage")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .build()
        startForeground(1007, note)
        workers.execute {
            try {
                loadDomains()
                val descriptor = Builder()
                    .setSession("GhostForge DNS Guard")
                    .setMtu(1500)
                    .addAddress("10.117.0.2", 32)
                    .addDnsServer("10.117.0.1")
                    .addRoute("10.117.0.1", 32)
                    // Exclude GhostForge itself to avoid recursive lookups when contacting
                    // the HTTPS resolver or refreshing the feed.
                    .addDisallowedApplication(packageName)
                    .establish()
                if (descriptor == null) {
                    lastError = "Android refused to establish the DNS VPN."
                    stopGuard()
                    return@execute
                }
                tun = descriptor
                running = true
                processPackets(descriptor)
            } catch (ex: Exception) {
                lastError = ex.message ?: "DNS Guard failed"
            } finally {
                stopGuard()
            }
        }
        return START_STICKY
    }

    private fun loadDomains() {
        val prefs = getSharedPreferences("ghostforge_settings", MODE_PRIVATE)
        val manual = prefs.getString("blocked_domains", "").orEmpty()
        val known = mutableSetOf("malware.test")
        fun addDomain(s: String) {
            val item = s.trim().lowercase().trim('.')
            if (item.length in 4..253 && item.contains(".") &&
                item.matches(Regex("[a-z0-9.-]+")) && !item.contains("..")) known.add(item)
        }
        manual.lineSequence().forEach { addDomain(it) }

        // Optional self-hosted feed. DNS queries themselves are not sent to this server.
        val base = prefs.getString("endpoint", "").orEmpty().trimEnd('/')
        if (base.startsWith("https://") && !base.endsWith(".invalid")) {
            try {
                val conn = URL(base + "/api/v1/protection/domains").openConnection() as HttpURLConnection
                conn.connectTimeout = 4000
                conn.readTimeout = 4000
                conn.instanceFollowRedirects = false
                try {
                    if (conn.responseCode == 200) {
                        val root = JSONObject(conn.inputStream.bufferedReader().use { it.readText() })
                        val list = root.optJSONArray("domains")
                        if (list != null) {
                            for (i in 0 until minOf(list.length(), 20000)) addDomain(list.optString(i))
                        }
                    }
                } finally { conn.disconnect() }
            } catch (_: Exception) { /* keep manual rules if offline */ }
        }
        domains = known
    }

    private fun processPackets(fd: ParcelFileDescriptor) {
        val input = FileInputStream(fd.fileDescriptor)
        val output = FileOutputStream(fd.fileDescriptor)
        val packet = ByteArray(4096)
        while (active.get()) {
            val size = try { input.read(packet) } catch (_: Exception) { break }
            if (size <= 0) break
            val copy = packet.copyOf(size)
            if (!slots.tryAcquire()) continue
            workers.execute {
                try {
                    val result = reply(copy)
                    if (result != null && active.get()) synchronized(writeLock) {
                        try { output.write(result) } catch (_: Exception) { }
                    }
                } finally { slots.release() }
            }
        }
    }

    private fun reply(packet: ByteArray): ByteArray? {
        if (packet.size < 40) return null
        val version = (packet[0].toInt() ushr 4) and 15
        val ihl = (packet[0].toInt() and 15) * 4
        if (version != 4 || ihl < 20 || packet.size < ihl + 20 ||
            (packet[9].toInt() and 255) != 17) return null
        val frag = ((packet[6].toInt() and 31) shl 8) or (packet[7].toInt() and 255)
        if (frag != 0 || (packet[6].toInt() and 32) != 0) return null
        val udp = ihl
        val dstPort = readU16(packet, udp + 2)
        if (dstPort != 53) return null
        val udpSize = readU16(packet, udp + 4)
        if (udpSize < 20 || udp + udpSize > packet.size) return null
        val request = packet.copyOfRange(udp + 8, udp + udpSize)
        val question = readQuestion(request)
        val answer = when {
            question == null -> dnsError(request, 1)
            isBlocked(question) -> {
                blockedCount++
                dnsError(request, 3)
            }
            else -> dohLookup(request) ?: dnsError(request, 2)
        }
        if (answer == null) return null
        val total = 20 + 8 + answer.size
        if (total > 65535) return null
        val out = ByteArray(total)
        out[0] = 0x45
        out[2] = (total ushr 8).toByte()
        out[3] = total.toByte()
        out[8] = 64
        out[9] = 17
        System.arraycopy(packet, 16, out, 12, 4)
        System.arraycopy(packet, 12, out, 16, 4)
        out[20] = packet[udp + 2]
        out[21] = packet[udp + 3]
        out[22] = packet[udp]
        out[23] = packet[udp + 1]
        val length = 8 + answer.size
        out[24] = (length ushr 8).toByte()
        out[25] = length.toByte()
        System.arraycopy(answer, 0, out, 28, answer.size)
        val sum = checksum(out, 0, 20)
        out[10] = (sum ushr 8).toByte()
        out[11] = sum.toByte()
        // UDP checksum omitted (valid for IPv4). Never used for IPv6.
        return out
    }

    private fun readQuestion(dns: ByteArray): String? {
        if (dns.size < 17 || readU16(dns, 4) != 1 ||
            (dns[2].toInt() and 128) != 0) return null
        val names = ArrayList<String>()
        var p = 12
        while (p < dns.size) {
            val length = dns[p++].toInt() and 255
            if (length == 0) {
                if (p + 4 > dns.size) return null
                val host = names.joinToString(".").lowercase()
                return try { IDN.toASCII(host) } catch (_: Exception) { null }
            }
            if (length > 63 || p + length > dns.size) return null
            names.add(String(dns, p, length, Charsets.US_ASCII))
            p += length
            if (names.size > 60) return null
        }
        return null
    }

    private fun isBlocked(host: String): Boolean =
        domains.any { host == it || host.endsWith("." + it) }

    private fun dohLookup(dns: ByteArray): ByteArray? {
        return try {
            val conn = URL("https://cloudflare-dns.com/dns-query").openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.connectTimeout = 3500
            conn.readTimeout = 3500
            conn.instanceFollowRedirects = false
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/dns-message")
            conn.setRequestProperty("Accept", "application/dns-message")
            try {
                conn.outputStream.use { it.write(dns) }
                if (conn.responseCode != 200) null else {
                    val answer = conn.inputStream.use { input ->
                        val buffer = ByteArray(4096)
                        val output = java.io.ByteArrayOutputStream()
                        while (output.size() < buffer.size) {
                            val n = input.read(buffer, 0, buffer.size - output.size())
                            if (n < 0) break
                            output.write(buffer, 0, n)
                        }
                        output.toByteArray()
                    }
                    if (answer.size < 12) null else answer
                }
            } finally { conn.disconnect() }
        } catch (_: Exception) { null }
    }

    private fun dnsError(request: ByteArray, rcode: Int): ByteArray? {
        if (request.size < 12) return null
        // Respond to the same question without pretending a malicious domain is resolved.
        var i = 12
        while (i < request.size && (request[i].toInt() and 255) in 1..63) {
            i += 1 + (request[i].toInt() and 255)
        }
        if (i + 5 > request.size) return null
        val response = request.copyOfRange(0, i + 5)
        response[2] = 0x81.toByte()
        response[3] = (0x80 or rcode).toByte()
        for (p in 6..11) response[p] = 0
        return response
    }

    private fun readU16(data: ByteArray, off: Int) =
        ((data[off].toInt() and 255) shl 8) or (data[off + 1].toInt() and 255)

    private fun checksum(data: ByteArray, start: Int, length: Int): Int {
        var sum = 0L
        for (i in start until start + length step 2) {
            sum += ((data[i].toInt() and 255) shl 8) or (data[i + 1].toInt() and 255)
        }
        while (sum > 0xffff) sum = (sum and 0xffff) + (sum ushr 16)
        return (sum.inv() and 0xffff).toInt()
    }

    private fun stopGuard() {
        active.set(false)
        running = false
        try { tun?.close() } catch (_: Exception) { }
        tun = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onRevoke() {
        stopGuard()
        super.onRevoke()
    }

    override fun onDestroy() {
        active.set(false)
        running = false
        try { tun?.close() } catch (_: Exception) { }
        workers.shutdownNow()
        super.onDestroy()
    }
}
