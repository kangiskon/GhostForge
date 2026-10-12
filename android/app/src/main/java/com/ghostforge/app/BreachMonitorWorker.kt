package com.ghostforge.app

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import org.json.JSONObject

class BreachMonitorWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        val context = applicationContext
        val prefs = context.getSharedPreferences("ghostforge_settings", Context.MODE_PRIVATE)
        if (!prefs.getBoolean("breach_monitor", false)) return Result.success()
        val token = VerifiedSession.get(context) ?: return Result.success()
        val endpoint = prefs.getString("endpoint", "").orEmpty()
        val found = SecurityApi.breaches(endpoint, token).getOrElse { return Result.retry() }
        if (!found.optBoolean("checked", false)) return Result.retry()
        val names = found.optJSONArray("breaches")
        val list = (0 until (names?.length() ?: 0)).map { names!!.optString(it) }
            .filter { it.isNotBlank() }.sorted()
        val signature = list.joinToString("|")
        val previous = prefs.getString("last_breach_list", null)
        prefs.edit().putString("last_breach_list", signature).apply()
        if (previous == null || previous == signature || list.isEmpty()) return Result.success()
        val prior = previous.split("|").filter { it.isNotBlank() }.toSet()
        val fresh = list.filterNot { it in prior }
        if (fresh.isEmpty()) return Result.success()
        if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(
            context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) return Result.success()
        val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        notificationManager.createNotificationChannel(NotificationChannel(
            "ghostforge_alerts", "GhostForge Security Alerts", NotificationManager.IMPORTANCE_DEFAULT))
        val intent = Intent(context, MainActivity::class.java)
        val pending = PendingIntent.getActivity(context, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val notification = NotificationCompat.Builder(context, "ghostforge_alerts")
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("GhostForge: new breach reported")
            .setContentText("A verified email has new reported breach exposure. Open GhostForge for details.")
            .setContentIntent(pending)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .build()
        notificationManager.notify(512, notification)
        return Result.success()
    }
}
