package com.glasschat.ui

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.ContextCompat

/** Optional, content-free local alerts for newly persisted Signal messages discovered by polling. */
object SecureMessageNotifications {
    private const val CHANNEL_ID = "glasschat-secure-messages"
    private const val NOTIFICATION_ID = 0x4743
    private const val PREFERENCES = "glasschat_notification_preferences"
    private const val ENABLED_KEY = "secure_messages_enabled"

    fun isEnabled(context: Context): Boolean = context.applicationContext
        .getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
        .getBoolean(ENABLED_KEY, false)

    fun enable(context: Context) {
        val app = context.applicationContext
        createChannel(app)
        app.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .edit().putBoolean(ENABLED_KEY, true).apply()
    }

    fun disable(context: Context) {
        val app = context.applicationContext
        app.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .edit().putBoolean(ENABLED_KEY, false).apply()
        (app.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager).cancel(NOTIFICATION_ID)
    }

    fun showNewMessages(context: Context, count: Int) {
        if (count <= 0) return
        val app = context.applicationContext
        if (!isEnabled(app)) return
        if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(
                app, Manifest.permission.POST_NOTIFICATIONS
            ) != PackageManager.PERMISSION_GRANTED
        ) return

        createChannel(app)
        val launch = app.packageManager.getLaunchIntentForPackage(app.packageName) ?: return
        launch.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK or android.content.Intent.FLAG_ACTIVITY_CLEAR_TOP)
        val pendingIntent = PendingIntent.getActivity(
            app, 0, launch, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val manager = app.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val title = if (count == 1) "New secure message" else "New secure messages"
        try {
            manager.notify(NOTIFICATION_ID, Notification.Builder(app, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_notify_chat)
                .setContentTitle(title)
                .setContentText(if (count == 1) "Open GlassChat to view it" else "Open GlassChat to view them")
                .setContentIntent(pendingIntent)
                .setAutoCancel(true)
                .setVisibility(Notification.VISIBILITY_PRIVATE)
                .build())
        } catch (_: SecurityException) {
            // Permission may be revoked between the check and notify; polling still completed safely.
        }
    }

    private fun createChannel(context: Context) {
        if (Build.VERSION.SDK_INT >= 26) {
            val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(NotificationChannel(
                CHANNEL_ID,
                "Secure messages",
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = "Generic alerts when encrypted messages are saved on this device."
                lockscreenVisibility = Notification.VISIBILITY_PRIVATE
            })
        }
    }
}
