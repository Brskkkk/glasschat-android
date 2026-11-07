package com.glasschat.owner

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat

/** Lifecycle/notification demonstration only. It deliberately does not claim to host GlassChat APIs. */
class GlassChatOwnerService : Service() {
    override fun onCreate() { super.onCreate(); createChannel() }
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> { currentStatus = "Stopped"; stopForeground(STOP_FOREGROUND_REMOVE); stopSelf(); return START_NOT_STICKY }
            ACTION_PAUSE -> { currentStatus = "Paused · backend not configured"; updateNotification(); return START_NOT_STICKY }
            else -> { currentStatus = "Demo active · backend not configured"; startForeground(NOTIFICATION_ID, buildNotification()); return START_NOT_STICKY }
        }
    }
    override fun onBind(intent: Intent?): IBinder? = null
    override fun onDestroy() { if (currentStatus != "Stopped") currentStatus = "Stopped"; super.onDestroy() }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            val channel = NotificationChannel(CHANNEL_ID, "GlassChat Owner service preview", NotificationManager.IMPORTANCE_LOW).apply { description = "Shows the local foreground-service demonstration state." }
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }
    private fun buildNotification(): Notification {
        val open = PendingIntent.getActivity(this, 1, Intent(this, MainActivity::class.java), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(this, 2, Intent(this, GlassChatOwnerService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val pause = PendingIntent.getService(this, 3, Intent(this, GlassChatOwnerService::class.java).setAction(ACTION_PAUSE), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_sync_noanim)
            .setContentTitle("GlassChat Owner · demo")
            .setContentText(currentStatus)
            .setStyle(NotificationCompat.BigTextStyle().bigText("$currentStatus. No account service, relay or server endpoint is configured."))
            .setContentIntent(open).setOngoing(true).setOnlyAlertOnce(true)
            .addAction(0, "Open", open).addAction(0, "Pause", pause).addAction(0, "Stop", stop).build()
    }
    private fun updateNotification() { getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, buildNotification()) }

    companion object {
        const val ACTION_START = "com.glasschat.owner.START"
        const val ACTION_PAUSE = "com.glasschat.owner.PAUSE"
        const val ACTION_STOP = "com.glasschat.owner.STOP"
        private const val CHANNEL_ID = "glasschat_owner_preview"
        private const val NOTIFICATION_ID = 4101
        @Volatile var currentStatus: String = "Not configured"
            private set
    }
}
