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
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/**
 * Lifecycle-only foundation. No account API, database, relay or network listener is configured,
 * so this service must never describe itself as an operational messaging server.
 */
class GlassChatOwnerService : Service() {
    override fun onCreate() {
        super.onCreate()
        createChannel()
        state.value = persistedIdleState()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                preferences().edit().putBoolean(KEY_STOPPED, true).putBoolean(KEY_PAUSED, false).apply()
                publishState(STATUS_STOPPED)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf(startId)
                return START_NOT_STICKY
            }
            ACTION_PAUSE -> {
                preferences().edit().putBoolean(KEY_PAUSED, true).apply()
                publishState(STATUS_PAUSED)
                updateNotification()
                return START_STICKY
            }
            ACTION_RESUME, ACTION_START -> {
                preferences().edit().putBoolean(KEY_STOPPED, false).putBoolean(KEY_PAUSED, false).apply()
                startActive(startId)
                return START_STICKY
            }
            null -> {
                // START_STICKY may redeliver a null intent after process death. Honor the
                // owner's explicit Stop choice and never turn a paused service back on.
                val prefs = preferences()
                if (prefs.getBoolean(KEY_STOPPED, false) || prefs.getBoolean(KEY_PAUSED, false)) {
                    stopSelf(startId)
                    return START_NOT_STICKY
                }
                startActive(startId)
                return START_STICKY
            }
            else -> {
                stopSelf(startId)
                return START_NOT_STICKY
            }
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        if (state.value != STATUS_STOPPED && state.value != STATUS_PAUSED) publishState(STATUS_STOPPED)
        super.onDestroy()
    }

    private fun startActive(startId: Int) {
        publishState(STATUS_ACTIVE)
        ServiceCompat.startForeground(
            this,
            NOTIFICATION_ID,
            buildNotification(),
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) ServiceInfoCompat.TYPE_SPECIAL_USE else 0
        )
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "GlassChat Owner service status",
                NotificationManager.IMPORTANCE_LOW
            ).apply { description = "Shows whether the local Owner service lifecycle is active." }
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun buildNotification(): Notification {
        val open = PendingIntent.getActivity(
            this, 1, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val pauseOrResumeAction = if (state.value == STATUS_PAUSED) ACTION_RESUME else ACTION_PAUSE
        val pauseOrResumeLabel = if (state.value == STATUS_PAUSED) "Resume" else "Pause"
        val toggle = PendingIntent.getService(
            this, 3, Intent(this, GlassChatOwnerService::class.java).setAction(pauseOrResumeAction),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val stop = PendingIntent.getService(
            this, 2, Intent(this, GlassChatOwnerService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val checkedAt = DateTimeFormatter.ofPattern("HH:mm:ss")
            .withZone(ZoneId.systemDefault()).format(lastStartedAt ?: Instant.now())
        val statusText = if (state.value == STATUS_PAUSED) "Paused · backend not configured" else "Foreground service active · backend not configured"
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_sync_noanim)
            .setContentTitle("GlassChat Owner Server")
            .setContentText(statusText)
            .setStyle(NotificationCompat.BigTextStyle().bigText(
                "$statusText\nAccount service: unavailable\nRelay: unavailable\nLocal service start: $checkedAt"
            ))
            .setContentIntent(open)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .addAction(0, "Open dashboard", open)
            .addAction(0, pauseOrResumeLabel, toggle)
            .addAction(0, "Stop", stop)
            .build()
    }

    private fun publishState(value: String) {
        state.value = value
        if (value == STATUS_ACTIVE) lastStartedAt = Instant.now()
    }

    private fun updateNotification() {
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, buildNotification())
    }

    private fun preferences() = getSharedPreferences(PREFERENCES, MODE_PRIVATE)

    private fun persistedIdleState(): String = when {
        preferences().getBoolean(KEY_STOPPED, false) -> STATUS_STOPPED
        preferences().getBoolean(KEY_PAUSED, false) -> STATUS_PAUSED
        else -> STATUS_STOPPED // No live service can be assumed until Android starts it.
    }

    companion object {
        const val ACTION_START = "com.glasschat.owner.START"
        const val ACTION_PAUSE = "com.glasschat.owner.PAUSE"
        const val ACTION_RESUME = "com.glasschat.owner.RESUME"
        const val ACTION_STOP = "com.glasschat.owner.STOP"
        const val STATUS_ACTIVE = "Service active · backend not configured"
        const val STATUS_PAUSED = "Paused · backend not configured"
        const val STATUS_STOPPED = "Stopped"
        private const val CHANNEL_ID = "glasschat_owner_service"
        private const val NOTIFICATION_ID = 4101
        private const val PREFERENCES = "owner_service_state"
        private const val KEY_STOPPED = "explicitly_stopped"
        private const val KEY_PAUSED = "paused"
        private var lastStartedAt: Instant? = null
        private val state = MutableStateFlow(STATUS_STOPPED)
        val status: StateFlow<String> = state
    }
}

private object ServiceInfoCompat {
    const val TYPE_SPECIAL_USE = android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
}
