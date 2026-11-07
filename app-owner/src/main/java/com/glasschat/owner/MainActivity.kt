package com.glasschat.owner

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import com.glasschat.ui.LocalMessengerScreen

class MainActivity : ComponentActivity() {
    private var notice by mutableStateOf("")
    private var autoStartEnabled by mutableStateOf(false)
    private var lastServerStartMillis by mutableStateOf(0L)
    private val askNotifications = registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) startGlassChatOwnerService()
        else notice = "Notifications are off, so the foreground service notification cannot be shown. Allow notifications before starting the server service."
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        autoStartEnabled = GlassChatOwnerService.isAutoStartEnabled(this)
        lastServerStartMillis = GlassChatOwnerService.lastStartTimeMillis(this)
        setContent {
            val serviceStatus by GlassChatOwnerService.status.collectAsState()
            LaunchedEffect(serviceStatus) {
                if (serviceStatus == GlassChatOwnerService.STATUS_ACTIVE) {
                    lastServerStartMillis = GlassChatOwnerService.lastStartTimeMillis(this@MainActivity)
                }
            }
            LocalMessengerScreen(
                context = LocalContext.current,
                owner = true,
                ownerServiceStatus = serviceStatus,
                externalNotice = notice,
                onStartServer = ::requestStart,
                onPauseServer = { sendServiceAction(GlassChatOwnerService.ACTION_PAUSE) },
                onResumeServer = { sendServiceAction(GlassChatOwnerService.ACTION_RESUME) },
                onStopServer = { sendServiceAction(GlassChatOwnerService.ACTION_STOP) },
                autoStartEnabled = autoStartEnabled,
                lastServerStartMillis = lastServerStartMillis,
                onAutoStartChanged = { enabled ->
                    GlassChatOwnerService.setAutoStartEnabled(this, enabled)
                    autoStartEnabled = enabled
                    notice = if (enabled) "Automatic startup enabled by your choice. Android may still restrict it." else "Automatic startup disabled."
                }
            )
        }
    }

    private fun requestStart() {
        if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            askNotifications.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else startGlassChatOwnerService()
    }

    private fun startGlassChatOwnerService() {
        notice = ""
        ContextCompat.startForegroundService(
            this,
            Intent(this, GlassChatOwnerService::class.java).setAction(GlassChatOwnerService.ACTION_START)
        )
    }

    private fun sendServiceAction(action: String) {
        if (action == GlassChatOwnerService.ACTION_RESUME || action == GlassChatOwnerService.ACTION_START) {
            ContextCompat.startForegroundService(this, Intent(this, GlassChatOwnerService::class.java).setAction(action))
        } else startService(Intent(this, GlassChatOwnerService::class.java).setAction(action))
    }
}
