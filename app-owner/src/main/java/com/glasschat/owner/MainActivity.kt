package com.glasschat.owner

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import com.glasschat.ui.GlassChatScreen

class MainActivity : ComponentActivity() {
    private val askNotifications = registerForActivityResult(ActivityResultContracts.RequestPermission()) { startGlassChatOwnerService() }
    override fun onCreate(savedInstanceState: Bundle?) { super.onCreate(savedInstanceState)
        setContent {
            GlassChatScreen(owner = true, serviceStatus = GlassChatOwnerService.currentStatus,
                onStart = {
                    if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) askNotifications.launch(Manifest.permission.POST_NOTIFICATIONS)
                    else startGlassChatOwnerService()
                }, onStop = { startService(Intent(this, GlassChatOwnerService::class.java).setAction(GlassChatOwnerService.ACTION_STOP)) })
        }
    }
    private fun startGlassChatOwnerService() { ContextCompat.startForegroundService(this, Intent(this, GlassChatOwnerService::class.java).setAction(GlassChatOwnerService.ACTION_START)) }
}
