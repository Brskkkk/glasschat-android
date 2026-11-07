package com.glasschat.owner

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.core.content.ContextCompat

/** Opt-in reboot startup only; Android may still defer or reject background FGS starts. */
class OwnerBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != Intent.ACTION_BOOT_COMPLETED) return
        if (!GlassChatOwnerService.isAutoStartEnabled(context)) return
        if (GlassChatOwnerService.wasExplicitlyStopped(context)) return

        try {
            ContextCompat.startForegroundService(
                context,
                Intent(context, GlassChatOwnerService::class.java).setAction(GlassChatOwnerService.ACTION_START)
            )
        } catch (error: RuntimeException) {
            // Android/OEM background-start rules can prevent automatic recovery. Never bypass them.
            Log.w("GlassChatOwner", "Automatic startup was blocked; the owner must open the app", error)
        }
    }
}
