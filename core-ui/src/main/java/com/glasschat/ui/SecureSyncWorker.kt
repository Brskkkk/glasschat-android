package com.glasschat.ui

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import com.glasschat.crypto.GlassChatSecureRuntime
import com.glasschat.data.SealedLocalStore
import java.util.concurrent.TimeUnit

/**
 * Best-effort, network-constrained refresh for verified accounts. The relay still contains only
 * ciphertext; the worker decrypts and commits locally before its runtime acknowledges a delivery.
 * This is periodic polling, not push delivery or an always-on Owner server.
 */
class SecureSyncWorker(context: Context, params: WorkerParameters) : Worker(context, params) {
    override fun doWork(): Result {
        val store = try { SealedLocalStore(applicationContext) } catch (_: Exception) { return Result.failure() }
        return try {
            val runtime = GlassChatSecureRuntime(store)
            runtime.retryQueued()
            runtime.receive()
            Result.success()
        } catch (_: Exception) {
            if (runAttemptCount >= MAX_RETRIES) Result.failure() else Result.retry()
        } finally {
            store.close()
        }
    }

    companion object {
        private const val MAX_RETRIES = 8
    }
}

/** Schedules low-frequency encrypted inbox/outbox sync only after a verified session exists. */
object SecureSyncScheduler {
    private const val PERIODIC_NAME = "glasschat-secure-periodic-sync"
    private const val IMMEDIATE_NAME = "glasschat-secure-sync-now"

    fun start(context: Context) {
        val app = context.applicationContext
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()
        val periodic = androidx.work.PeriodicWorkRequest.Builder(
            SecureSyncWorker::class.java, 15, TimeUnit.MINUTES
        ).setConstraints(constraints)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
            .build()
        val immediate = androidx.work.OneTimeWorkRequest.Builder(SecureSyncWorker::class.java)
            .setConstraints(constraints)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
            .build()
        WorkManager.getInstance(app).enqueueUniquePeriodicWork(
            PERIODIC_NAME, ExistingPeriodicWorkPolicy.KEEP, periodic
        )
        WorkManager.getInstance(app).enqueueUniqueWork(
            IMMEDIATE_NAME, ExistingWorkPolicy.KEEP, immediate
        )
    }
}
