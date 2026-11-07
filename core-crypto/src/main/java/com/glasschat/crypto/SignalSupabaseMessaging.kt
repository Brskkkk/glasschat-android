package com.glasschat.crypto

import com.glasschat.data.CiphertextDelivery
import com.glasschat.data.SealedLocalStore
import com.glasschat.network.SupabaseRelayClient
import org.json.JSONObject
import java.time.Instant
import java.util.UUID

/** Authenticated mapping established by the caller from the account/device directory. */
data class VerifiedPeerTransportDevice(
    val accountId: String,
    val signalDeviceId: Int,
    val conversationId: String
)

data class SecureSendResult(
    val deliveryId: String,
    val state: SendState,
    val detail: String
)

enum class SendState {
    ENCRYPTED_QUEUED_NOT_DELIVERED,
    RELAY_ACCEPTED_RECIPIENT_NOT_CONFIRMED,
    RELAY_ACCEPTED_LOCAL_STATE_PENDING
}

data class SecureReceiveResult(
    val stored: Int,
    val acknowledged: Int,
    val skipped: Int,
    val failures: List<String>
)

/**
 * Coordinates the existing Signal ratchet/outbox with authenticated Supabase RPCs. It accepts
 * already-authenticated session and directory data; it never treats IDs supplied by a composer or
 * relay row as proof of identity. Network calls carry only opaque Signal envelopes.
 *
 * A timeout or rejected response is reported as locally queued, never as sent. Repeating a delivery
 * uses the same id and ciphertext; the server's idempotency check makes that safe. Incoming rows are
 * acknowledged only after authenticated device mapping, Signal decryption, and durable encrypted
 * local message storage have all succeeded.
 */
class SignalSupabaseMessaging(
    private val relay: SupabaseRelayClient,
    private val pipeline: SignalMessagePipeline,
    private val localStore: SealedLocalStore,
    private val accessToken: () -> String,
    private val localAccountId: String,
    private val localSignalDeviceId: Int,
    private val localTransportDeviceId: String
) {
    @Synchronized
    fun sendText(
        recipient: VerifiedPeerTransportDevice,
        recipientTransportDeviceId: String,
        conversationId: String,
        text: String,
        now: Long = System.currentTimeMillis()
    ): SecureSendResult {
        require(recipientTransportDeviceId.isNotBlank())
        require(recipient.accountId.isNotBlank() && recipient.signalDeviceId in 1..127)
        require(conversationId.isNotBlank())
        val deliveryId = UUID.randomUUID().toString()
        val expiry = now + MAX_RELAY_RETENTION_MS
        val queued = pipeline.encryptAndQueue(
            deliveryId = deliveryId,
            localAccountId = localAccountId,
            localSignalDeviceId = localSignalDeviceId,
            authenticatedLocalTransportDeviceId = localTransportDeviceId,
            senderTransportDeviceId = localTransportDeviceId,
            recipientAccountId = recipient.accountId,
            recipientSignalDeviceId = recipient.signalDeviceId,
            recipientTransportDeviceId = recipientTransportDeviceId,
            plaintext = text,
            expiresAt = expiry,
            conversationId = conversationId,
            now = now
        )
        var relayConfirmed = false
        return try {
            submit(queued.deliveryId, queued.recipientDeviceId, queued.ciphertext, queued.expiresAt)
            relayConfirmed = true
            pipeline.markRelayAccepted(queued.deliveryId, queued.recipientDeviceId)
            SecureSendResult(queued.deliveryId, SendState.RELAY_ACCEPTED_RECIPIENT_NOT_CONFIRMED,
                "Encrypted ciphertext accepted by relay; recipient has not confirmed receipt.")
        } catch (_: Exception) {
            if (relayConfirmed) SecureSendResult(queued.deliveryId, SendState.RELAY_ACCEPTED_LOCAL_STATE_PENDING,
                "Relay accepted the encrypted message; recipient receipt is unconfirmed, and local outbox cleanup is pending.")
            else SecureSendResult(queued.deliveryId, SendState.ENCRYPTED_QUEUED_NOT_DELIVERED,
                "No relay confirmation; encrypted copy remains queued locally. Recipient receipt is unconfirmed.")
        } finally {
            queued.ciphertext.fill(0)
        }
    }

    /** Independently ratchet-encrypt and submit to every verified device in the same peer account. */
    @Synchronized
    fun sendTextToDevices(
        recipients: List<VerifiedPeerTransportDeviceWithTransport>,
        conversationId: String,
        text: String,
        now: Long = System.currentTimeMillis()
    ): List<SecureSendResult> {
        require(recipients.isNotEmpty())
        require(recipients.all { it.peer.conversationId == conversationId })
        val queued = pipeline.encryptAndQueueFanout(
            localAccountId = localAccountId,
            localSignalDeviceId = localSignalDeviceId,
            authenticatedLocalTransportDeviceId = localTransportDeviceId,
            recipients = recipients,
            plaintext = text,
            conversationId = conversationId,
            now = now
        )
        return queued.map { delivery ->
            var confirmed = false
            try {
                submit(delivery.deliveryId, delivery.recipientDeviceId, delivery.ciphertext, delivery.expiresAt)
                confirmed = true
                pipeline.markRelayAccepted(delivery.deliveryId, delivery.recipientDeviceId)
                SecureSendResult(delivery.deliveryId, SendState.RELAY_ACCEPTED_RECIPIENT_NOT_CONFIRMED,
                    "Encrypted ciphertext accepted for this device; recipient receipt is unconfirmed.")
            } catch (_: Exception) {
                if (confirmed) SecureSendResult(delivery.deliveryId, SendState.RELAY_ACCEPTED_LOCAL_STATE_PENDING,
                    "Relay accepted this device's ciphertext; local outbox cleanup is pending.")
                else SecureSendResult(delivery.deliveryId, SendState.ENCRYPTED_QUEUED_NOT_DELIVERED,
                    "This device's encrypted copy remains queued locally; relay acceptance is unconfirmed.")
            } finally { delivery.ciphertext.fill(0) }
        }
    }

    /** Retry safely after network restoration; each result retains its own delivery ID/state. */
    @Synchronized
    fun retryPending(now: Long = System.currentTimeMillis()): List<SecureSendResult> {
        val result = ArrayList<SecureSendResult>()
        for (delivery in localStore.pendingCiphertext(now)) {
            var relayConfirmed = false
            try {
                submit(delivery.deliveryId, delivery.recipientDeviceId, delivery.ciphertext, delivery.expiresAt)
                relayConfirmed = true
                pipeline.markRelayAccepted(delivery.deliveryId, delivery.recipientDeviceId)
                result += SecureSendResult(delivery.deliveryId, SendState.RELAY_ACCEPTED_RECIPIENT_NOT_CONFIRMED,
                    "Encrypted ciphertext accepted by relay; recipient has not confirmed receipt.")
            } catch (_: Exception) {
                if (relayConfirmed) result += SecureSendResult(delivery.deliveryId, SendState.RELAY_ACCEPTED_LOCAL_STATE_PENDING,
                    "Relay accepted the encrypted message; recipient receipt is unconfirmed, and local outbox cleanup is pending.")
                else result += SecureSendResult(delivery.deliveryId, SendState.ENCRYPTED_QUEUED_NOT_DELIVERED,
                    "Still queued locally; relay acceptance is unconfirmed.")
            } finally {
                delivery.ciphertext.fill(0)
            }
        }
        return result
    }

    /** Refresh sender-owned, per-device durable-storage receipts without exposing relay ciphertext. */
    @Synchronized
    fun refreshDeliveryStatuses(): Int {
        val expected = LinkedHashMap<String, String>()
        for (message in localStore.list("message")) {
            val states = message.optJSONArray("deviceDeliveries") ?: continue
            for (index in 0 until states.length()) {
                val state = states.optJSONObject(index) ?: continue
                if (state.optString("state") == "relay_accepted_recipient_not_confirmed") {
                    val id = state.optString("deliveryId")
                    val recipient = state.optString("recipientTransportDeviceId")
                    if (id.isNotBlank() && recipient.isNotBlank()) expected[id] = recipient
                }
            }
        }
        if (expected.isEmpty()) return 0
        val receipts = LinkedHashMap<String, RelayDeliveryReceipt>()
        val ids = expected.keys.toList()
        for (batch in ids.chunked(100)) {
            val rows = relay.fetchDeliveryStatuses(accessToken(), localTransportDeviceId, batch)
            for (index in 0 until rows.length()) {
                val row = rows.optJSONObject(index) ?: continue
                val id = row.optString("delivery_id")
                val recipient = row.optString("recipient_device_id")
                val status = row.optString("status")
                if (id !in batch || expected[id] != recipient) continue
                val recordedAt = row.optString("recorded_at").takeIf { it.isNotBlank() }
                    ?.let { try { Instant.parse(it).toEpochMilli() } catch (_: Exception) { null } }
                receipts[id] = RelayDeliveryReceipt(recipient, status, recordedAt)
            }
        }
        // A missing response is not proof of delivery. Leave it unchanged; only the authenticated
        // status RPC may advance the visible state.
        return pipeline.applyDeliveryReceipts(receipts)
    }

    /**
     * Poll encrypted deliveries. `peerDevices` must come from authenticated contact-device lookup
     * and must already bind each transport UUID to the expected Signal account/device/conversation.
     */
    @Synchronized
    fun receivePending(
        peerDevices: Map<String, VerifiedPeerTransportDevice>,
        now: Long = System.currentTimeMillis(),
        limit: Int = 50
    ): SecureReceiveResult {
        val rows = relay.fetchCiphertext(accessToken(), localTransportDeviceId, limit)
        var stored = 0
        var acknowledged = 0
        var skipped = 0
        val failures = ArrayList<String>()
        for (index in 0 until rows.length()) {
            val row = rows.optJSONObject(index)
            if (row == null) { skipped++; continue }
            val deliveryId = row.optString("delivery_id")
            val senderDeviceId = row.optString("sender_device_id")
            val recipientDeviceId = row.optString("recipient_device_id")
            val peer = peerDevices[senderDeviceId]
            if (deliveryId.isBlank() || peer == null || recipientDeviceId != localTransportDeviceId) {
                skipped++
                continue
            }
            var ciphertext: ByteArray? = null
            try {
                val expiry = Instant.parse(row.getString("expires_at")).toEpochMilli()
                ciphertext = relay.decodePgBytea(row.getString("ciphertext"))
                val messageId = pipeline.decryptAndStore(
                    CiphertextDelivery(deliveryId, senderDeviceId, recipientDeviceId, ciphertext, expiry),
                    authenticatedLocalTransportDeviceId = localTransportDeviceId,
                    authenticatedSenderTransportDeviceId = senderDeviceId,
                    localAccountId = localAccountId,
                    localSignalDeviceId = localSignalDeviceId,
                    senderAccountId = peer.accountId,
                    senderSignalDeviceId = peer.signalDeviceId,
                    conversationId = peer.conversationId,
                    receivedAt = now
                )
                check(messageId == deliveryId) { "Stored message ID does not match relay delivery" }
                stored++
                if (relay.acknowledgeCiphertext(accessToken(), deliveryId, localTransportDeviceId)) {
                    acknowledged++
                } else {
                    failures += "A received message is safely stored, but relay acknowledgment is pending."
                }
            } catch (_: Exception) {
                // Keep server copy for retry; do not reveal transport details or mark it delivered.
                failures += "One encrypted delivery could not be stored and acknowledged; it remains on the relay."
            } finally {
                ciphertext?.fill(0)
                clearJsonCiphertext(row)
            }
        }
        return SecureReceiveResult(stored, acknowledged, skipped, failures)
    }

    private fun submit(deliveryId: String, recipientDeviceId: String, ciphertext: ByteArray, expiresAt: Long) {
        val response = relay.submitCiphertext(
            token = accessToken(),
            deliveryId = deliveryId,
            senderDeviceId = localTransportDeviceId,
            recipientDeviceId = recipientDeviceId,
            ciphertext = ciphertext,
            expiresAtIso = Instant.ofEpochMilli(expiresAt).toString()
        )
        check(response == deliveryId) { "Relay did not confirm the requested delivery ID" }
    }

    private fun clearJsonCiphertext(row: JSONObject) {
        row.remove("ciphertext")
    }

    private companion object {
        const val MAX_RELAY_RETENTION_MS = 7L * 24 * 60 * 60 * 1000
    }
}
