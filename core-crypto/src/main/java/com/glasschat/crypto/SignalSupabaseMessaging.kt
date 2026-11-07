package com.glasschat.crypto

import com.glasschat.data.CiphertextDelivery
import com.glasschat.data.SealedLocalStore
import com.glasschat.network.GroupCiphertextCopy
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
    /** Valid deliveries persisted locally, including safe duplicate retries. */
    val stored: Int,
    /** Newly created local message rows; suitable for one generic incoming notification. */
    val newlyStored: Int,
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

    /**
     * Independently ratchet-encrypt and submit to every verified device linked to this local
     * conversation. Direct chats are constrained by the runtime to one account; local groups may
     * include several accounts, each reached through a separate pairwise Signal session.
     */
    @Synchronized
    fun sendTextToDevices(
        recipients: List<VerifiedPeerTransportDeviceWithTransport>,
        conversationId: String,
        text: String,
        serverGroupId: String? = null,
        serverGroupMembershipVersion: Long? = null,
        now: Long = System.currentTimeMillis()
    ): List<SecureSendResult> {
        require(recipients.isNotEmpty())
        require(recipients.all { it.peer.conversationId == conversationId })
        require((serverGroupId == null) == (serverGroupMembershipVersion == null))
        val queued = pipeline.encryptAndQueueFanout(
            localAccountId = localAccountId,
            localSignalDeviceId = localSignalDeviceId,
            authenticatedLocalTransportDeviceId = localTransportDeviceId,
            recipients = recipients,
            plaintext = text,
            conversationId = conversationId,
            serverGroupId = serverGroupId,
            serverGroupMembershipVersion = serverGroupMembershipVersion,
            now = now
        )
        if (serverGroupId != null) {
            check(serverGroupMembershipVersion != null)
            val expiry = queued.first().expiresAt
            check(queued.all { it.expiresAt == expiry }) { "Group fan-out has inconsistent expiry times" }
            return submitGroupBatch(serverGroupId, serverGroupMembershipVersion, expiry,
                queued.map { GroupCiphertextCopy(it.deliveryId, it.recipientDeviceId, it.ciphertext) })
        }
        return queued.map { delivery ->
            var relayConfirmed = false
            try {
                submit(delivery.deliveryId, delivery.recipientDeviceId, delivery.ciphertext, delivery.expiresAt)
                relayConfirmed = true
                pipeline.markRelayAccepted(delivery.deliveryId, delivery.recipientDeviceId)
                SecureSendResult(delivery.deliveryId, SendState.RELAY_ACCEPTED_RECIPIENT_NOT_CONFIRMED,
                    "Encrypted ciphertext accepted for this device; recipient receipt is unconfirmed.")
            } catch (_: Exception) {
                if (relayConfirmed) SecureSendResult(delivery.deliveryId, SendState.RELAY_ACCEPTED_LOCAL_STATE_PENDING,
                    "Relay accepted this device's ciphertext; local cleanup is pending.")
                else SecureSendResult(delivery.deliveryId, SendState.ENCRYPTED_QUEUED_NOT_DELIVERED,
                    "This device's encrypted copy remains queued locally; relay acceptance is unconfirmed.")
            } finally { delivery.ciphertext.fill(0) }
        }
    }

    /** Retry safely after network restoration; each result retains its own delivery ID/state. */
    @Synchronized
    fun retryPending(now: Long = System.currentTimeMillis()): List<SecureSendResult> {
        val result = ArrayList<SecureSendResult>()
        val pending = localStore.pendingCiphertext(now)
        pending.filter { it.groupId == null }.forEach { delivery ->
            var relayConfirmed = false
            try {
                submit(delivery.deliveryId, delivery.recipientDeviceId, delivery.ciphertext, delivery.expiresAt)
                relayConfirmed = true
                pipeline.markRelayAccepted(delivery.deliveryId, delivery.recipientDeviceId)
                result += SecureSendResult(delivery.deliveryId, SendState.RELAY_ACCEPTED_RECIPIENT_NOT_CONFIRMED,
                    "Encrypted ciphertext accepted by relay; recipient has not confirmed receipt.")
            } catch (_: Exception) {
                if (relayConfirmed) result += SecureSendResult(delivery.deliveryId, SendState.RELAY_ACCEPTED_LOCAL_STATE_PENDING,
                    "Relay accepted this ciphertext; local cleanup is pending.")
                else result += SecureSendResult(delivery.deliveryId, SendState.ENCRYPTED_QUEUED_NOT_DELIVERED,
                    "Still queued locally; relay acceptance is unconfirmed.")
            } finally { delivery.ciphertext.fill(0) }
        }

        // Keep each server-managed logical message together on retry. The atomic RPC is
        // idempotent after a lost response, so retries cannot create a second partial fan-out.
        val grouped = pending.filter { it.groupId != null }.groupBy { delivery ->
            localStore.get("device", "fanout_delivery:${delivery.deliveryId}")
                ?.optString("fanoutMessageId")?.takeIf { it.isNotBlank() }
                ?: "missing:${delivery.deliveryId}"
        }
        grouped.forEach { (fanoutKey, copies) ->
            val groupId = copies.first().groupId
            val membershipVersion = copies.first().groupMembershipVersion
            val expiry = copies.first().expiresAt
            if (copies.any { it.groupId != groupId || it.groupMembershipVersion != membershipVersion || it.expiresAt != expiry }) {
                copies.forEach { delivery ->
                    result += SecureSendResult(delivery.deliveryId, SendState.ENCRYPTED_QUEUED_NOT_DELIVERED,
                        "Group ciphertext remains queued locally because its saved fan-out is inconsistent.")
                    delivery.ciphertext.fill(0)
                }
            } else if (groupId == null || membershipVersion == null || fanoutKey.startsWith("missing:")) {
                copies.forEach { delivery ->
                    result += SecureSendResult(delivery.deliveryId, SendState.ENCRYPTED_QUEUED_NOT_DELIVERED,
                        "Group ciphertext remains queued locally; refresh the group fan-out before retrying.")
                    delivery.ciphertext.fill(0)
                }
            } else {
                val messageId = fanoutKey
                val message = localStore.get("message", messageId)
                val deviceStates = message?.optJSONArray("deviceDeliveries")
                val pendingIds = copies.map { it.deliveryId }.toSet()
                val complete = deviceStates != null && (0 until deviceStates.length()).all { index ->
                    val state = deviceStates.optJSONObject(index) ?: return@all false
                    state.optString("state") in setOf(
                        "relay_accepted_recipient_not_confirmed", "recipient_stored"
                    ) || state.optString("deliveryId") in pendingIds
                }
                if (!complete) {
                    copies.forEach { delivery ->
                        result += SecureSendResult(delivery.deliveryId, SendState.ENCRYPTED_QUEUED_NOT_DELIVERED,
                            "Group ciphertext remains queued; refresh and prepare a complete fan-out before retrying.")
                        delivery.ciphertext.fill(0)
                    }
                } else {
                    result += submitGroupBatch(groupId, membershipVersion, expiry,
                        copies.map { GroupCiphertextCopy(it.deliveryId, it.recipientDeviceId, it.ciphertext) })
                }
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
        var newlyStored = 0
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
            val relayGroupId = row.optString("group_id").takeIf { it.isNotBlank() && it != "null" }
            val localConversation = peer?.let { localStore.get("conversation", it.conversationId) }
            val serverGroupMatches = if (localConversation?.optBoolean("serverManaged") == true)
                relayGroupId == peer?.conversationId else relayGroupId == null
            if (deliveryId.isBlank() || peer == null || recipientDeviceId != localTransportDeviceId || !serverGroupMatches) {
                skipped++
                continue
            }
            var ciphertext: ByteArray? = null
            try {
                val expiry = Instant.parse(row.getString("expires_at")).toEpochMilli()
                ciphertext = relay.decodePgBytea(row.getString("ciphertext"))
                val storedMessage = pipeline.decryptAndStore(
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
                check(storedMessage.deliveryId == deliveryId) { "Stored message ID does not match relay delivery" }
                stored++
                if (storedMessage.newlyStored) newlyStored++
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
        return SecureReceiveResult(stored, newlyStored, acknowledged, skipped, failures)
    }

    private fun submitGroupBatch(
        groupId: String,
        membershipVersion: Long,
        expiresAt: Long,
        copies: List<GroupCiphertextCopy>
    ): List<SecureSendResult> {
        return try {
            val accepted = relay.submitGroupCiphertextBatch(
                token = accessToken(), groupId = groupId, membershipVersion = membershipVersion,
                senderDeviceId = localTransportDeviceId, expiresAtIso = Instant.ofEpochMilli(expiresAt).toString(),
                copies = copies
            )
            check(accepted == copies.map { it.deliveryId }.toSet())
            copies.map { copy ->
                try {
                    pipeline.markRelayAccepted(copy.deliveryId, copy.recipientDeviceId)
                    SecureSendResult(copy.deliveryId, SendState.RELAY_ACCEPTED_RECIPIENT_NOT_CONFIRMED,
                        "Encrypted ciphertext accepted atomically for this group fan-out; recipient receipt is unconfirmed.")
                } catch (_: Exception) {
                    SecureSendResult(copy.deliveryId, SendState.RELAY_ACCEPTED_LOCAL_STATE_PENDING,
                        "The relay accepted this group fan-out; local cleanup for this device remains pending.")
                }
            }
        } catch (_: Exception) {
            copies.map { copy -> SecureSendResult(copy.deliveryId, SendState.ENCRYPTED_QUEUED_NOT_DELIVERED,
                "The complete encrypted group fan-out remains queued locally; relay acceptance is unconfirmed.") }
        } finally { copies.forEach { it.ciphertext.fill(0) } }
    }

    private fun submit(
        deliveryId: String, recipientDeviceId: String, ciphertext: ByteArray, expiresAt: Long,
        groupId: String? = null, groupMembershipVersion: Long? = null
    ) {
        require((groupId == null) == (groupMembershipVersion == null)) {
            "A server-group delivery without its saved roster version stays queued locally"
        }
        val token = accessToken()
        val expiry = Instant.ofEpochMilli(expiresAt).toString()
        val response = if (groupId == null) relay.submitCiphertext(
            token = token, deliveryId = deliveryId, senderDeviceId = localTransportDeviceId,
            recipientDeviceId = recipientDeviceId, ciphertext = ciphertext, expiresAtIso = expiry
        ) else relay.submitGroupCiphertext(
            token = token, deliveryId = deliveryId, groupId = groupId,
            membershipVersion = requireNotNull(groupMembershipVersion), senderDeviceId = localTransportDeviceId,
            recipientDeviceId = recipientDeviceId, ciphertext = ciphertext, expiresAtIso = expiry
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
