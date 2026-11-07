package com.glasschat.crypto

import com.glasschat.data.CiphertextDelivery
import com.glasschat.data.SealedLocalStore
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64

/** Versioned transport representation; it contains only Signal ciphertext, never a plaintext fallback. */
object SignalCiphertextEnvelopeCodec {
    private val MAGIC = byteArrayOf(0x47, 0x43, 0x53, 0x31) // GCS1
    private const val VERSION = 1
    private const val HEADER_BYTES = 10

    fun encode(envelope: SignalCiphertextEnvelope): ByteArray {
        val payload = envelope.serializedMessage
        try {
            require(payload.isNotEmpty() && payload.size <= SignalCiphertextEnvelope.MAX_SERIALIZED_MESSAGE_BYTES)
            val output = ByteArrayOutputStream(HEADER_BYTES + payload.size)
            DataOutputStream(output).use { data ->
                data.write(MAGIC)
                data.writeByte(VERSION)
                data.writeByte(envelope.type)
                data.writeInt(payload.size)
                data.write(payload)
            }
            return output.toByteArray()
        } finally {
            payload.fill(0)
        }
    }

    fun decode(wireBytes: ByteArray): SignalCiphertextEnvelope {
        require(wireBytes.size in HEADER_BYTES + 1..HEADER_BYTES + SignalCiphertextEnvelope.MAX_SERIALIZED_MESSAGE_BYTES) {
            "Signal envelope has an invalid size"
        }
        DataInputStream(ByteArrayInputStream(wireBytes)).use { data ->
            val magic = ByteArray(MAGIC.size)
            data.readFully(magic)
            require(magic.contentEquals(MAGIC)) { "Unsupported ciphertext envelope" }
            require(data.readUnsignedByte() == VERSION) { "Unsupported ciphertext envelope version" }
            val type = data.readUnsignedByte()
            val length = data.readInt()
            require(length in 1..SignalCiphertextEnvelope.MAX_SERIALIZED_MESSAGE_BYTES && length == data.available()) {
                "Ciphertext envelope length is invalid"
            }
            val payload = ByteArray(length)
            data.readFully(payload)
            return try {
                SignalCiphertextEnvelope(type, payload)
            } finally {
                payload.fill(0)
                magic.fill(0)
            }
        }
    }
}

/** Metadata returned after an encrypted copy has been durably queued on this device. */
data class QueuedSignalDelivery(
    val deliveryId: String,
    val recipientDeviceId: String,
    val expiresAt: Long,
    /** Opaque Signal ciphertext for an authenticated transport adapter; caller must clear it. */
    val ciphertext: ByteArray
)

/** Minimal status metadata returned by the authenticated relay; never includes message content. */
data class RelayDeliveryReceipt(val recipientDeviceId: String, val status: String, val recordedAt: Long?)

/** Indicates whether this authenticated delivery created a new local message or was an idempotent retry. */
data class DecryptedStoreResult(val deliveryId: String, val newlyStored: Boolean)

/**
 * Local E2EE message boundary shared by Owner and Client builds. Outbound text is encrypted with
 * an already-established, identity-pinned Signal session before any record is written. The local
 * outbox stores only the versioned Signal envelope. This class does not authenticate account/device
 * mappings, contact permission or a relay; callers may invoke it only with IDs from an authenticated
 * directory, bind the sender ID to the authenticated local device, and submit the returned opaque
 * bytes only through an authenticated ciphertext API. The result's ciphertext copy is owned by the
 * caller and should be cleared after transport use.
 *
 * Inbound processing checks authenticated transport-device mappings supplied by the caller, decrypts
 * only through the pinned Signal session, persists plaintext inside SealedLocalStore's encrypted
 * message record, and returns only after that write succeeds. A caller may acknowledge a relay copy
 * only after this method returns. Outbound ratchet advancement and ciphertext queue insertion, and
 * inbound ratchet advancement and encrypted message persistence, share one local SQLite transaction.
 * The caller must retain ciphertext until transport acknowledgment. No network transport is implemented.
 */
data class VerifiedPeerTransportDeviceWithTransport(
    val transportDeviceId: String,
    val peer: VerifiedPeerTransportDevice
)

class SignalMessagePipeline(
    private val localStore: SealedLocalStore,
    private val protocolStore: SealedSignalProtocolStore
) {
    private val crypto = SignalSessionCrypto(protocolStore)

    @Synchronized
    fun encryptAndQueue(
        deliveryId: String,
        localAccountId: String,
        localSignalDeviceId: Int,
        authenticatedLocalTransportDeviceId: String,
        senderTransportDeviceId: String,
        recipientAccountId: String,
        recipientSignalDeviceId: Int,
        recipientTransportDeviceId: String,
        plaintext: String,
        expiresAt: Long,
        conversationId: String? = null,
        now: Long = System.currentTimeMillis()
    ): QueuedSignalDelivery {
        require(deliveryId.isNotBlank() && deliveryId.length <= 100)
        require(authenticatedLocalTransportDeviceId.isNotBlank() && authenticatedLocalTransportDeviceId.length <= 200)
        require(senderTransportDeviceId == authenticatedLocalTransportDeviceId) {
            "Sender device does not match the authenticated local device"
        }
        require(recipientTransportDeviceId.isNotBlank() && recipientTransportDeviceId.length <= 200)
        require(recipientAccountId.isNotBlank() && recipientAccountId.length <= 128)
        require(plaintext.isNotBlank()) { "Empty messages are not supported" }
        require(expiresAt > now && expiresAt <= now + MAX_RELAY_RETENTION_MS) {
            "Relay retention must be positive and no longer than seven days"
        }
        val cleartext = plaintext.toByteArray(StandardCharsets.UTF_8)
        var wire: ByteArray? = null
        try {
            require(cleartext.size <= SignalCiphertextEnvelope.MAX_SERIALIZED_MESSAGE_BYTES) {
                "Message exceeds the supported size"
            }
            // encrypt() fails closed unless the local identity is provisioned and the peer identity
            // and session were established through the verified-bundle path.
            // Signal's ratchet advancement and the durable ciphertext outbox row must commit or
            // roll back together. Otherwise a crash between them could consume a ratchet message
            // without retaining the bytes needed to deliver it safely.
            wire = localStore.inTransaction {
                val envelope = crypto.encrypt(
                    localAccountId,
                    localSignalDeviceId,
                    recipientAccountId,
                    recipientSignalDeviceId,
                    cleartext
                )
                val encoded = SignalCiphertextEnvelopeCodec.encode(envelope)
                try {
                    localStore.queueCiphertext(
                        CiphertextDelivery(
                            deliveryId = deliveryId,
                            senderDeviceId = senderTransportDeviceId,
                            recipientDeviceId = recipientTransportDeviceId,
                            ciphertext = encoded,
                            expiresAt = expiresAt
                        ),
                        now
                    )
                    if (!conversationId.isNullOrBlank()) {
                        localStore.put("message", deliveryId, JSONObject()
                            .put("id", deliveryId).put("conversationId", conversationId)
                            .put("sender", "You").put("text", plaintext).put("createdAt", now)
                            .put("delivery", QUEUED_DELIVERY), conversationId, now)
                    }
                    encoded.copyOf()
                } finally { encoded.fill(0) }
            }
            return QueuedSignalDelivery(
                deliveryId = deliveryId,
                recipientDeviceId = recipientTransportDeviceId,
                expiresAt = expiresAt,
                ciphertext = requireNotNull(wire).copyOf()
            )
        } finally {
            cleartext.fill(0)
            wire?.fill(0)
        }
    }

    /**
     * Encrypt one logical message independently for every verified recipient device. For a group,
     * each member device gets its own pairwise Signal session and ciphertext copy; this is not a
     * Signal Sender-Key group protocol. Server-managed groups use a caller-validated authoritative
     * roster and persist their group ID with each ciphertext so the relay can enforce membership.
     * Ratchet advancement, per-device ciphertext outbox rows, delivery mappings and the single visible
     * local message commit atomically. A failure to encrypt for any device rolls the whole local
     * batch back; relay submission happens afterward and may yield partial delivery.
     */
    @Synchronized
    fun encryptAndQueueFanout(
        localAccountId: String,
        localSignalDeviceId: Int,
        authenticatedLocalTransportDeviceId: String,
        recipients: List<VerifiedPeerTransportDeviceWithTransport>,
        plaintext: String,
        conversationId: String,
        serverGroupId: String? = null,
        serverGroupMembershipVersion: Long? = null,
        now: Long = System.currentTimeMillis()
    ): List<QueuedSignalDelivery> {
        require(authenticatedLocalTransportDeviceId.isNotBlank())
        require(recipients.isNotEmpty() && recipients.size <= 127)
        require(recipients.map { it.transportDeviceId }.distinct().size == recipients.size) {
            "Recipient device list contains duplicates"
        }
        require(recipients.all { target ->
            target.peer.accountId.isNotBlank() && target.peer.signalDeviceId in 1..127 &&
                target.peer.conversationId == conversationId
        }) { "Every recipient must be a verified device linked to this conversation" }
        require(conversationId.isNotBlank() && plaintext.isNotBlank())
        require(serverGroupId == null || serverGroupId == conversationId) { "Server group ID must match this conversation" }
        require((serverGroupId == null) == (serverGroupMembershipVersion == null)) { "Server-group ciphertext must retain its roster version" }
        val cleartext = plaintext.toByteArray(StandardCharsets.UTF_8)
        val messageId = java.util.UUID.randomUUID().toString()
        val expiresAt = now + MAX_RELAY_RETENTION_MS
        val ciphertextCopies = ArrayList<QueuedSignalDelivery>(recipients.size)
        try {
            require(cleartext.size <= SignalCiphertextEnvelope.MAX_SERIALIZED_MESSAGE_BYTES) {
                "Message exceeds the supported size"
            }
            return localStore.inTransaction {
                val rows = ciphertextCopies
                val deviceStates = org.json.JSONArray()
                recipients.forEach { target ->
                    require(target.peer.signalDeviceId in 1..127 && target.transportDeviceId.isNotBlank())
                    require(target.peer.conversationId == conversationId)
                    val deliveryId = java.util.UUID.randomUUID().toString()
                    val envelope = crypto.encrypt(localAccountId, localSignalDeviceId,
                        target.peer.accountId, target.peer.signalDeviceId, cleartext)
                    val encoded = SignalCiphertextEnvelopeCodec.encode(envelope)
                    try {
                        localStore.queueCiphertext(CiphertextDelivery(deliveryId,
                            authenticatedLocalTransportDeviceId, target.transportDeviceId, encoded, expiresAt, serverGroupId, serverGroupMembershipVersion), now)
                        localStore.put("device", fanoutMappingId(deliveryId), JSONObject()
                            .put("fanoutMessageId", messageId).put("deliveryId", deliveryId)
                            .put("recipientTransportDeviceId", target.transportDeviceId), createdAt = now)
                        deviceStates.put(JSONObject().put("deliveryId", deliveryId)
                            .put("recipientTransportDeviceId", target.transportDeviceId)
                            .put("signalDeviceId", target.peer.signalDeviceId)
                            .put("expiresAt", expiresAt)
                            .put("state", QUEUED_DELIVERY))
                        rows += QueuedSignalDelivery(deliveryId, target.transportDeviceId, expiresAt, encoded.copyOf())
                    } finally { encoded.fill(0) }
                }
                localStore.put("message", messageId, JSONObject().put("id", messageId)
                    .put("conversationId", conversationId).put("sender", "You").put("text", plaintext)
                    .put("createdAt", now).put("delivery", QUEUED_DELIVERY)
                    .put("deviceDeliveries", deviceStates), conversationId, now)
                rows
            }
        } catch (failure: Throwable) {
            ciphertextCopies.forEach { it.ciphertext.fill(0) }
            throw failure
        } finally { cleartext.fill(0) }
    }

    /**
     * Decrypt and durably save one authenticated relay delivery. The network caller must derive the
     * authenticated local and sender device IDs from its verified token/device directory, then pass
     * those mappings here. Repeated delivery IDs
     * are idempotent only when an existing message is already marked as received encrypted content.
     */
    @Synchronized
    fun decryptAndStore(
        delivery: CiphertextDelivery,
        authenticatedLocalTransportDeviceId: String,
        authenticatedSenderTransportDeviceId: String,
        localAccountId: String,
        localSignalDeviceId: Int,
        senderAccountId: String,
        senderSignalDeviceId: Int,
        conversationId: String,
        receivedAt: Long = System.currentTimeMillis()
    ): DecryptedStoreResult {
        require(delivery.deliveryId.isNotBlank() && delivery.deliveryId.length <= 100)
        require(authenticatedLocalTransportDeviceId.isNotBlank() && authenticatedLocalTransportDeviceId.length <= 200)
        require(authenticatedSenderTransportDeviceId.isNotBlank() && authenticatedSenderTransportDeviceId.length <= 200)
        require(delivery.senderDeviceId == authenticatedSenderTransportDeviceId) {
            "Relay sender does not match the authenticated sender-device mapping"
        }
        require(delivery.recipientDeviceId == authenticatedLocalTransportDeviceId) {
            "Relay recipient does not match this authenticated device"
        }
        require(delivery.expiresAt > receivedAt) { "Ciphertext delivery has expired" }
        require(conversationId.isNotBlank() && conversationId.length <= 200)
        require(senderAccountId.isNotBlank() && senderAccountId.length <= 128)
        return localStore.inTransaction {
            val ciphertextDigest = MessageDigest.getInstance("SHA-256").digest(delivery.ciphertext)
            val ciphertextDigestBase64 = try {
                Base64.getEncoder().encodeToString(ciphertextDigest)
            } finally { ciphertextDigest.fill(0) }
            val existing = localStore.get("message", delivery.deliveryId)
            if (existing != null) {
                check(existing.optString("delivery") == RECEIVED_DELIVERY &&
                    existing.optString("conversationId") == conversationId &&
                    existing.optString("sender") == senderAccountId &&
                    existing.optString("ciphertextSha256") == ciphertextDigestBase64) {
                    "Delivery ID already belongs to different encrypted content"
                }
                return@inTransaction DecryptedStoreResult(delivery.deliveryId, newlyStored = false)
            }

            val envelope = SignalCiphertextEnvelopeCodec.decode(delivery.ciphertext)
            // SessionCipher may advance session/pre-key state. Persist that change and the
            // encrypted local message atomically, so a retry after a crash is idempotent.
            val plaintext = crypto.decrypt(
                localAccountId,
                localSignalDeviceId,
                senderAccountId,
                senderSignalDeviceId,
                envelope
            )
            try {
                val text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(plaintext))
                    .toString()
                require(text.isNotBlank()) { "Empty messages are not supported" }
                val message = JSONObject()
                    .put("id", delivery.deliveryId)
                    .put("conversationId", conversationId)
                    .put("sender", senderAccountId)
                    .put("text", text)
                    .put("createdAt", receivedAt)
                    .put("delivery", RECEIVED_DELIVERY)
                    .put("ciphertextSha256", ciphertextDigestBase64)
                localStore.put("message", delivery.deliveryId, message, conversationId, receivedAt)
                DecryptedStoreResult(delivery.deliveryId, newlyStored = true)
            } finally {
                plaintext.fill(0)
            }
        }
    }

    /** Called only after the relay RPC returns the matching delivery ID. */
    @Synchronized
    fun markRelayAccepted(deliveryId: String, recipientTransportDeviceId: String, acceptedAt: Long = System.currentTimeMillis()) {
        localStore.inTransaction {
            val fanoutId = fanoutMappingId(deliveryId)
            val fanout = localStore.get("device", fanoutId)
            val messageId = fanout?.optString("fanoutMessageId").orEmpty().ifBlank { deliveryId }
            val message = localStore.get("message", messageId)
            if (fanout != null) check(message != null) { "Fan-out message record is missing" }
            if (message != null) {
                val states = message.optJSONArray("deviceDeliveries")
                if (fanout != null) {
                    check(fanout.optString("recipientTransportDeviceId") == recipientTransportDeviceId) {
                        "Relay recipient does not match the fan-out device mapping"
                    }
                    check(states != null) { "Fan-out message is missing per-device delivery state" }
                    var matched = false
                    for (index in 0 until states.length()) {
                        val state = states.optJSONObject(index) ?: continue
                        if (state.optString("deliveryId") == deliveryId &&
                            state.optString("recipientTransportDeviceId") == recipientTransportDeviceId) {
                            state.put("state", RELAY_ACCEPTED_DELIVERY).put("relayAcceptedAt", acceptedAt)
                            matched = true
                            break
                        }
                    }
                    check(matched) { "Fan-out delivery is not mapped to this message" }
                    val accepted = (0 until states.length()).count { states.optJSONObject(it)?.optString("state") == RELAY_ACCEPTED_DELIVERY }
                    val aggregate = when {
                        accepted == states.length() -> RELAY_ACCEPTED_DELIVERY
                        accepted > 0 -> PARTIAL_DELIVERY
                        else -> QUEUED_DELIVERY
                    }
                    message.put("deviceDeliveries", states).put("delivery", aggregate)
                } else {
                    check(message.optString("delivery") == QUEUED_DELIVERY) { "Message is not awaiting relay acceptance" }
                    message.put("delivery", RELAY_ACCEPTED_DELIVERY).put("relayAcceptedAt", acceptedAt)
                }
                localStore.put("message", messageId, message, message.optString("conversationId"), message.optLong("createdAt", acceptedAt))
            }
            check(localStore.acknowledgeCiphertext(deliveryId, recipientTransportDeviceId)) {
                "Relay accepted the message but its local ciphertext copy could not be cleared"
            }
            if (fanout != null) check(localStore.delete("device", fanoutId)) { "Fan-out mapping could not be cleared" }
        }
    }

    /** Apply authenticated sender-visible relay receipts to their exact per-device outbox entries. */
    @Synchronized
    fun applyDeliveryReceipts(receipts: Map<String, RelayDeliveryReceipt>): Int = localStore.inTransaction {
        var changed = 0
        for (message in localStore.list("message")) {
            val states = message.optJSONArray("deviceDeliveries") ?: continue
            var messageChanged = false
            for (index in 0 until states.length()) {
                val state = states.optJSONObject(index) ?: continue
                val deliveryId = state.optString("deliveryId")
                val receipt = receipts[deliveryId] ?: continue
                check(state.optString("recipientTransportDeviceId") == receipt.recipientDeviceId) {
                    "Relay status recipient does not match the locally verified device mapping"
                }
                val previous = state.optString("state")
                val next = when (receipt.status) {
                    "acknowledged" -> "recipient_stored"
                    "expired" -> "relay_expired"
                    "pending" -> RELAY_ACCEPTED_DELIVERY
                    else -> error("Relay returned an unsupported delivery status")
                }
                if (previous == next) continue
                if (previous == "recipient_stored" || previous == "relay_expired") {
                    // Terminal receipts cannot regress or be replaced by a contradictory result.
                    if (next == RELAY_ACCEPTED_DELIVERY) continue
                    error("Relay returned a conflicting status for a terminal delivery receipt")
                }
                check(previous == RELAY_ACCEPTED_DELIVERY) {
                    "Relay receipt cannot advance a delivery that was not accepted"
                }
                state.put("state", next)
                receipt.recordedAt?.let { state.put(if (next == "recipient_stored") "recipientStoredAt" else "relayExpiredAt", it) }
                messageChanged = true
            }
            if (messageChanged) {
                message.put("deviceDeliveries", states)
                message.put("delivery", aggregateDeliveryState(states))
                message.put("deliveryStatusCheckedAt", System.currentTimeMillis())
                localStore.put("message", message.getString("id"), message,
                    message.optString("conversationId"), message.optLong("createdAt", System.currentTimeMillis()))
                changed++
            }
        }
        changed
    }

    private fun aggregateDeliveryState(states: org.json.JSONArray): String {
        val values = (0 until states.length()).mapNotNull { states.optJSONObject(it)?.optString("state") }
        if (values.isEmpty()) return QUEUED_DELIVERY
        val stored = values.count { it == "recipient_stored" }
        val expired = values.count { it == "relay_expired" }
        val accepted = values.count { it == RELAY_ACCEPTED_DELIVERY || it == "recipient_stored" }
        return when {
            stored == values.size -> "recipient_stored_all_devices"
            stored > 0 -> "recipient_stored_some_devices"
            expired == values.size -> "encrypted_expired"
            expired > 0 -> "encrypted_partial_expiry"
            accepted == values.size -> RELAY_ACCEPTED_DELIVERY
            accepted > 0 -> PARTIAL_DELIVERY
            else -> QUEUED_DELIVERY
        }
    }

    private fun fanoutMappingId(deliveryId: String) = "fanout_delivery:$deliveryId"

    private companion object {
        const val QUEUED_DELIVERY = "encrypted_queued_not_delivered"
        const val RELAY_ACCEPTED_DELIVERY = "relay_accepted_recipient_not_confirmed"
        const val PARTIAL_DELIVERY = "encrypted_partially_accepted"
        const val RECEIVED_DELIVERY = "received_encrypted_local"
        const val MAX_RELAY_RETENTION_MS = 7L * 24 * 60 * 60 * 1000
    }
}
