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
 * only after this method returns. Session advancement plus message persistence is not transactional;
 * callers must retain the ciphertext and handle retry/replay safely. No network transport is implemented.
 */
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
            val envelope = crypto.encrypt(
                localAccountId,
                localSignalDeviceId,
                recipientAccountId,
                recipientSignalDeviceId,
                cleartext
            )
            wire = SignalCiphertextEnvelopeCodec.encode(envelope)
            localStore.queueCiphertext(
                CiphertextDelivery(
                    deliveryId = deliveryId,
                    senderDeviceId = senderTransportDeviceId,
                    recipientDeviceId = recipientTransportDeviceId,
                    ciphertext = wire,
                    expiresAt = expiresAt
                ),
                now
            )
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
    ): String {
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
        val existing = localStore.get("message", delivery.deliveryId)
        if (existing != null) {
            check(existing.optString("delivery") == RECEIVED_DELIVERY &&
                existing.optString("conversationId") == conversationId) {
                "Delivery ID already belongs to a different local message"
            }
            return delivery.deliveryId
        }

        val envelope = SignalCiphertextEnvelopeCodec.decode(delivery.ciphertext)
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
            localStore.put("message", delivery.deliveryId, message, conversationId, receivedAt)
            return delivery.deliveryId
        } finally {
            plaintext.fill(0)
        }
    }

    private companion object {
        const val RECEIVED_DELIVERY = "received_encrypted_local"
        const val MAX_RELAY_RETENTION_MS = 7L * 24 * 60 * 60 * 1000
    }
}
