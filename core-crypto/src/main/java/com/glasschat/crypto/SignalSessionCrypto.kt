package com.glasschat.crypto

import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.message.CiphertextMessage
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.message.SignalMessage
import org.signal.libsignal.protocol.state.PreKeyBundle
import org.signal.libsignal.protocol.state.SignalProtocolStore

/**
 * Opaque Signal Protocol ciphertext for exactly one recipient device. The type byte is required
 * by the Signal protocol to distinguish an initial pre-key message from a ratcheted message;
 * message bytes are never decoded or transformed by the relay.
 */
class SignalCiphertextEnvelope(type: Int, serializedMessage: ByteArray) {
    val type: Int = type
    private val payload = serializedMessage.copyOf()

    init {
        require(type == CiphertextMessage.PREKEY_TYPE || type == CiphertextMessage.WHISPER_TYPE) {
            "Only Signal pre-key and whisper ciphertexts are accepted"
        }
        require(payload.isNotEmpty() && payload.size <= MAX_SERIALIZED_MESSAGE_BYTES) {
            "Signal ciphertext must fit the supported message size"
        }
    }

    val serializedMessage: ByteArray get() = payload.copyOf()

    companion object {
        const val MAX_SERIALIZED_MESSAGE_BYTES = 1024 * 1024
    }
}

/**
 * Thin adapter over Signal's maintained implementation. A caller must supply a durable,
 * encrypted SignalProtocolStore and an authenticated, verified PreKeyBundle. This class does
 * not implement keys, ratchets, serialization, or cryptography itself.
 *
 * Calls are serialized per instance because libsignal's SessionBuilder and SessionCipher are
 * documented as not thread-safe. Use a separate adapter per protocol store, not per coroutine.
 */
class SignalSessionCrypto(private val protocolStore: SignalProtocolStore) {
    @Synchronized
    fun establishSession(
        localAccountId: String,
        localSignalDeviceId: Int,
        remoteAccountId: String,
        remoteSignalDeviceId: Int,
        verifiedBundle: PreKeyBundle
    ) {
        val local = address(localAccountId, localSignalDeviceId)
        val remote = address(remoteAccountId, remoteSignalDeviceId)
        SessionBuilder(protocolStore, remote, local).process(verifiedBundle)
    }

    @Synchronized
    fun encrypt(
        localAccountId: String,
        localSignalDeviceId: Int,
        remoteAccountId: String,
        remoteSignalDeviceId: Int,
        plaintext: ByteArray
    ): SignalCiphertextEnvelope {
        require(plaintext.isNotEmpty()) { "Empty messages are not supported" }
        require(plaintext.size <= SignalCiphertextEnvelope.MAX_SERIALIZED_MESSAGE_BYTES) {
            "Message exceeds the supported size"
        }
        val local = address(localAccountId, localSignalDeviceId)
        val remote = address(remoteAccountId, remoteSignalDeviceId)
        val plaintextCopy = plaintext.copyOf()
        try {
            val message = SessionCipher(protocolStore, local, remote).encrypt(plaintextCopy)
            val serialized = message.serialize()
            try {
                return SignalCiphertextEnvelope(message.type, serialized)
            } finally {
                serialized.fill(0)
            }
        } finally {
            plaintextCopy.fill(0)
        }
    }

    @Synchronized
    fun decrypt(
        localAccountId: String,
        localSignalDeviceId: Int,
        remoteAccountId: String,
        remoteSignalDeviceId: Int,
        envelope: SignalCiphertextEnvelope
    ): ByteArray {
        val local = address(localAccountId, localSignalDeviceId)
        val remote = address(remoteAccountId, remoteSignalDeviceId)
        val cipher = SessionCipher(protocolStore, local, remote)
        val serialized = envelope.serializedMessage
        try {
            return when (envelope.type) {
                CiphertextMessage.PREKEY_TYPE -> cipher.decrypt(PreKeySignalMessage(serialized))
                CiphertextMessage.WHISPER_TYPE -> cipher.decrypt(SignalMessage(serialized))
                else -> error("Unsupported Signal ciphertext type")
            }
        } finally {
            serialized.fill(0)
        }
    }

    private fun address(accountId: String, signalDeviceId: Int): SignalProtocolAddress {
        require(accountId.isNotBlank() && accountId.length <= 128) { "Invalid account identifier" }
        require(signalDeviceId in MIN_SIGNAL_DEVICE_ID..MAX_SIGNAL_DEVICE_ID) {
            "Signal device ID must be between 1 and 127"
        }
        return SignalProtocolAddress(accountId, signalDeviceId)
    }

    private companion object {
        const val MIN_SIGNAL_DEVICE_ID = 1
        const val MAX_SIGNAL_DEVICE_ID = 127
    }
}
