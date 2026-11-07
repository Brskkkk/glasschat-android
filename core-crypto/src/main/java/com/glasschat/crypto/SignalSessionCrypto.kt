package com.glasschat.crypto

import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.message.CiphertextMessage
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.message.SignalMessage
import org.signal.libsignal.protocol.state.PreKeyBundle

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
 * Thin adapter over Signal's maintained implementation. It requires the Keystore-encrypted store
 * and an expected peer identity key that the caller obtained through authenticated account lookup
 * and explicit contact verification. It checks both signatures in the supplied bundle and pins the
 * identity before session setup. It cannot authenticate the transport; the calling runtime must supply authenticated directory data,
 * explicit fingerprint verification, and a ciphertext-only transport.
 *
 * Calls are serialized per instance because libsignal's SessionBuilder and SessionCipher are
 * documented as not thread-safe. Use a separate adapter per protocol store, not per coroutine.
 */
class SignalSessionCrypto(private val protocolStore: SealedSignalProtocolStore) {
    @Synchronized
    fun establishSession(
        localAccountId: String,
        localSignalDeviceId: Int,
        remoteAccountId: String,
        remoteSignalDeviceId: Int,
        verifiedBundle: PreKeyBundle,
        trustedIdentityKey: IdentityKey
    ) {
        protocolStore.requireProvisionedIdentity(localAccountId, localSignalDeviceId)
        val local = address(localAccountId, localSignalDeviceId)
        val remote = address(remoteAccountId, remoteSignalDeviceId)
        require(verifiedBundle.deviceId == remoteSignalDeviceId) { "Pre-key bundle device does not match the authenticated peer device" }
        require(verifiedBundle.identityKey == trustedIdentityKey) { "Pre-key bundle identity does not match the verified contact identity" }
        val signedKeyBytes = verifiedBundle.signedPreKey.serialize()
        val signedKeySignature = verifiedBundle.signedPreKeySignature
        val kyberKeyBytes = verifiedBundle.kyberPreKey.serialize()
        val kyberKeySignature = verifiedBundle.kyberPreKeySignature
        try {
            require(trustedIdentityKey.publicKey.verifySignature(signedKeyBytes, signedKeySignature)) {
                "Signal signed pre-key signature is invalid"
            }
            require(trustedIdentityKey.publicKey.verifySignature(kyberKeyBytes, kyberKeySignature)) {
                "Signal Kyber pre-key signature is invalid"
            }
        } finally {
            signedKeyBytes.fill(0)
            signedKeySignature.fill(0)
            kyberKeyBytes.fill(0)
            kyberKeySignature.fill(0)
        }
        protocolStore.pinVerifiedIdentity(remote, trustedIdentityKey)
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
        protocolStore.requireProvisionedIdentity(localAccountId, localSignalDeviceId)
        val local = address(localAccountId, localSignalDeviceId)
        val remote = address(remoteAccountId, remoteSignalDeviceId)
        check(protocolStore.getIdentity(remote) != null) { "Peer identity has not been verified" }
        check(protocolStore.containsSession(remote)) { "No verified Signal session is available" }
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
        protocolStore.requireProvisionedIdentity(localAccountId, localSignalDeviceId)
        val local = address(localAccountId, localSignalDeviceId)
        val remote = address(remoteAccountId, remoteSignalDeviceId)
        check(protocolStore.getIdentity(remote) != null) { "Peer identity has not been verified" }
        check(protocolStore.containsSession(remote)) { "No verified Signal session is available" }
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
