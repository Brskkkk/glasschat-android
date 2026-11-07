package com.glasschat.crypto

/** Public-only Signal pre-key material. Byte-array accessors always return defensive copies. */
class SignalPublicKeyMaterial(
    val id: Int,
    publicKey: ByteArray,
    signature: ByteArray? = null
) {
    private val publicKeyBytes = publicKey.copyOf()
    private val signatureBytes = signature?.copyOf()

    val publicKey: ByteArray get() = publicKeyBytes.copyOf()
    val signature: ByteArray? get() = signatureBytes?.copyOf()
}

/**
 * Public-only initial upload material for an authenticated account/device. It is not itself proof
 * of account ownership; only an authenticated server operation may publish it under that identity.
 */
class SignalPublicPreKeyBundle(
    val registrationId: Int,
    val deviceId: Int,
    identityKey: ByteArray,
    val signedPreKey: SignalPublicKeyMaterial,
    val kyberLastResortPreKey: SignalPublicKeyMaterial,
    oneTimePreKeys: List<SignalPublicKeyMaterial>
) {
    private val identityKeyBytes = identityKey.copyOf()
    private val oneTime = oneTimePreKeys.toList()

    val identityKey: ByteArray get() = identityKeyBytes.copyOf()
    val oneTimePreKeys: List<SignalPublicKeyMaterial> get() = oneTime.toList()
}
