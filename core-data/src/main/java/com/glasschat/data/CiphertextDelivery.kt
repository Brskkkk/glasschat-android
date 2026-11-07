package com.glasschat.data

/** One per-recipient-device encrypted delivery copy; ciphertext is never decoded by the relay. */
data class CiphertextDelivery(
    val deliveryId: String,
    val senderDeviceId: String,
    val recipientDeviceId: String,
    val ciphertext: ByteArray,
    val expiresAt: Long
)
