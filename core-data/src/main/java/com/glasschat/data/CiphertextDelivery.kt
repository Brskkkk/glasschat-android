package com.glasschat.data

/** One per-recipient-device encrypted delivery copy; ciphertext is never decoded by the relay. */
data class CiphertextDelivery(
    val deliveryId: String,
    val senderDeviceId: String,
    val recipientDeviceId: String,
    val ciphertext: ByteArray,
    val expiresAt: Long,
    /** Optional server-managed group ID; null for direct and local-only groups. */
    val groupId: String? = null,
    /** Group roster snapshot used to authorize this ciphertext; null for non-server-group sends. */
    val groupMembershipVersion: Long? = null
)
