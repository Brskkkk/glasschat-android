package com.glasschat.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import org.signal.libsignal.protocol.message.CiphertextMessage

class SignalCiphertextEnvelopeCodecTest {
    @Test
    fun roundTripPreservesTypeAndCiphertextBytes() {
        val expected = byteArrayOf(0, 1, 2, 0x7f, -1)
        val source = expected.copyOf()
        val encoded = SignalCiphertextEnvelopeCodec.encode(
            SignalCiphertextEnvelope(CiphertextMessage.WHISPER_TYPE, source)
        )
        source.fill(0)

        val decoded = SignalCiphertextEnvelopeCodec.decode(encoded)
        assertEquals(CiphertextMessage.WHISPER_TYPE, decoded.type)
        assertArrayEquals(expected, decoded.serializedMessage)
    }

    @Test
    fun envelopeAndAccessorDefensivelyCopyPayload() {
        val original = byteArrayOf(1, 2, 3)
        val envelope = SignalCiphertextEnvelope(CiphertextMessage.PREKEY_TYPE, original)
        original[0] = 9
        val firstRead = envelope.serializedMessage
        assertEquals(1, firstRead[0].toInt())
        firstRead[1] = 9
        assertArrayEquals(byteArrayOf(1, 2, 3), envelope.serializedMessage)
    }

    @Test
    fun rejectsTruncatedHeader() {
        assertRejected { SignalCiphertextEnvelopeCodec.decode(ByteArray(9)) }
    }

    @Test
    fun rejectsWrongMagicAndUnsupportedVersion() {
        val valid = encodedSample()
        val wrongMagic = valid.copyOf().also { it[0] = 0 }
        assertRejected { SignalCiphertextEnvelopeCodec.decode(wrongMagic) }
        val wrongVersion = valid.copyOf().also { it[4] = 2 }
        assertRejected { SignalCiphertextEnvelopeCodec.decode(wrongVersion) }
    }

    @Test
    fun rejectsUnsupportedSignalTypeAndInvalidPayloadLength() {
        val valid = encodedSample()
        val unsupportedType = valid.copyOf().also { it[5] = 99 }
        assertRejected { SignalCiphertextEnvelopeCodec.decode(unsupportedType) }
        val wrongLength = valid.copyOf().also { it[9] = (it[9] + 1).toByte() }
        assertRejected { SignalCiphertextEnvelopeCodec.decode(wrongLength) }
        val emptyPayload = valid.copyOfRange(0, 10).also { it[9] = 0 }
        assertRejected { SignalCiphertextEnvelopeCodec.decode(emptyPayload) }
    }

    @Test
    fun rejectsTrailingDataAndOversizeWirePayload() {
        val trailing = encodedSample() + byteArrayOf(0)
        assertRejected { SignalCiphertextEnvelopeCodec.decode(trailing) }
        val oversized = ByteArray(10 + SignalCiphertextEnvelope.MAX_SERIALIZED_MESSAGE_BYTES + 1)
        assertRejected { SignalCiphertextEnvelopeCodec.decode(oversized) }
    }

    @Test
    fun rejectsUnsupportedEnvelopeTypesAndEmptyCiphertext() {
        assertRejected { SignalCiphertextEnvelope(0, byteArrayOf(1)) }
        assertRejected { SignalCiphertextEnvelope(CiphertextMessage.WHISPER_TYPE, ByteArray(0)) }
    }

    private fun encodedSample(): ByteArray = SignalCiphertextEnvelopeCodec.encode(
        SignalCiphertextEnvelope(CiphertextMessage.WHISPER_TYPE, byteArrayOf(10, 20, 30))
    )

    private fun assertRejected(action: () -> Unit) {
        try {
            action()
        } catch (_: IllegalArgumentException) {
            return
        }
        throw AssertionError("Expected malformed ciphertext to be rejected")
    }
}
