package com.glasschat.ui

import android.content.ContentResolver
import android.net.Uri
import android.provider.OpenableColumns
import org.json.JSONObject
import java.util.Base64

/** Small inline file payload; the enclosing message must still pass through Signal encryption. */
internal data class InlineEncryptedAttachment(
    val fileName: String,
    val mimeType: String,
    val byteCount: Int,
    val serialized: String
)

internal object InlineEncryptedAttachmentCodec {
    private const val PREFIX = "glasschat-attachment-v1:"
    const val MAX_FILE_BYTES = 512 * 1024
    private const val MAX_NAME_CHARS = 180
    private const val MAX_MIME_CHARS = 120

    fun encode(fileName: String, mimeType: String, bytes: ByteArray): InlineEncryptedAttachment {
        require(bytes.isNotEmpty() && bytes.size <= MAX_FILE_BYTES) { "Choose a non-empty file no larger than 512 KiB." }
        val safeName = cleanName(fileName)
        val safeMime = mimeType.take(MAX_MIME_CHARS).ifBlank { "application/octet-stream" }
        val payload = JSONObject().put("version", 1).put("name", safeName)
            .put("mime", safeMime).put("data", Base64.getEncoder().encodeToString(bytes))
        return InlineEncryptedAttachment(safeName, safeMime, bytes.size, PREFIX + payload.toString())
    }

    fun isAttachment(text: String): Boolean = text.startsWith(PREFIX)

    fun describe(text: String): InlineEncryptedAttachment? = try {
        val json = parse(text)
        val encoded = json.getString("data")
        val padding = when {
            encoded.endsWith("==") -> 2
            encoded.endsWith("=") -> 1
            else -> 0
        }
        val size = (encoded.length.toLong() / 4L * 3L - padding).coerceAtLeast(0L).toInt()
        InlineEncryptedAttachment(cleanName(json.getString("name")), json.getString("mime").take(MAX_MIME_CHARS), size, text)
    } catch (_: Exception) { null }

    fun decode(text: String): Pair<InlineEncryptedAttachment, ByteArray> {
        val json = parse(text)
        val bytes = Base64.getDecoder().decode(json.getString("data"))
        require(bytes.isNotEmpty() && bytes.size <= MAX_FILE_BYTES) { "Attachment size is invalid." }
        val name = cleanName(json.getString("name"))
        val mime = json.getString("mime").take(MAX_MIME_CHARS)
        return InlineEncryptedAttachment(name, mime, bytes.size, text) to bytes
    }

    fun readFrom(resolver: ContentResolver, uri: Uri): InlineEncryptedAttachment {
        val name = resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) cursor.getString(0) else null
        } ?: "attachment"
        val mime = resolver.getType(uri) ?: "application/octet-stream"
        val input = resolver.openInputStream(uri) ?: error("Could not open that file.")
        val raw = ByteArray(MAX_FILE_BYTES)
        val buffer = ByteArray(16 * 1024)
        var size = 0
        try {
            input.use { stream ->
                while (true) {
                    val count = stream.read(buffer)
                    if (count < 0) break
                    require(size + count <= MAX_FILE_BYTES) { "Choose a file no larger than 512 KiB." }
                    if (count > 0) {
                        System.arraycopy(buffer, 0, raw, size, count)
                        size += count
                    }
                }
            }
            val selectedBytes = raw.copyOf(size)
            return try { encode(name, mime, selectedBytes) } finally { selectedBytes.fill(0) }
        } finally {
            buffer.fill(0)
            raw.fill(0)
        }
    }

    private fun cleanName(value: String): String = value.substringAfterLast('/').substringAfterLast('\\')
        .filterNot { it.isISOControl() }.take(MAX_NAME_CHARS).ifBlank { "attachment" }

    private fun parse(text: String): JSONObject {
        require(text.startsWith(PREFIX)) { "This message is not an attachment." }
        val json = JSONObject(text.substring(PREFIX.length))
        require(json.optInt("version") == 1) { "Unsupported attachment version." }
        val encoded = json.getString("data")
        require(encoded.length in 4..((MAX_FILE_BYTES + 2) / 3 * 4 + 4) && encoded.length % 4 == 0) {
            "Attachment data size is invalid."
        }
        require(json.getString("name").length <= MAX_NAME_CHARS && json.getString("mime").length <= MAX_MIME_CHARS) {
            "Attachment metadata is too long."
        }
        return json
    }
}
