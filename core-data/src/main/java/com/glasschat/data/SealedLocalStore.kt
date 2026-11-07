package com.glasschat.data

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Small local-first encrypted record store. Every application payload is AES-GCM encrypted
 * with a non-exportable Android Keystore key before it enters SQLite. Index columns are limited
 * to opaque record ids, types, conversation ids and timestamps; those metadata are not encrypted.
 * This protects data at rest only: it is not an end-to-end messaging protocol.
 *
 * Call methods off the main thread. SQL transactions make a record write atomic. If the Keystore
 * key is lost or invalidated, reads fail closed; this class never wipes a database to recover.
 */
class SealedLocalStore(context: Context) : SQLiteOpenHelper(
    context.applicationContext,
    DATABASE_NAME,
    null,
    DATABASE_VERSION
) {
    private val appContext = context.applicationContext
    private val lock = Any()
    private val key: SecretKey by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { getOrCreateKey() }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL("CREATE TABLE records (kind TEXT NOT NULL, id TEXT NOT NULL, conversation_id TEXT, created_at INTEGER NOT NULL, payload BLOB NOT NULL, PRIMARY KEY(kind,id))")
        db.execSQL("CREATE INDEX records_by_conversation ON records(kind,conversation_id,created_at)")
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        if (oldVersion == 1 && newVersion == 2) {
            // Version 2 binds AES-GCM ciphertext to its row identity and metadata. SQLiteOpenHelper
            // runs this upgrade transactionally; if any row cannot be opened, the whole migration
            // rolls back and the original database remains intact.
            migrateV1ToV2(db)
            return
        }
        throw IllegalStateException("No safe migration from local store version $oldVersion to $newVersion")
    }

    fun put(kind: String, id: String, json: JSONObject, conversationId: String? = null, createdAt: Long = System.currentTimeMillis()) {
        require(kind in ALLOWED_KINDS) { "Unknown record kind" }
        require(id.isNotBlank() && id.length <= 200) { "Invalid record id" }
        require(conversationId == null || conversationId.length <= 200) { "Invalid conversation id" }
        val encrypted = encrypt(kind, id, conversationId, createdAt, json.toString().toByteArray(StandardCharsets.UTF_8))
        synchronized(lock) {
            writableDatabase.beginTransaction()
            try {
                val values = ContentValues().apply {
                    put("kind", kind); put("id", id); put("conversation_id", conversationId)
                    put("created_at", createdAt); put("payload", encrypted)
                }
                check(writableDatabase.insertWithOnConflict("records", null, values, SQLiteDatabase.CONFLICT_REPLACE) != -1L) {
                    "Could not save encrypted record"
                }
                writableDatabase.setTransactionSuccessful()
            } finally { writableDatabase.endTransaction() }
        }
    }

    fun get(kind: String, id: String): JSONObject? {
        require(kind in ALLOWED_KINDS)
        synchronized(lock) {
            readableDatabase.rawQuery("SELECT conversation_id,created_at,payload FROM records WHERE kind=? AND id=?", arrayOf(kind, id)).use { cursor ->
                if (!cursor.moveToFirst()) return null
                val conversationId = if (cursor.isNull(0)) null else cursor.getString(0)
                val createdAt = cursor.getLong(1)
                val payload = decrypt(kind, id, conversationId, createdAt, cursor.getBlob(2))
                return JSONObject(String(payload, StandardCharsets.UTF_8))
            }
        }
    }

    fun list(kind: String, conversationId: String? = null): List<JSONObject> {
        require(kind in ALLOWED_KINDS)
        synchronized(lock) {
            val sql = if (conversationId == null) "SELECT id,conversation_id,created_at,payload FROM records WHERE kind=? ORDER BY created_at,id" else "SELECT id,conversation_id,created_at,payload FROM records WHERE kind=? AND conversation_id=? ORDER BY created_at,id"
            val args = if (conversationId == null) arrayOf(kind) else arrayOf(kind, conversationId)
            readableDatabase.rawQuery(sql, args).use { cursor ->
                val result = ArrayList<JSONObject>(cursor.count)
                while (cursor.moveToNext()) {
                    val id = cursor.getString(0)
                    val rowConversationId = if (cursor.isNull(1)) null else cursor.getString(1)
                    val createdAt = cursor.getLong(2)
                    val payload = decrypt(kind, id, rowConversationId, createdAt, cursor.getBlob(3))
                    result += JSONObject(String(payload, StandardCharsets.UTF_8))
                }
                return result
            }
        }
    }

    fun searchMessages(query: String, limit: Int = 100): List<JSONObject> {
        require(query.isNotBlank() && query.length <= 200)
        require(limit in 1..500)
        val needle = query.trim().lowercase()
        synchronized(lock) {
            readableDatabase.rawQuery("SELECT id,conversation_id,created_at,payload FROM records WHERE kind='message' ORDER BY created_at DESC LIMIT ?", arrayOf(limit.toString())).use { cursor ->
                val hits = ArrayList<JSONObject>()
                while (cursor.moveToNext()) {
                    val id = cursor.getString(0)
                    val conversationId = if (cursor.isNull(1)) null else cursor.getString(1)
                    val createdAt = cursor.getLong(2)
                    val payload = decrypt("message", id, conversationId, createdAt, cursor.getBlob(3))
                    val item = JSONObject(String(payload, StandardCharsets.UTF_8))
                    if (item.optString("text").lowercase().contains(needle)) hits += item
                }
                return hits
            }
        }
    }

    /** Local editing helper. This never edits a message on another device or on a relay. */
    fun editLocalMessage(messageId: String, replacementText: String, editedAt: Long = System.currentTimeMillis()): Boolean {
        require(messageId.isNotBlank() && replacementText.isNotBlank() && replacementText.length <= 20_000)
        synchronized(lock) {
            val current = get("message", messageId) ?: return false
            val priorText = current.optString("text")
            val history = current.optJSONArray("editHistory") ?: org.json.JSONArray()
            if (priorText.isNotEmpty()) history.put(JSONObject().put("text", priorText).put("at", editedAt))
            current.put("text", replacementText).put("editedAt", editedAt).put("editHistory", history)
            writableDatabase.beginTransaction()
            try {
                val values = ContentValues().apply {
                    put("kind", "message")
                    put("id", messageId)
                    put("conversation_id", current.optString("conversationId").ifBlank { null })
                    put("created_at", current.optLong("createdAt", editedAt))
                    put("payload", encrypt("message", messageId, current.optString("conversationId").ifBlank { null }, current.optLong("createdAt", editedAt), current.toString().toByteArray(StandardCharsets.UTF_8)))
                }
                check(writableDatabase.insertWithOnConflict("records", null, values, SQLiteDatabase.CONFLICT_REPLACE) != -1L) {
                    "Could not update local message"
                }
                writableDatabase.setTransactionSuccessful()
            } finally { writableDatabase.endTransaction() }
            return true
        }
    }

    /** Deletes only this device's local copy. It does not retract a delivered message. */
    fun deleteLocalMessage(messageId: String): Boolean = delete("message", messageId)

    /** Idempotently add/remove a local reaction by actor and emoji. */
    fun setLocalReaction(messageId: String, actorId: String, emoji: String, active: Boolean, now: Long = System.currentTimeMillis()): Boolean {
        require(messageId.isNotBlank() && actorId.isNotBlank() && emoji.isNotBlank() && emoji.length <= 16)
        val id = "$messageId:$actorId:$emoji"
        if (!active) return delete("reaction", id)
        val reaction = JSONObject().put("id", id).put("messageId", messageId).put("actorId", actorId).put("emoji", emoji).put("createdAt", now)
        put("reaction", id, reaction, createdAt = now)
        return true
    }

    /** Drafts are local-only and keyed by conversation. Blank text removes the draft. */
    fun saveLocalDraft(conversationId: String, text: String, now: Long = System.currentTimeMillis()) {
        require(conversationId.isNotBlank() && conversationId.length <= 200 && text.length <= 20_000)
        if (text.isBlank()) { delete("draft", conversationId); return }
        put("draft", conversationId, JSONObject().put("conversationId", conversationId).put("text", text).put("updatedAt", now), conversationId, now)
    }

    /** Local conversation flags; they are not synchronized to other participants. */
    fun setLocalConversationFlag(conversationId: String, flag: String, enabled: Boolean, now: Long = System.currentTimeMillis()) {
        require(conversationId.isNotBlank() && flag in setOf("pinned", "archived", "muted"))
        synchronized(lock) {
            val conversation = get("conversation", conversationId) ?: JSONObject().put("id", conversationId).put("createdAt", now)
            conversation.put(flag, enabled).put("updatedAt", now)
            put("conversation", conversationId, conversation, conversationId, conversation.optLong("createdAt", now))
        }
    }

    /**
     * A contact nickname is a private label on this device. It is never uploaded or visible to
     * the labeled account or Owner. Passing a blank value removes the nickname.
     */
    fun setLocalContactNickname(contactId: String, nickname: String, now: Long = System.currentTimeMillis()): Boolean {
        require(contactId.isNotBlank() && nickname.length <= 80)
        synchronized(lock) {
            val contact = get("contact", contactId) ?: return false
            if (nickname.isBlank()) contact.remove("nickname") else contact.put("nickname", nickname.trim())
            contact.put("updatedAt", now)
            put("contact", contactId, contact, createdAt = contact.optLong("createdAt", now))
            return true
        }
    }

    /** Remove only this device's saved contact entry. */
    fun removeLocalContact(contactId: String): Boolean = delete("contact", contactId)

    /** A bookmark is private to this device. */
    fun setLocalBookmark(messageId: String, saved: Boolean, now: Long = System.currentTimeMillis()): Boolean {
        require(messageId.isNotBlank())
        if (!saved) return delete("saved", messageId)
        val message = get("message", messageId) ?: return false
        put("saved", messageId, JSONObject().put("messageId", messageId).put("conversationId", message.optString("conversationId")).put("savedAt", now), message.optString("conversationId"), now)
        return true
    }

    /**
     * Persist one recipient-device copy of a ciphertext envelope. Calling code must authenticate
     * the sender, authorize the recipient device and fan out a distinct copy per active device.
     * This is storage logic only; it is not a network relay or an authentication boundary.
     */
    fun queueCiphertext(envelope: CiphertextDelivery, now: Long = System.currentTimeMillis()) {
        require(envelope.deliveryId.isNotBlank() && envelope.deliveryId.length <= 100)
        require(envelope.senderDeviceId.isNotBlank() && envelope.senderDeviceId.length <= 200)
        require(envelope.recipientDeviceId.isNotBlank() && envelope.recipientDeviceId.length <= 200)
        require(envelope.ciphertext.isNotEmpty() && envelope.ciphertext.size <= MAX_ENVELOPE_BYTES)
        require(envelope.expiresAt > now && envelope.expiresAt <= now + MAX_RELAY_RETENTION_MS) {
            "Relay retention must be positive and no longer than seven days"
        }
        val rowId = "${envelope.deliveryId}:${envelope.recipientDeviceId}"
        require(rowId.length <= 200)
        synchronized(lock) {
            val existing = get("relay_delivery", rowId)
            val encoded = Base64.getEncoder().encodeToString(envelope.ciphertext)
            if (existing != null) {
                val same = existing.optString("senderDeviceId") == envelope.senderDeviceId &&
                    existing.optString("recipientDeviceId") == envelope.recipientDeviceId &&
                    existing.optString("ciphertext") == encoded &&
                    existing.optLong("expiresAt") == envelope.expiresAt
                check(same) { "Delivery ID already exists with different envelope data" }
                return // Idempotent retry; preserve the original expiry and payload.
            }
            val value = JSONObject()
                .put("deliveryId", envelope.deliveryId)
                .put("senderDeviceId", envelope.senderDeviceId)
                .put("recipientDeviceId", envelope.recipientDeviceId)
                .put("ciphertext", encoded)
                .put("expiresAt", envelope.expiresAt)
            put("relay_delivery", rowId, value, createdAt = now)
        }
    }

    /** Returns unexpired ciphertext rows for one device without deleting them on retrieval. */
    fun pendingCiphertextFor(recipientDeviceId: String, now: Long = System.currentTimeMillis()): List<CiphertextDelivery> {
        require(recipientDeviceId.isNotBlank())
        synchronized(lock) {
            expireCiphertext(now)
            return list("relay_delivery").asSequence()
                .filter { it.optString("recipientDeviceId") == recipientDeviceId && it.optLong("expiresAt") > now }
                .map { row ->
                    CiphertextDelivery(
                        deliveryId = row.getString("deliveryId"),
                        senderDeviceId = row.getString("senderDeviceId"),
                        recipientDeviceId = row.getString("recipientDeviceId"),
                        ciphertext = Base64.getDecoder().decode(row.getString("ciphertext")),
                        expiresAt = row.getLong("expiresAt")
                    )
                }.toList()
        }
    }

    /**
     * Remove only the copy addressed to the authenticated recipient device. The network caller
     * must invoke this only after that device has durably committed the decrypted message locally;
     * this method cannot itself prove authentication or durable persistence.
     */
    fun acknowledgeCiphertext(deliveryId: String, authenticatedRecipientDeviceId: String): Boolean {
        require(deliveryId.isNotBlank() && authenticatedRecipientDeviceId.isNotBlank())
        val rowId = "$deliveryId:$authenticatedRecipientDeviceId"
        synchronized(lock) {
            val row = get("relay_delivery", rowId) ?: return false
            check(row.optString("deliveryId") == deliveryId && row.optString("recipientDeviceId") == authenticatedRecipientDeviceId) {
                "Acknowledgment device does not match delivery target"
            }
            return delete("relay_delivery", rowId)
        }
    }

    /** Remove expired pending copies; delivery IDs and ciphertext are otherwise retained. */
    fun expireCiphertext(now: Long = System.currentTimeMillis()): Int {
        synchronized(lock) {
            val expired = list("relay_delivery").filter { it.optLong("expiresAt") <= now }
            var removed = 0
            expired.forEach { row ->
                val id = "${row.optString("deliveryId")}:${row.optString("recipientDeviceId")}" 
                if (delete("relay_delivery", id)) removed++
            }
            return removed
        }
    }

    /**
     * Create a one-time local invitation. Only a SHA-256 digest is persisted; callers must show
     * the returned random code once and must never log it. This is an Owner-device registry
     * primitive, not a remotely authenticated registration endpoint.
     */
    fun createLocalInvitation(expiresAt: Long, now: Long = System.currentTimeMillis()): String {
        require(expiresAt > now && expiresAt <= now + MAX_INVITATION_LIFETIME_MS) {
            "Invitation expiry must be within 30 days"
        }
        val raw = ByteArray(32).also(SecureRandom()::nextBytes)
        val code = Base64.getUrlEncoder().withoutPadding().encodeToString(raw)
        val digest = invitationDigest(code)
        val id = "sha256:$digest"
        val row = JSONObject()
            .put("expiresAt", expiresAt)
            .put("createdAt", now)
            .put("redeemedAt", JSONObject.NULL)
            .put("revokedAt", JSONObject.NULL)
        synchronized(lock) {
            writableDatabase.beginTransaction()
            try {
                insertEncryptedRecord(writableDatabase, "invitation", id, null, now, row)
                insertAuditEvent(writableDatabase, "invitation_created", "invitation", id, now)
                writableDatabase.setTransactionSuccessful()
            } finally { writableDatabase.endTransaction() }
        }
        raw.fill(0)
        return code
    }

    /**
     * Redeem one invitation and create a permanent UUID account in one SQLite transaction.
     * The invitation code is never stored in plaintext. This is local registration only: it does
     * not authenticate a remote request, publish a profile, or register a device/public key.
     */
    fun redeemLocalInvitation(
        code: String,
        username: String,
        displayName: String,
        now: Long = System.currentTimeMillis()
    ): JSONObject {
        require(code.length in 40..64 && code.all { it.isLetterOrDigit() || it == '-' || it == '_' }) { "Invalid invitation code" }
        val normalizedUsername = username.trim().lowercase()
        val display = displayName.trim()
        require(normalizedUsername.matches(Regex("[a-z0-9_]{3,32}"))) { "Username must be 3–32 letters, numbers, or underscores" }
        require(display.length in 1..80) { "Display name must be 1–80 characters" }
        val invitationId = "sha256:${invitationDigest(code)}"
        synchronized(lock) {
            val db = writableDatabase
            db.beginTransaction()
            try {
                val invitation = readRecord(db, "invitation", invitationId)
                    ?: throw IllegalArgumentException("Invitation is invalid")
                check(invitation.isNull("revokedAt")) { "Invitation was revoked" }
                check(invitation.isNull("redeemedAt")) { "Invitation was already used" }
                check(invitation.optLong("expiresAt", 0L) > now) { "Invitation expired" }
                check(!accountUsernameExists(db, normalizedUsername)) { "Username is already taken" }

                val accountId = java.util.UUID.randomUUID().toString()
                val account = JSONObject()
                    .put("id", accountId)
                    .put("username", normalizedUsername)
                    .put("displayName", display)
                    .put("role", "client")
                    .put("status", "active")
                    .put("createdAt", now)
                insertEncryptedRecord(db, "account", accountId, null, now, account)

                invitation.put("redeemedAt", now).put("redeemedAccountId", accountId)
                updateEncryptedRecord(db, "invitation", invitationId, null, invitation.optLong("createdAt", now), invitation)
                insertAuditEvent(db, "local_account_registered", "account", accountId, now)
                db.setTransactionSuccessful()
                return JSONObject(account.toString())
            } finally { db.endTransaction() }
        }
    }

    /** Owner-local account list. This does not expose any private keys (none are stored here). */
    fun localAccounts(): List<JSONObject> = list("account")

    /**
     * Register a device public identity and optional FCM routing token in this local database.
     * The device key must be generated/protected by the device; this stores only the public key.
     * This is not a remote authentication or authorization boundary.
     */
    fun registerLocalDevice(
        accountId: String,
        publicIdentityKey: ByteArray,
        fcmToken: String? = null,
        now: Long = System.currentTimeMillis()
    ): JSONObject {
        require(publicIdentityKey.size in 32..512) { "Invalid public identity key size" }
        require(fcmToken == null || (fcmToken.isNotBlank() && fcmToken.length <= 4096)) { "Invalid FCM token" }
        val deviceId = java.util.UUID.randomUUID().toString()
        val record = JSONObject()
            .put("id", deviceId)
            .put("accountId", accountId)
            .put("publicIdentityKey", Base64.getEncoder().encodeToString(publicIdentityKey))
            .put("fcmToken", fcmToken ?: JSONObject.NULL)
            .put("status", "active")
            .put("createdAt", now)
            .put("lastAuthenticatedAt", JSONObject.NULL)
        synchronized(lock) {
            val db = writableDatabase
            db.beginTransaction()
            try {
                val account = readRecord(db, "account", accountId)
                    ?: throw IllegalArgumentException("Account does not exist in local registry")
                check(account.optString("status") == "active") { "Account is not active" }
                insertEncryptedRecord(db, "device", deviceId, null, now, record)
                insertAuditEvent(db, "local_device_registered", "device", deviceId, now, accountId)
                db.setTransactionSuccessful()
            } finally { db.endTransaction() }
        }
        return JSONObject(record.toString())
    }

    /** Local device inventory for the Owner UI. Remote access must be denied by a real backend. */
    fun localDevices(accountId: String): List<JSONObject> {
        require(accountId.isNotBlank())
        return list("device").filter { it.optString("accountId") == accountId }
    }

    /** Mark a local device revoked instead of deleting its audit trail. */
    fun revokeLocalDevice(accountId: String, deviceId: String, now: Long = System.currentTimeMillis()): Boolean {
        require(accountId.isNotBlank() && deviceId.isNotBlank())
        synchronized(lock) {
            val db = writableDatabase
            db.beginTransaction()
            try {
                val device = readRecord(db, "device", deviceId) ?: return false
                if (device.optString("accountId") != accountId || device.optString("status") == "revoked") return false
                device.put("status", "revoked").put("revokedAt", now).put("fcmToken", JSONObject.NULL)
                updateEncryptedRecord(db, "device", deviceId, null, device.optLong("createdAt", now), device)
                insertAuditEvent(db, "local_device_revoked", "device", deviceId, now, accountId)
                db.setTransactionSuccessful()
                return true
            } finally { db.endTransaction() }
        }
    }

    /** Token refresh is local metadata only; a server must authenticate ownership before accepting it. */
    fun updateLocalFcmToken(accountId: String, deviceId: String, token: String?, now: Long = System.currentTimeMillis()): Boolean {
        require(accountId.isNotBlank() && deviceId.isNotBlank())
        require(token == null || (token.isNotBlank() && token.length <= 4096))
        synchronized(lock) {
            val db = writableDatabase
            db.beginTransaction()
            try {
                val device = readRecord(db, "device", deviceId) ?: return false
                if (device.optString("accountId") != accountId || device.optString("status") != "active") return false
                device.put("fcmToken", token ?: JSONObject.NULL).put("updatedAt", now)
                updateEncryptedRecord(db, "device", deviceId, null, device.optLong("createdAt", now), device)
                db.setTransactionSuccessful()
                return true
            } finally { db.endTransaction() }
        }
    }

    /** Change local registry status; remote authorization must be enforced by a real server. */
    fun setLocalAccountStatus(accountId: String, status: String, now: Long = System.currentTimeMillis()): Boolean {
        require(status in setOf("active", "suspended", "deleted"))
        synchronized(lock) {
            val db = writableDatabase
            db.beginTransaction()
            try {
                val account = readRecord(db, "account", accountId) ?: return false
                val previousStatus = account.optString("status", "unknown")
                if (previousStatus == status) { db.setTransactionSuccessful(); return true }
                account.put("status", status).put("updatedAt", now)
                updateEncryptedRecord(db, "account", accountId, null, account.optLong("createdAt", now), account)
                insertAuditEvent(db, "local_account_status_changed:$previousStatus->$status", "account", accountId, now)
                db.setTransactionSuccessful()
                return true
            } finally { db.endTransaction() }
        }
    }

    /** Revoke an unused invitation; returns false when the code is unknown or already consumed. */
    fun revokeLocalInvitation(code: String, now: Long = System.currentTimeMillis()): Boolean {
        require(code.length in 40..64)
        val id = "sha256:${invitationDigest(code)}"
        synchronized(lock) {
            val db = writableDatabase
            db.beginTransaction()
            try {
                val invite = readRecord(db, "invitation", id) ?: return false
                if (!invite.isNull("redeemedAt") || !invite.isNull("revokedAt")) return false
                invite.put("revokedAt", now)
                updateEncryptedRecord(db, "invitation", id, null, invite.optLong("createdAt", now), invite)
                insertAuditEvent(db, "invitation_revoked", "invitation", id, now)
                db.setTransactionSuccessful()
                return true
            } finally { db.endTransaction() }
        }
    }

    /** Recent Owner actions are encrypted local audit entries, not server-authenticated evidence. */
    fun localAdminAudit(limit: Int = 100): List<JSONObject> {
        require(limit in 1..500)
        return list("admin_audit").takeLast(limit).asReversed()
    }

    private fun insertAuditEvent(
        db: SQLiteDatabase,
        event: String,
        subjectType: String,
        subjectId: String?,
        now: Long,
        accountId: String? = null
    ) {
        val id = java.util.UUID.randomUUID().toString()
        val payload = JSONObject()
            .put("id", id)
            .put("event", event.take(100))
            .put("subjectType", subjectType)
            .put("subjectId", subjectId ?: JSONObject.NULL)
            .put("accountId", accountId ?: JSONObject.NULL)
            .put("createdAt", now)
        insertEncryptedRecord(db, "admin_audit", id, null, now, payload)
    }

    private fun accountUsernameExists(db: SQLiteDatabase, username: String): Boolean {
        db.rawQuery("SELECT id,conversation_id,created_at,payload FROM records WHERE kind='account'", null).use { cursor ->
            while (cursor.moveToNext()) {
                val id = cursor.getString(0)
                val conversationId = if (cursor.isNull(1)) null else cursor.getString(1)
                val createdAt = cursor.getLong(2)
                val payload = decrypt("account", id, conversationId, createdAt, cursor.getBlob(3))
                val account = JSONObject(String(payload, StandardCharsets.UTF_8))
                if (account.optString("username").equals(username, ignoreCase = true)) return true
            }
        }
        return false
    }

    private fun readRecord(db: SQLiteDatabase, kind: String, id: String): JSONObject? {
        db.rawQuery("SELECT conversation_id,created_at,payload FROM records WHERE kind=? AND id=?", arrayOf(kind, id)).use { cursor ->
            if (!cursor.moveToFirst()) return null
            val conversationId = if (cursor.isNull(0)) null else cursor.getString(0)
            val createdAt = cursor.getLong(1)
            val payload = decrypt(kind, id, conversationId, createdAt, cursor.getBlob(2))
            return JSONObject(String(payload, StandardCharsets.UTF_8))
        }
    }

    private fun insertEncryptedRecord(db: SQLiteDatabase, kind: String, id: String, conversationId: String?, createdAt: Long, json: JSONObject) {
        val values = ContentValues().apply {
            put("kind", kind); put("id", id); put("conversation_id", conversationId)
            put("created_at", createdAt); put("payload", encrypt(kind, id, conversationId, createdAt, json.toString().toByteArray(StandardCharsets.UTF_8)))
        }
        check(db.insertOrThrow("records", null, values) >= 0L)
    }

    private fun updateEncryptedRecord(db: SQLiteDatabase, kind: String, id: String, conversationId: String?, createdAt: Long, json: JSONObject) {
        val values = ContentValues().apply {
            put("conversation_id", conversationId); put("created_at", createdAt)
            put("payload", encrypt(kind, id, conversationId, createdAt, json.toString().toByteArray(StandardCharsets.UTF_8)))
        }
        check(db.update("records", values, "kind=? AND id=?", arrayOf(kind, id)) == 1) { "Record disappeared during transaction" }
    }

    private fun invitationDigest(code: String): String = MessageDigest.getInstance("SHA-256")
        .digest(code.toByteArray(StandardCharsets.UTF_8))
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    fun delete(kind: String, id: String): Boolean {
        require(kind in ALLOWED_KINDS)
        synchronized(lock) { return writableDatabase.delete("records", "kind=? AND id=?", arrayOf(kind, id)) > 0 }
    }

    fun deleteConversation(conversationId: String) {
        synchronized(lock) {
            writableDatabase.beginTransaction()
            try {
                writableDatabase.delete("records", "kind IN ('message','draft') AND conversation_id=?", arrayOf(conversationId))
                writableDatabase.delete("records", "kind='conversation' AND id=?", arrayOf(conversationId))
                writableDatabase.setTransactionSuccessful()
            } finally { writableDatabase.endTransaction() }
        }
    }

    private data class RowIdentity(val kind: String, val id: String, val conversationId: String?, val createdAt: Long)

    private fun migrateV1ToV2(db: SQLiteDatabase) {
        val rows = ArrayList<RowIdentity>()
        db.rawQuery("SELECT kind,id,conversation_id,created_at FROM records", null).use { cursor ->
            while (cursor.moveToNext()) rows += RowIdentity(
                cursor.getString(0), cursor.getString(1),
                if (cursor.isNull(2)) null else cursor.getString(2), cursor.getLong(3)
            )
        }
        rows.forEach { row ->
            val oldPayload = db.rawQuery("SELECT payload FROM records WHERE kind=? AND id=?", arrayOf(row.kind, row.id)).use { cursor ->
                check(cursor.moveToFirst()) { "Record disappeared during encrypted-store migration" }
                cursor.getBlob(0)
            }
            val plaintext = decryptLegacyV1(oldPayload)
            val upgraded = try { encrypt(row.kind, row.id, row.conversationId, row.createdAt, plaintext) }
                finally { plaintext.fill(0) }
            val values = ContentValues().apply { put("payload", upgraded) }
            check(db.update("records", values, "kind=? AND id=?", arrayOf(row.kind, row.id)) == 1) {
                "Record could not be migrated; original database is preserved by transaction rollback"
            }
        }
    }

    private fun encrypt(kind: String, id: String, conversationId: String?, createdAt: Long, plain: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD(recordAad(kind, id, conversationId, createdAt))
        val iv = cipher.iv
        val encrypted = cipher.doFinal(plain)
        return ByteBuffer.allocate(1 + iv.size + encrypted.size).put(iv.size.toByte()).put(iv).put(encrypted).array()
    }

    private fun decrypt(kind: String, id: String, conversationId: String?, createdAt: Long, record: ByteArray): ByteArray = decryptRecord(record) { cipher ->
        cipher.updateAAD(recordAad(kind, id, conversationId, createdAt))
    }

    private fun decryptLegacyV1(record: ByteArray): ByteArray = decryptRecord(record) { }

    private inline fun decryptRecord(record: ByteArray, configure: (Cipher) -> Unit): ByteArray {
        try {
            val input = ByteBuffer.wrap(record)
            val ivSize = input.get().toInt() and 0xff
            require(ivSize in 12..16 && input.remaining() > ivSize) { "Invalid encrypted record" }
            val iv = ByteArray(ivSize).also(input::get)
            val encrypted = ByteArray(input.remaining()).also(input::get)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            configure(cipher)
            return cipher.doFinal(encrypted)
        } catch (e: Exception) {
            throw IllegalStateException("Local encrypted data could not be opened; no data was cleared.", e)
        }
    }

    private fun recordAad(kind: String, id: String, conversationId: String?, createdAt: Long): ByteArray {
        val bytes = ByteArrayOutputStream()
        DataOutputStream(bytes).use { out ->
            out.writeUTF(kind)
            out.writeUTF(id)
            out.writeBoolean(conversationId != null)
            if (conversationId != null) out.writeUTF(conversationId)
            out.writeLong(createdAt)
        }
        return bytes.toByteArray()
    }

    private fun getOrCreateKey(): SecretKey {
        val store = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (store.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(false)
            .build())
        return generator.generateKey()
    }

    override fun close() { synchronized(lock) { super.close() } }

    companion object {
        private const val DATABASE_NAME = "glasschat_local.db"
        private const val DATABASE_VERSION = 2
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "glasschat_local_records_v1"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val MAX_ENVELOPE_BYTES = 1024 * 1024
        private const val MAX_RELAY_RETENTION_MS = 7L * 24 * 60 * 60 * 1000
        private const val MAX_INVITATION_LIFETIME_MS = 30L * 24 * 60 * 60 * 1000
        private val ALLOWED_KINDS = setOf("conversation", "message", "contact", "draft", "setting", "reaction", "saved", "relay_delivery", "account", "invitation", "device", "admin_audit")
    }
}
