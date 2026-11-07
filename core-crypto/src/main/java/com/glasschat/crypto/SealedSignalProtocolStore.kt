package com.glasschat.crypto

import com.glasschat.data.SealedLocalStore
import org.json.JSONObject
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.InvalidKeyIdException
import org.signal.libsignal.protocol.InvalidMessageException
import org.signal.libsignal.protocol.NoSessionException
import org.signal.libsignal.protocol.ReusedBaseKeyException
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.groups.state.SenderKeyRecord
import org.signal.libsignal.protocol.state.IdentityKeyStore
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SessionRecord
import org.signal.libsignal.protocol.state.SignalProtocolStore
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Durable libsignal protocol state stored inside [SealedLocalStore]'s AES-GCM records. The
 * database row identifier is a digest; account, address, key ID, protocol category, and serialized
 * key/session bytes are inside the authenticated encrypted payload.
 *
 * This is protocol-state persistence only. It does not generate/publish prekeys, authenticate a
 * peer or bundle, provide identity-verification UI, or wire encryption into app messaging. The
 * existing Android Keystore key protects these records at rest; it is not a Signal identity key.
 *
 * Kyber records stored through [storeKyberPreKey] are one-time; use
 * [storeLastResortKyberPreKey] for a persistent last-resort record so Signal's reuse-tuple check
 * is enforced. Key publication and rotation are still not app-wired.
 */
class SealedSignalProtocolStore(
    private val localStore: SealedLocalStore,
    private val localAccountId: String
) : SignalProtocolStore {
    private val lock = accountLocks.computeIfAbsent(localAccountId) { Any() }

    init {
        require(localAccountId.isNotBlank() && localAccountId.length <= 128) {
            "Invalid local account identifier"
        }
    }

    override fun getIdentityKeyPair(): IdentityKeyPair = synchronized(lock) {
        val serialized = readBytes(IDENTITY_PAIR, SINGLETON_KEY) ?: run {
            writeBytes(IDENTITY_PAIR, SINGLETON_KEY, IdentityKeyPair.generate().serialize())
            readBytes(IDENTITY_PAIR, SINGLETON_KEY)
                ?: error("Signal identity key pair was not persisted")
        }
        try {
            IdentityKeyPair(serialized)
        } catch (e: Exception) {
            throw IllegalStateException("Saved Signal identity key pair is invalid; data was not cleared", e)
        } finally {
            serialized.fill(0)
        }
    }

    override fun getLocalRegistrationId(): Int = synchronized(lock) {
        val saved = localStore.get(RECORD_KIND, rowId(REGISTRATION_ID, SINGLETON_KEY))
        if (saved != null) {
            val value = decodePayload(saved, REGISTRATION_ID, SINGLETON_KEY).getInt("value")
            require(value in 1..MAX_REGISTRATION_ID) { "Saved Signal registration ID is invalid" }
            return@synchronized value
        }
        val value = SecureRandom().nextInt(MAX_REGISTRATION_ID) + 1
        writeJson(REGISTRATION_ID, SINGLETON_KEY, JSONObject().put("value", value))
        value
    }

    override fun saveIdentity(address: SignalProtocolAddress, identityKey: IdentityKey): IdentityKeyStore.IdentityChange = synchronized(lock) {
        val key = addressKey(address)
        val previous = readBytes(REMOTE_IDENTITY, key)
        val serialized = identityKey.serialize()
        val changed = previous != null && !previous.contentEquals(serialized)
        previous?.fill(0)
        writeBytes(REMOTE_IDENTITY, key, serialized)
        if (changed) IdentityKeyStore.IdentityChange.REPLACED_EXISTING else IdentityKeyStore.IdentityChange.NEW_OR_UNCHANGED
    }

    override fun isTrustedIdentity(address: SignalProtocolAddress, identityKey: IdentityKey, direction: IdentityKeyStore.Direction): Boolean = synchronized(lock) {
        val saved = readBytes(REMOTE_IDENTITY, addressKey(address)) ?: return@synchronized true
        try {
            val candidate = identityKey.serialize()
            try {
                saved.contentEquals(candidate)
            } finally {
                candidate.fill(0)
            }
        } finally {
            saved.fill(0)
        }
    }

    override fun getIdentity(address: SignalProtocolAddress): IdentityKey? = synchronized(lock) {
        val serialized = readBytes(REMOTE_IDENTITY, addressKey(address)) ?: return@synchronized null
        try {
            IdentityKey(serialized)
        } catch (e: Exception) {
            throw IllegalStateException("Saved Signal identity key is invalid; data was not cleared", e)
        } finally {
            serialized.fill(0)
        }
    }

    override fun loadPreKey(preKeyId: Int): PreKeyRecord = synchronized(lock) {
        decodeRecord(PRE_KEY, numericKey(preKeyId), "pre-key $preKeyId", ::PreKeyRecord)
    }

    override fun storePreKey(preKeyId: Int, record: PreKeyRecord) = synchronized(lock) {
        require(preKeyId == record.id) { "Pre-key ID does not match its record" }
        writeSerialized(PRE_KEY, numericKey(preKeyId), record.serialize())
    }

    override fun containsPreKey(preKeyId: Int): Boolean = synchronized(lock) {
        contains(PRE_KEY, numericKey(preKeyId))
    }

    override fun removePreKey(preKeyId: Int) = synchronized(lock) {
        remove(PRE_KEY, numericKey(preKeyId))
    }

    override fun loadSession(address: SignalProtocolAddress): SessionRecord = synchronized(lock) {
        val bytes = readBytes(SESSION, addressKey(address)) ?: return@synchronized SessionRecord()
        try {
            SessionRecord(bytes)
        } catch (e: InvalidMessageException) {
            throw IllegalStateException("Saved Signal session is invalid; data was not cleared", e)
        } finally {
            bytes.fill(0)
        }
    }

    override fun loadExistingSessions(addresses: MutableList<SignalProtocolAddress>): MutableList<SessionRecord> = synchronized(lock) {
        val records = ArrayList<SessionRecord>(addresses.size)
        addresses.forEach { address ->
            if (!contains(SESSION, addressKey(address))) {
                throw NoSessionException(address, "No saved Signal session for $address")
            }
            records += loadSession(address)
        }
        records
    }

    override fun getSubDeviceSessions(name: String): MutableList<Int> = synchronized(lock) {
        localStore.list(RECORD_KIND).mapNotNull { row ->
            val payload = checkedPayload(row, SESSION) ?: return@mapNotNull null
            val address = JSONObject(payload.getString("key"))
            if (address.optString("name") != name) return@mapNotNull null
            address.optInt("deviceId").takeIf { it != PRIMARY_DEVICE_ID }
        }.distinct().toMutableList()
    }

    override fun storeSession(address: SignalProtocolAddress, record: SessionRecord) = synchronized(lock) {
        writeSerialized(SESSION, addressKey(address), record.serialize())
    }

    override fun containsSession(address: SignalProtocolAddress): Boolean = synchronized(lock) {
        contains(SESSION, addressKey(address))
    }

    override fun deleteSession(address: SignalProtocolAddress) = synchronized(lock) {
        remove(SESSION, addressKey(address))
    }

    override fun deleteAllSessions(name: String) = synchronized(lock) {
        val keys = localStore.list(RECORD_KIND).mapNotNull { row ->
            val payload = checkedPayload(row, SESSION) ?: return@mapNotNull null
            val key = payload.getString("key")
            if (JSONObject(key).optString("name") == name) key else null
        }
        keys.forEach { remove(SESSION, it) }
    }

    override fun loadSignedPreKey(signedPreKeyId: Int): SignedPreKeyRecord = synchronized(lock) {
        decodeRecord(SIGNED_PRE_KEY, numericKey(signedPreKeyId), "signed pre-key $signedPreKeyId", ::SignedPreKeyRecord)
    }

    override fun loadSignedPreKeys(): MutableList<SignedPreKeyRecord> = synchronized(lock) {
        loadAll(SIGNED_PRE_KEY, ::SignedPreKeyRecord)
    }

    override fun storeSignedPreKey(signedPreKeyId: Int, record: SignedPreKeyRecord) = synchronized(lock) {
        require(signedPreKeyId == record.id) { "Signed pre-key ID does not match its record" }
        writeSerialized(SIGNED_PRE_KEY, numericKey(signedPreKeyId), record.serialize())
    }

    override fun containsSignedPreKey(signedPreKeyId: Int): Boolean = synchronized(lock) {
        contains(SIGNED_PRE_KEY, numericKey(signedPreKeyId))
    }

    override fun removeSignedPreKey(signedPreKeyId: Int) = synchronized(lock) {
        // Keep Kyber last-resort reuse history even after retiring a pre-key ID. Reuse history is
        // security state, not key material, and must not be reset by key rotation or ID reuse.
        remove(SIGNED_PRE_KEY, numericKey(signedPreKeyId))
    }

    override fun storeSenderKey(sender: SignalProtocolAddress, distributionId: UUID, record: SenderKeyRecord) = synchronized(lock) {
        writeSerialized(SENDER_KEY, senderKey(sender, distributionId), record.serialize())
    }

    override fun loadSenderKey(sender: SignalProtocolAddress, distributionId: UUID): SenderKeyRecord? = synchronized(lock) {
        val bytes = readBytes(SENDER_KEY, senderKey(sender, distributionId)) ?: return@synchronized null
        try {
            SenderKeyRecord(bytes)
        } catch (e: InvalidMessageException) {
            throw IllegalStateException("Saved Signal sender key is invalid; data was not cleared", e)
        } finally {
            bytes.fill(0)
        }
    }

    override fun loadKyberPreKey(kyberPreKeyId: Int): KyberPreKeyRecord = synchronized(lock) {
        decodeRecord(KYBER_PRE_KEY, numericKey(kyberPreKeyId), "Kyber pre-key $kyberPreKeyId", ::KyberPreKeyRecord)
    }

    override fun loadKyberPreKeys(): MutableList<KyberPreKeyRecord> = synchronized(lock) {
        loadAll(KYBER_PRE_KEY, ::KyberPreKeyRecord)
    }

    override fun storeKyberPreKey(kyberPreKeyId: Int, record: KyberPreKeyRecord) = synchronized(lock) {
        require(kyberPreKeyId == record.id) { "Kyber pre-key ID does not match its record" }
        writeKyberPreKey(kyberPreKeyId, record, KYBER_ONE_TIME)
    }

    /** Store a persistent last-resort Kyber key; ordinary [storeKyberPreKey] keys are one-time. */
    fun storeLastResortKyberPreKey(kyberPreKeyId: Int, record: KyberPreKeyRecord) = synchronized(lock) {
        require(kyberPreKeyId == record.id) { "Kyber pre-key ID does not match its record" }
        writeKyberPreKey(kyberPreKeyId, record, KYBER_LAST_RESORT)
    }

    /** Remove Kyber key material while preserving last-resort base-key reuse history. */
    fun removeKyberPreKey(kyberPreKeyId: Int) = synchronized(lock) {
        remove(KYBER_PRE_KEY, numericKey(kyberPreKeyId))
    }

    override fun containsKyberPreKey(kyberPreKeyId: Int): Boolean = synchronized(lock) {
        contains(KYBER_PRE_KEY, numericKey(kyberPreKeyId))
    }

    override fun markKyberPreKeyUsed(kyberPreKeyId: Int, signedPreKeyId: Int, baseKey: ECPublicKey) = synchronized(lock) {
        val key = numericKey(kyberPreKeyId)
        val payload = localStore.get(RECORD_KIND, rowId(KYBER_PRE_KEY, key))
            ?: throw InvalidKeyIdException("No saved Kyber pre-key $kyberPreKeyId")
        val metadata = decodePayload(payload, KYBER_PRE_KEY, key)
        when (metadata.optString("usage", KYBER_ONE_TIME)) {
            KYBER_ONE_TIME -> remove(KYBER_PRE_KEY, key)
            KYBER_LAST_RESORT -> {
                val baseKeyBytes = baseKey.serialize()
                val tuple = try {
                    JSONObject()
                        .put("kyberId", kyberPreKeyId)
                        .put("signedPreKeyId", signedPreKeyId)
                        .put("baseKey", Base64.getEncoder().encodeToString(baseKeyBytes))
                        .toString()
                } finally {
                    baseKeyBytes.fill(0)
                }
                if (contains(KYBER_USE, tuple)) {
                    throw ReusedBaseKeyException("Signal last-resort Kyber tuple was already used")
                }
                writeJson(KYBER_USE, tuple, JSONObject().put("used", true))
            }
            else -> throw IllegalStateException("Saved Signal Kyber key has an invalid usage type")
        }
    }

    private fun writeKyberPreKey(kyberPreKeyId: Int, record: KyberPreKeyRecord, usage: String) {
        val bytes = record.serialize()
        try {
            writeJson(KYBER_PRE_KEY, numericKey(kyberPreKeyId), JSONObject()
                .put("serialized", Base64.getEncoder().encodeToString(bytes))
                .put("usage", usage))
        } finally {
            bytes.fill(0)
        }
    }

    private fun <T : Any> decodeRecord(category: String, key: String, description: String, decode: (ByteArray) -> T): T {
        val bytes = readBytes(category, key) ?: throw InvalidKeyIdException("No saved $description")
        try {
            return decode(bytes)
        } catch (e: InvalidMessageException) {
            throw IllegalStateException("Saved Signal $description is invalid; data was not cleared", e)
        } finally {
            bytes.fill(0)
        }
    }

    private fun <T : Any> loadAll(category: String, decode: (ByteArray) -> T): MutableList<T> =
        localStore.list(RECORD_KIND).mapNotNull { row ->
            val payload = checkedPayload(row, category) ?: return@mapNotNull null
            val bytes = Base64.getDecoder().decode(payload.getString("serialized"))
            try {
                decode(bytes)
            } catch (e: InvalidMessageException) {
                throw IllegalStateException("Saved Signal $category is invalid; data was not cleared", e)
            } finally {
                bytes.fill(0)
            }
        }.toMutableList()

    private fun readBytes(category: String, key: String): ByteArray? =
        localStore.get(RECORD_KIND, rowId(category, key))?.let { payload ->
            Base64.getDecoder().decode(decodePayload(payload, category, key).getString("serialized"))
        }

    private fun writeSerialized(category: String, key: String, bytes: ByteArray) {
        try {
            writeJson(category, key, JSONObject().put("serialized", Base64.getEncoder().encodeToString(bytes)))
        } finally {
            bytes.fill(0)
        }
    }

    private fun writeBytes(category: String, key: String, bytes: ByteArray) = writeSerialized(category, key, bytes)

    private fun writeJson(category: String, key: String, body: JSONObject) {
        val payload = JSONObject()
            .put("schema", PAYLOAD_SCHEMA)
            .put("account", localAccountId)
            .put("category", category)
            .put("key", key)
        val names = body.keys()
        while (names.hasNext()) {
            val name = names.next()
            payload.put(name, body.get(name))
        }
        localStore.put(RECORD_KIND, rowId(category, key), payload)
    }

    private fun decodePayload(payload: JSONObject, category: String, key: String): JSONObject {
        check(payload.optInt("schema") == PAYLOAD_SCHEMA &&
            payload.optString("account") == localAccountId &&
            payload.optString("category") == category &&
            payload.optString("key") == key) {
            "Signal record metadata does not match its encrypted index"
        }
        return payload
    }

    private fun checkedPayload(row: JSONObject, category: String): JSONObject? {
        if (row.optString("category") != category || row.optString("account") != localAccountId) return null
        return decodePayload(row, category, row.getString("key"))
    }

    private fun contains(category: String, key: String): Boolean =
        localStore.get(RECORD_KIND, rowId(category, key))?.let {
            decodePayload(it, category, key)
            true
        } ?: false

    private fun remove(category: String, key: String) {
        localStore.delete(RECORD_KIND, rowId(category, key))
    }

    private fun rowId(category: String, key: String): String {
        val encoded = ByteArrayOutputStream()
        DataOutputStream(encoded).use { output ->
            listOf(ROW_ID_DOMAIN, localAccountId, category, key).forEach { field ->
                val bytes = field.toByteArray(Charsets.UTF_8)
                output.writeInt(bytes.size)
                output.write(bytes)
                bytes.fill(0)
            }
        }
        val input = encoded.toByteArray()
        return try {
            MessageDigest.getInstance("SHA-256").digest(input)
                .joinToString("") { "%02x".format(it.toInt() and 0xff) }
        } finally {
            input.fill(0)
        }
    }

    private fun addressKey(address: SignalProtocolAddress): String = JSONObject()
        .put("name", address.name)
        .put("deviceId", address.deviceId)
        .toString()

    private fun senderKey(address: SignalProtocolAddress, distributionId: UUID): String = JSONObject()
        .put("address", addressKey(address))
        .put("distributionId", distributionId.toString())
        .toString()

    private fun numericKey(id: Int): String = id.toString()

    private companion object {
        const val RECORD_KIND = "signal_state"
        const val ROW_ID_DOMAIN = "glasschat/libsignal/store/v1"
        const val PAYLOAD_SCHEMA = 1
        const val SINGLETON_KEY = "local"
        const val MAX_REGISTRATION_ID = 16380
        const val PRIMARY_DEVICE_ID = 1
        const val IDENTITY_PAIR = "identity_pair"
        const val REGISTRATION_ID = "registration_id"
        const val REMOTE_IDENTITY = "remote_identity"
        const val PRE_KEY = "pre_key"
        const val SIGNED_PRE_KEY = "signed_pre_key"
        const val SESSION = "session"
        const val SENDER_KEY = "sender_key"
        const val KYBER_PRE_KEY = "kyber_pre_key"
        const val KYBER_USE = "kyber_use"
        const val KYBER_ONE_TIME = "one_time"
        const val KYBER_LAST_RESORT = "last_resort"
        val accountLocks = ConcurrentHashMap<String, Any>()
    }
}
