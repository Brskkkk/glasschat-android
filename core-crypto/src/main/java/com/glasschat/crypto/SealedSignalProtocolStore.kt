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
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
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
 * The initial provisioning helper generates and persists local Signal identity/prekey material,
 * returning only public upload data. It does not publish that data, authenticate an account or peer,
 * provide identity-verification UI, replenish/rotate keys, or wire encryption into app messaging.
 * The existing Android Keystore key protects these records at rest; it is not a Signal identity key.
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

    /**
     * Generate an initial Signal identity and pre-key set, persisting all private material before
     * returning public-only upload data. Call only after the app has an authenticated local account
     * identity and a stable Signal device ID. This does not publish keys or establish trust.
     *
     * Initial keys use a fixed ID range because no publication can occur until this method returns
     * successfully and sets its durable completion marker. A retry after a partial local write can
     * safely finish the unpublished set. Once marked ready, missing key material is treated as
     * corruption/consumption, never silently regenerated under an old ID.
     */
    fun provisionInitialPublicPreKeys(signalDeviceId: Int): SignalPublicPreKeyBundle = synchronized(lock) {
        require(signalDeviceId in MIN_SIGNAL_DEVICE_ID..MAX_SIGNAL_DEVICE_ID) {
            "Signal device ID must be between 1 and 127"
        }
        val readyRecord = localStore.get(RECORD_KIND, rowId(INITIAL_KEYS_READY, SINGLETON_KEY))
        if (readyRecord != null) {
            val ready = decodePayload(readyRecord, INITIAL_KEYS_READY, SINGLETON_KEY)
            check(ready.optInt("deviceId") == signalDeviceId) {
                "This Signal identity is already bound to a different device ID"
            }
            check(ready.optInt("oneTimeCount") == INITIAL_ONE_TIME_PREKEY_COUNT) {
                "Saved initial Signal pre-key manifest is invalid"
            }
        } else {
            val identity = getIdentityKeyPair()
            for (id in 1..INITIAL_ONE_TIME_PREKEY_COUNT) {
                if (!containsPreKey(id)) {
                    val keyPair = ECKeyPair.generate()
                    storePreKey(id, PreKeyRecord(id, keyPair))
                }
            }
            if (!containsSignedPreKey(INITIAL_SIGNED_PREKEY_ID)) {
                val keyPair = ECKeyPair.generate()
                val publicBytes = keyPair.publicKey.serialize()
                val signature = try { identity.privateKey.calculateSignature(publicBytes) }
                finally { publicBytes.fill(0) }
                try {
                    storeSignedPreKey(
                        INITIAL_SIGNED_PREKEY_ID,
                        SignedPreKeyRecord(INITIAL_SIGNED_PREKEY_ID, System.currentTimeMillis(), keyPair, signature)
                    )
                } finally { signature.fill(0) }
            }
            if (!containsKyberPreKey(INITIAL_KYBER_PREKEY_ID)) {
                val keyPair = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
                val publicBytes = keyPair.publicKey.serialize()
                val signature = try { identity.privateKey.calculateSignature(publicBytes) }
                finally { publicBytes.fill(0) }
                try {
                    storeLastResortKyberPreKey(
                        INITIAL_KYBER_PREKEY_ID,
                        KyberPreKeyRecord(INITIAL_KYBER_PREKEY_ID, System.currentTimeMillis(), keyPair, signature)
                    )
                } finally { signature.fill(0) }
            }
            writeJson(INITIAL_KEYS_READY, SINGLETON_KEY, JSONObject()
                .put("deviceId", signalDeviceId)
                .put("oneTimeCount", INITIAL_ONE_TIME_PREKEY_COUNT)
                .put("createdAt", System.currentTimeMillis()))
        }

        val identity = getIdentityKeyPair()
        val signed = loadSignedPreKey(INITIAL_SIGNED_PREKEY_ID)
        val kyber = loadKyberPreKey(INITIAL_KYBER_PREKEY_ID)
        val signedPublic = signed.keyPair.publicKey.serialize()
        val signedSignature = signed.signature
        val kyberPublic = kyber.keyPair.publicKey.serialize()
        val kyberSignature = kyber.signature
        try {
            SignalPublicPreKeyBundle(
                registrationId = getLocalRegistrationId(),
                deviceId = signalDeviceId,
                identityKey = identity.publicKey.serialize(),
                signedPreKey = SignalPublicKeyMaterial(INITIAL_SIGNED_PREKEY_ID, signedPublic, signedSignature),
                kyberLastResortPreKey = SignalPublicKeyMaterial(INITIAL_KYBER_PREKEY_ID, kyberPublic, kyberSignature),
                oneTimePreKeys = (1..INITIAL_ONE_TIME_PREKEY_COUNT).mapNotNull { id ->
                    if (!containsPreKey(id)) return@mapNotNull null
                    val public = loadPreKey(id).keyPair.publicKey.serialize()
                    try { SignalPublicKeyMaterial(id, public) } finally { public.fill(0) }
                }
            )
        } finally {
            signedPublic.fill(0)
            signedSignature.fill(0)
            kyberPublic.fill(0)
            kyberSignature.fill(0)
        }
    }

    /** Fail closed unless this store is provisioned for the authenticated local account/device. */
    fun requireProvisionedIdentity(accountId: String, signalDeviceId: Int) = synchronized(lock) {
        require(accountId.isNotBlank() && accountId.length <= 128) { "Invalid local account identifier" }
        require(signalDeviceId in MIN_SIGNAL_DEVICE_ID..MAX_SIGNAL_DEVICE_ID) {
            "Signal device ID must be between 1 and 127"
        }
        check(accountId == localAccountId) { "Signal store does not belong to the authenticated local account" }
        val readyRecord = localStore.get(RECORD_KIND, rowId(INITIAL_KEYS_READY, SINGLETON_KEY))
            ?: error("Local Signal identity and prekeys are not provisioned")
        val ready = decodePayload(readyRecord, INITIAL_KEYS_READY, SINGLETON_KEY)
        check(ready.optInt("deviceId") == signalDeviceId) {
            "Local Signal identity is bound to a different device ID"
        }
    }

    /** Pin a peer identity only after the caller has authenticated the account and completed trust verification. */
    fun pinVerifiedIdentity(address: SignalProtocolAddress, identityKey: IdentityKey) = synchronized(lock) {
        val key = addressKey(address)
        val candidate = identityKey.serialize()
        try {
            val existing = readBytes(REMOTE_IDENTITY, key)
            if (existing != null) {
                try {
                    check(existing.contentEquals(candidate)) {
                        "Peer identity changed; explicit re-verification is required before replacing it"
                    }
                } finally { existing.fill(0) }
            } else {
                writeBytes(REMOTE_IDENTITY, key, candidate)
            }
        } finally { candidate.fill(0) }
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
        try {
            check(!changed) { "Peer identity changed; explicit re-verification is required before replacing it" }
            writeBytes(REMOTE_IDENTITY, key, serialized)
        } finally {
            previous?.fill(0)
            serialized.fill(0)
        }
        if (changed) IdentityKeyStore.IdentityChange.REPLACED_EXISTING else IdentityKeyStore.IdentityChange.NEW_OR_UNCHANGED
    }

    override fun isTrustedIdentity(address: SignalProtocolAddress, identityKey: IdentityKey, direction: IdentityKeyStore.Direction): Boolean = synchronized(lock) {
        val saved = readBytes(REMOTE_IDENTITY, addressKey(address)) ?: return@synchronized false
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
        const val INITIAL_KEYS_READY = "initial_keys_ready"
        const val INITIAL_ONE_TIME_PREKEY_COUNT = 100
        const val INITIAL_SIGNED_PREKEY_ID = 1
        const val INITIAL_KYBER_PREKEY_ID = 1
        const val MIN_SIGNAL_DEVICE_ID = 1
        const val MAX_SIGNAL_DEVICE_ID = 127
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
