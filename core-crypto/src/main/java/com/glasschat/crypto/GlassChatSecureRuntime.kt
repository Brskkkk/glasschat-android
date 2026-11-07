package com.glasschat.crypto

import com.glasschat.data.SealedLocalStore
import com.glasschat.network.SupabaseRelayClient
import com.glasschat.network.SupabaseSession
import org.json.JSONArray
import org.json.JSONObject
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.kem.KEMPublicKey
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.state.PreKeyBundle
import java.security.MessageDigest
import java.time.Instant
import java.util.UUID

/**
 * Fail-closed Owner/Client runtime. Configuration, auth tokens, peer mappings and Signal private
 * state are stored only through the Keystore-sealed local store. The anon key is public project
 * configuration; no service-role key or password is retained. A live route exists only after the
 * project is configured, a Supabase user is authenticated, a GlassChat account/device is registered,
 * and the peer's directory identity has been explicitly verified.
 */
class GlassChatSecureRuntime(private val store: SealedLocalStore) {
    @Synchronized
    fun configure(endpoint: String, anonKey: String) {
        // Validate before persisting. This is the public anon key, never a service-role credential.
        SupabaseRelayClient(endpoint, anonKey)
        store.put("setting", CONFIG, JSONObject().put("endpoint", endpoint.trim().trimEnd('/'))
            .put("anonKey", anonKey.trim()))
    }

    @Synchronized
    fun projectConfiguration(): JSONObject? = store.get("setting", CONFIG)

    @Synchronized
    fun signUp(email: String, password: CharArray): String {
        try {
            val session = relay().signUp(email, password)
            if (session == null) return "Supabase account created; verify the email, then sign in here. No GlassChat account has been linked yet."
            saveSession(session)
            val account = relay().currentAccount(session.accessToken)
            if (account != null) store.put("account", ACCOUNT, account)
            return if (account == null) "Supabase account created and signed in; verify email if requested, then redeem an Owner invitation." else
                "Supabase account created and authenticated."
        } finally { password.fill('\u0000') }
    }

    @Synchronized
    fun currentAccountSummary(): JSONObject? = relay().currentAccount(accessToken())

    @Synchronized
    fun signIn(email: String, password: CharArray): String {
        try {
            val client = relay()
            val session = client.signIn(email, password)
            saveSession(session)
            val account = client.currentAccount(session.accessToken)
            if (account != null) store.put("account", ACCOUNT, account)
            return if (account == null) "Supabase sign-in succeeded; this login still needs a GlassChat invitation." else
                "Authenticated as ${account.optString("username")} (${account.optString("role")})."
        } finally { password.fill('\u0000') }
    }

    @Synchronized
    fun redeemInvitation(code: String, username: String, displayName: String): String {
        val token = accessToken()
        val accountId = relay().redeemInvitation(token, code.trim(), username.trim().lowercase(), displayName.trim())
        val account = relay().currentAccount(token) ?: error("Invitation was accepted, but the account profile is not visible yet")
        check(account.optString("id") == accountId) { "Authenticated account does not match the redeemed invitation" }
        store.put("account", ACCOUNT, account)
        return "GlassChat account ${account.optString("username")} is ready. Register this device next."
    }

    @Synchronized
    fun createServerGroup(name: String): String {
        val cleanName = name.trim()
        require(cleanName.length in 1..80) { "Group name must be 1–80 characters" }
        val own = requireAccount()
        requireLocalDevice(own.getString("id"))
        val id = relay().createGroup(accessToken(), cleanName)
        check(id.matches(Regex("(?i)[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"))) {
            "Server returned an invalid group ID"
        }
        check(store.get("conversation", id) == null) { "This server group ID is already used by a local conversation" }
        store.put("conversation", id, JSONObject().put("id", id).put("name", cleanName)
            .put("createdAt", System.currentTimeMillis()).put("kind", "group").put("role", "owner").put("serverManaged", true), id)
        return id
    }

    @Synchronized
    fun createServerGroupInvitation(groupId: String): String {
        val conversation = store.get("conversation", groupId) ?: error("Select a saved group first")
        check(conversation.optBoolean("serverManaged")) { "This group has no server-managed membership" }
        val own = requireAccount()
        requireLocalDevice(own.getString("id"))
        val expiry = Instant.ofEpochMilli(System.currentTimeMillis() + INVITATION_LIFETIME_MS).toString()
        return relay().createGroupInvitation(accessToken(), groupId, expiry)
    }

    @Synchronized
    fun redeemServerGroupInvitation(code: String): JSONObject {
        val own = requireAccount()
        requireLocalDevice(own.getString("id"))
        val rows = relay().redeemGroupInvitation(accessToken(), code.trim())
        check(rows.length() == 1) { "Server did not confirm one group invitation" }
        val row = rows.getJSONObject(0)
        val groupId = row.getString("group_id")
        val groupName = row.getString("group_name")
        val existing = store.get("conversation", groupId)
        check(existing == null || existing.optBoolean("serverManaged")) {
            "This group ID collides with an unrelated local conversation; server membership was accepted but its local view was not replaced"
        }
        store.put("conversation", groupId, JSONObject().put("id", groupId).put("name", groupName)
            .put("kind", "group").put("role", "member").put("serverManaged", true)
            .put("createdAt", existing?.optLong("createdAt", System.currentTimeMillis()) ?: System.currentTimeMillis()), groupId)
        return JSONObject().put("groupId", groupId).put("groupName", groupName)
    }

    @Synchronized
    fun listServerGroups(): List<JSONObject> {
        requireAccount()
        val rows = relay().listMyGroups(accessToken())
        val serverRows = (0 until rows.length()).mapNotNull { index ->
            rows.optJSONObject(index)?.let { JSONObject(it.toString()) }
        }
        // Preflight all collisions before changing local conversation records.
        serverRows.forEach { row ->
            val id = row.getString("group_id")
            val existing = store.get("conversation", id)
            check(existing == null || existing.optBoolean("serverManaged")) {
                "A server group ID collides with an unrelated local conversation; no server groups were imported"
            }
        }
        serverRows.forEach { row ->
            val id = row.getString("group_id")
            val existing = store.get("conversation", id)
            store.put("conversation", id, JSONObject().put("id", id)
                .put("name", row.getString("group_name")).put("kind", "group").put("role", row.optString("role")).put("serverManaged", true)
                .put("createdAt", existing?.optLong("createdAt", System.currentTimeMillis()) ?: System.currentTimeMillis()), id)
        }
        return serverRows
    }

    @Synchronized
    fun listServerGroupMembers(groupId: String): List<JSONObject> {
        val conversation = store.get("conversation", groupId) ?: error("Select a saved group first")
        check(conversation.optBoolean("serverManaged")) { "This group has no server-managed membership" }
        requireAccount()
        val rows = relay().listGroupMembers(accessToken(), groupId)
        return (0 until rows.length()).mapNotNull { index -> rows.optJSONObject(index)?.let { JSONObject(it.toString()) } }
    }

    @Synchronized
    fun createInvitation(): String {
        val account = requireAccount()
        check(account.optString("role") == "owner") { "Only an authenticated Owner can create invitations" }
        val expiry = Instant.ofEpochMilli(System.currentTimeMillis() + INVITATION_LIFETIME_MS).toString()
        return relay().createInvitation(accessToken(), expiry)
    }

    /** Returns server-authoritative Owner-managed account rows with non-secret device metadata. */
    @Synchronized
    fun ownerListAccounts(): List<JSONObject> {
        requireOwnerAccount()
        val client = relay(); val token = accessToken(); val rows = client.ownerListAccounts(token)
        return (0 until rows.length()).mapNotNull { index ->
            rows.optJSONObject(index)?.let { account ->
                val result = JSONObject(account.toString())
                val deviceRows = client.ownerListDevices(token, account.getString("account_id"))
                result.put("devices", deviceRows)
            }
        }
    }

    @Synchronized
    fun ownerListAdminAudit(limit: Int = 100): List<JSONObject> {
        requireOwnerAccount()
        val rows = relay().ownerListAdminAudit(accessToken(), limit)
        return (0 until rows.length()).mapNotNull { rows.optJSONObject(it)?.let { row -> JSONObject(row.toString()) } }
    }

    @Synchronized
    fun ownerSetClientStatus(accountId: String, status: String): Boolean {
        requireOwnerAccount()
        return relay().ownerSetClientStatus(accessToken(), accountId, status)
    }

    @Synchronized
    fun ownerRevokeDevice(deviceId: String): Boolean {
        requireOwnerAccount()
        return relay().revokeDevice(accessToken(), deviceId)
    }

    @Synchronized
    fun initializeDevice(): String {
        val account = requireAccount()
        val accountId = account.getString("id")
        val client = relay()
        val token = accessToken()
        val registered = client.listOwnDevices(token, accountId)
        var saved = store.get("device", deviceRecordId(accountId))
        val signalDeviceId: Int
        val transportId: String
        if (saved != null) {
            signalDeviceId = saved.getInt("signalDeviceId")
            transportId = saved.getString("transportId")
        } else {
            val used = (0 until registered.length()).mapNotNull { registered.optJSONObject(it)?.optInt("signal_device_id") }.toSet()
            signalDeviceId = (1..127).firstOrNull { it !in used }
                ?: error("This account already has the maximum 127 active Signal devices")
            transportId = UUID.randomUUID().toString()
            saved = JSONObject().put("accountId", accountId).put("transportId", transportId)
                .put("signalDeviceId", signalDeviceId)
            store.put("device", deviceRecordId(accountId), saved)
        }

        val localRecord = requireNotNull(saved)
        val protocol = SealedSignalProtocolStore(store, accountId)
        val public = protocol.provisionRotatedPublicPreKeysIfDue(signalDeviceId)
            ?: protocol.provisionInitialPublicPreKeys(signalDeviceId)
        val identity = public.identityKey
        try {
            val existing = (0 until registered.length()).mapNotNull { registered.optJSONObject(it) }
                .firstOrNull { it.optInt("signal_device_id") == signalDeviceId }
            if (existing != null) {
                check(existing.optString("id") == transportId) {
                    "A different device already uses this Signal device ID; refusing to replace its identity. Remove the stale local device setup or register a fresh account device."
                }
                val remoteIdentity = client.decodePgBytea(existing.getString("public_identity_key"))
                try { check(remoteIdentity.contentEquals(identity)) { "Server device identity differs from this device's saved Signal identity; refusing to overwrite it." } }
                finally { remoteIdentity.fill(0) }
            } else {
                check(registered.length() == 0 || (0 until registered.length()).none {
                    registered.optJSONObject(it)?.optString("id") == transportId
                }) { "Saved transport device ID conflicts with a different server record" }
                client.registerDevice(token, accountId, transportId, signalDeviceId, public.registrationId, identity)
            }
            val signed = public.signedPreKey.publicKey
            val signedSig = public.signedPreKey.signature ?: error("Signed pre-key signature is missing")
            val kyber = public.kyberLastResortPreKey.publicKey
            val kyberSig = public.kyberLastResortPreKey.signature ?: error("Kyber pre-key signature is missing")
            try {
                client.publishSignedAndKyberPreKeys(token, accountId, transportId,
                    public.signedPreKey.id, signed, signedSig, public.kyberLastResortPreKey.id, kyber, kyberSig)
                protocol.markCurrentPublicPreKeysPublished(signalDeviceId,
                    public.signedPreKey.id, public.kyberLastResortPreKey.id)
            } finally { signed.fill(0); signedSig.fill(0); kyber.fill(0); kyberSig.fill(0) }

            val publicationId = "otpk:${accountId}:$transportId"
            val publication = store.get("device", publicationId)
            check(publication?.optString("state") != "in_flight") {
                "One-time-prekey upload had an uncertain outcome. It was not retried to avoid re-publishing a possibly consumed key; ask the project administrator to inspect the device's published keys before recovery."
            }
            if (publication?.optString("state") != "published") {
                store.put("device", publicationId, JSONObject().put("state", "in_flight"))
                val keys = public.oneTimePreKeys.map { material ->
                    val bytes = material.publicKey
                    try { material.id to bytes.copyOf() } finally { bytes.fill(0) }
                }
                try { client.publishOneTimePreKeys(token, accountId, transportId, keys) }
                catch (e: Exception) { throw IllegalStateException("One-time pre-key upload may have reached the server; automatic retry is disabled to avoid re-publishing consumed keys. ${e.message ?: "Check service state before retrying."}", e) }
                finally { keys.forEach { it.second.fill(0) } }
                store.put("device", publicationId, JSONObject().put("state", "published"))
            }
            replenishOneTimePreKeys(client, token, accountId, transportId, signalDeviceId, protocol)
            store.put("device", deviceRecordId(accountId), localRecord.put("registered", true)
                .put("registrationId", public.registrationId).put("identityFingerprint", fingerprint(identity)))
            return "This device is registered and its public Signal keys are published. Private keys remain on this device."
        } finally { identity.fill(0) }
    }

    /** Best-effort worker hook: rotate and republish only this registered device's public keys. */
    @Synchronized
    fun rotatePublishedPreKeysIfDue(): Boolean {
        val account = requireAccount()
        val accountId = account.getString("id")
        val local = requireLocalDevice(accountId)
        check(local.optBoolean("registered")) { "This device is not registered yet" }
        val transportId = local.getString("transportId")
        val signalDeviceId = local.getInt("signalDeviceId")
        val client = relay()
        val token = accessToken()
        val registered = client.listOwnDevices(token, accountId)
        val row = (0 until registered.length()).mapNotNull { registered.optJSONObject(it) }
            .firstOrNull { it.optString("id") == transportId && it.optInt("signal_device_id") == signalDeviceId }
            ?: error("The registered Signal device is no longer visible; refusing key publication")
        val protocol = SealedSignalProtocolStore(store, accountId)
        val identity = protocol.getIdentityKeyPair().publicKey.serialize()
        val remoteIdentity = client.decodePgBytea(row.getString("public_identity_key"))
        try {
            check(identity.contentEquals(remoteIdentity)) {
                "Server device identity differs from this device's saved Signal identity; refusing key rotation"
            }
        } finally { identity.fill(0); remoteIdentity.fill(0) }

        val public = protocol.provisionRotatedPublicPreKeysIfDue(signalDeviceId) ?: return false
        val signed = public.signedPreKey.publicKey
        val signedSig = public.signedPreKey.signature ?: error("Signed pre-key signature is missing")
        val kyber = public.kyberLastResortPreKey.publicKey
        val kyberSig = public.kyberLastResortPreKey.signature ?: error("Kyber pre-key signature is missing")
        try {
            client.publishSignedAndKyberPreKeys(token, accountId, transportId,
                public.signedPreKey.id, signed, signedSig, public.kyberLastResortPreKey.id, kyber, kyberSig)
            protocol.markCurrentPublicPreKeysPublished(signalDeviceId,
                public.signedPreKey.id, public.kyberLastResortPreKey.id)
            return true
        } finally { signed.fill(0); signedSig.fill(0); kyber.fill(0); kyberSig.fill(0) }
    }

    private fun replenishOneTimePreKeys(
        client: SupabaseRelayClient,
        token: String,
        accountId: String,
        transportId: String,
        signalDeviceId: Int,
        protocol: SealedSignalProtocolStore
    ) {
        val currentCount = client.countOwnOneTimePreKeys(token, transportId)
        if (currentCount >= ONE_TIME_PREKEY_LOW_WATER) return
        val needed = ONE_TIME_PREKEY_TARGET - currentCount
        check(needed in 1..ONE_TIME_PREKEY_TARGET) {
            "Server one-time prekey count is outside the safe replenishment range"
        }
        val generated = protocol.provisionAdditionalOneTimePreKeys(signalDeviceId, needed)
        val upload = generated.map { material ->
            val bytes = material.publicKey
            try { material.id to bytes.copyOf() } finally { bytes.fill(0) }
        }
        try {
            client.publishOneTimePreKeys(token, accountId, transportId, upload)
        } catch (e: Exception) {
            // IDs were durably burned before this request. A retry first counts server keys and
            // allocates a new range if needed; it never republishes this possibly accepted batch.
            throw IllegalStateException(
                "Signal prekey replenishment may have reached the server; those IDs will not be reused. ${e.message ?: "Check the next device setup sync."}", e
            )
        } finally {
            upload.forEach { it.second.fill(0) }
        }
    }

    /** Records this account's consent side. The peer must separately approve before keys are visible. */
    @Synchronized
    fun approveContact(peerAccountId: String) {
        val own = requireAccount()
        val peerId = peerAccountId.trim()
        check(peerId != own.getString("id")) { "You cannot add your own account as a contact" }
        relay().setContactConsent(accessToken(), own.getString("id"), peerId, true)
    }

    /** Fetches public identity fingerprints only after mutual consent is confirmed server-side. */
    @Synchronized
    fun loadContactDevices(peerAccountId: String): List<JSONObject> {
        val own = requireAccount()
        val peerId = peerAccountId.trim()
        check(peerId != own.getString("id")) { "You cannot add your own account as a contact" }
        val client = relay(); val token = accessToken()
        val rows = client.listContactDevices(token, peerId)
        val candidates = ArrayList<JSONObject>()
        for (i in 0 until rows.length()) {
            val row = rows.optJSONObject(i) ?: continue
            val key = client.decodePgBytea(row.getString("public_identity_key"))
            try {
                val candidate = JSONObject().put("accountId", row.getString("account_id"))
                    .put("transportId", row.getString("device_id"))
                    .put("signalDeviceId", row.getInt("signal_device_id"))
                    .put("registrationId", row.getInt("registration_id"))
                    .put("identityKey", client.pgByteaForLocalStorage(key))
                    .put("fingerprint", fingerprint(key))
                store.put("device", candidateRecordId(row.getString("device_id")), candidate)
                candidates += JSONObject(candidate.toString())
            } finally { key.fill(0) }
        }
        return candidates
    }

    @Synchronized
    fun verifyPeerAndEstablishSession(peerTransportDeviceId: String, conversationId: String, typedFingerprint: String): String {
        require(conversationId.matches(Regex("(?i)[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"))) {
            "Select a conversation with a valid local ID before verifying the peer"
        }
        val own = requireAccount()
        val localId = own.getString("id")
        val localDevice = requireLocalDevice(localId)
        val localConversation = store.get("conversation", conversationId)
            ?: error("Create or select a saved local conversation before verifying a peer")
        val candidate = store.get("device", candidateRecordId(peerTransportDeviceId))
            ?: error("Fetch the mutually approved contact device list first")
        if (localConversation.optBoolean("serverManaged")) {
            val members = relay().listGroupMembers(accessToken(), conversationId)
            check((0 until members.length()).any {
                members.optJSONObject(it)?.optString("account_id") == candidate.optString("accountId")
            }) { "Only a current server-group member can be verified in this conversation" }
        }
        val existingAccounts = verifiedPeers().values
            .filter { it.conversationId == conversationId }
            .map { it.accountId }
            .toSet()
        check(localConversation.optString("kind") == "group" ||
            existingAccounts.isEmpty() || existingAccounts == setOf(candidate.getString("accountId"))) {
            "A one-to-one conversation can only include devices from one peer account. Create a group to verify multiple people."
        }
        check(normalizeFingerprint(typedFingerprint) == normalizeFingerprint(candidate.getString("fingerprint"))) {
            "Fingerprint does not match. No one-time pre-key was fetched or consumed. Compare the full fingerprint with your contact out of band."
        }
        val rows = relay().fetchPeerBundle(accessToken(), peerTransportDeviceId)
        check(rows.length() == 1) { "The server did not return exactly one peer bundle" }
        val row = rows.getJSONObject(0)
        check(row.getString("account_id") == candidate.getString("accountId") &&
            row.getString("device_id") == peerTransportDeviceId &&
            row.getInt("signal_device_id") == candidate.getInt("signalDeviceId")) {
            "Peer bundle identity or device mapping changed; no session was established"
        }
        val trustedBytes = relay().decodePgBytea(candidate.getString("identityKey"))
        val bundleIdentityBytes = relay().decodePgBytea(row.getString("identity_key"))
        try { check(trustedBytes.contentEquals(bundleIdentityBytes)) { "Peer identity key changed after verification; no session was established" } }
        finally { bundleIdentityBytes.fill(0) }
        val signed = relay().decodePgBytea(row.getString("signed_prekey_public"))
        val signedSig = relay().decodePgBytea(row.getString("signed_prekey_signature"))
        val kyber = relay().decodePgBytea(row.getString("kyber_prekey_public"))
        val kyberSig = relay().decodePgBytea(row.getString("kyber_prekey_signature"))
        val identity = IdentityKey(trustedBytes)
        val oneTimeId = if (row.isNull("one_time_prekey_id")) PreKeyBundle.NULL_PRE_KEY_ID else row.getInt("one_time_prekey_id")
        val oneTime = if (row.isNull("one_time_prekey_public")) null else relay().decodePgBytea(row.getString("one_time_prekey_public"))
        try {
            val bundle = PreKeyBundle(row.getInt("registration_id"), row.getInt("signal_device_id"),
                oneTimeId, oneTime?.let { ECPublicKey(it) }, row.getInt("signed_prekey_id"), ECPublicKey(signed), signedSig,
                identity, row.getInt("kyber_prekey_id"), KEMPublicKey(kyber), kyberSig)
            val protocol = SealedSignalProtocolStore(store, localId)
            SignalSessionCrypto(protocol).establishSession(localId, localDevice.getInt("signalDeviceId"),
                candidate.getString("accountId"), candidate.getInt("signalDeviceId"), bundle, identity)
            val mapping = JSONObject().put("accountId", candidate.getString("accountId"))
                .put("transportId", peerTransportDeviceId).put("signalDeviceId", candidate.getInt("signalDeviceId"))
                .put("conversationId", conversationId).put("fingerprint", candidate.getString("fingerprint"))
                .put("verifiedPeer", true)
            store.put("device", verifiedRecordId(peerTransportDeviceId), mapping)
        } finally {
            trustedBytes.fill(0); signed.fill(0); signedSig.fill(0); kyber.fill(0); kyberSig.fill(0); oneTime?.fill(0)
        }
        return "Peer fingerprint matched and the Signal session was established for this conversation."
    }

    @Synchronized
    fun send(conversationId: String, text: String): String {
        val own = requireAccount(); val local = requireLocalDevice(own.getString("id"))
        val conversation = store.get("conversation", conversationId)
            ?: error("This conversation is not saved on this device")
        val peers = verifiedPeers().filterValues { it.conversationId == conversationId }
        check(peers.isNotEmpty()) { "No verified peer session is linked to this conversation" }
        check(peers.values.all { it.conversationId == conversationId }) {
            "Every recipient session must be verified for this exact conversation."
        }
        check(conversation.optString("kind") == "group" || peers.values.map { it.accountId }.distinct().size == 1) {
            "A one-to-one conversation may only target one verified peer account."
        }
        val serverGroupId = if (conversation.optBoolean("serverManaged")) {
            validateServerGroupRecipientCoverage(conversationId, own.getString("id"), peers)
            conversationId
        } else null
        val targets = peers.map { (transportId, peer) -> VerifiedPeerTransportDeviceWithTransport(transportId, peer) }
        val results = messaging(own.getString("id"), local).sendTextToDevices(targets, conversationId, text, serverGroupId)
        val accepted = results.count { it.state == SendState.RELAY_ACCEPTED_RECIPIENT_NOT_CONFIRMED }
        val queued = results.count { it.state == SendState.ENCRYPTED_QUEUED_NOT_DELIVERED }
        val cleanupPending = results.count { it.state == SendState.RELAY_ACCEPTED_LOCAL_STATE_PENDING }
        return when {
            accepted == results.size -> "Encrypted message accepted by the relay for all ${results.size} verified devices; recipient receipts are unconfirmed."
            accepted > 0 && cleanupPending == 0 -> "Encrypted message accepted for $accepted of ${results.size} verified devices; the remaining copies are queued locally. Recipient receipts are unconfirmed."
            accepted > 0 -> "Relay accepted copies for $accepted of ${results.size} devices; local cleanup is pending for $cleanupPending more and $queued remain queued. Recipient receipts are unconfirmed."
            queued == results.size -> "Encrypted copies for all ${results.size} verified devices are queued locally; relay acceptance is not confirmed."
            cleanupPending > 0 -> "Relay accepted $cleanupPending device copies, but local cleanup is pending; $queued others remain queued. Recipient receipts are unconfirmed."
            else -> "Encrypted message fan-out is incomplete; check each device's local delivery state."
        }
    }

    private fun validateServerGroupRecipientCoverage(
        groupId: String,
        ownAccountId: String,
        linkedPeers: Map<String, VerifiedPeerTransportDevice>
    ) {
        val token = accessToken()
        val members = relay().listGroupMembers(token, groupId)
        val memberAccounts = (0 until members.length()).mapNotNull { members.optJSONObject(it)?.optString("account_id") }
            .filter { it.isNotBlank() }.toSet()
        check(ownAccountId in memberAccounts) { "Your account is no longer a member of this server group" }
        val expectedAccounts = memberAccounts - ownAccountId
        val linked = linkedPeers.filterValues { it.conversationId == groupId }
        check(linked.values.map { it.accountId }.toSet() == expectedAccounts) {
            "Refresh the server group roster and verify every member before sending"
        }
        val expectedDevices = LinkedHashSet<String>()
        expectedAccounts.forEach { accountId ->
            val directory = relay().listContactDevices(token, accountId)
            check(directory.length() > 0) { "A server group member has no active, mutually approved devices" }
            for (index in 0 until directory.length()) {
                val row = directory.getJSONObject(index)
                check(row.optString("account_id") == accountId) { "Contact directory returned a different account" }
                val deviceId = row.getString("device_id")
                check(expectedDevices.add(deviceId)) { "Server group directory returned a duplicate device" }
                val verified = linked[deviceId]
                    ?: error("Verify every active member device fingerprint before sending to this server group")
                check(verified.accountId == accountId && verified.signalDeviceId == row.getInt("signal_device_id")) {
                    "A verified device mapping changed; refresh and compare fingerprints again"
                }
                val publicKey = relay().decodePgBytea(row.getString("public_identity_key"))
                try {
                    check(fingerprint(publicKey) == store.get("device", verifiedRecordId(deviceId))?.optString("fingerprint")) {
                        "A member device identity changed; verify its new fingerprint before sending"
                    }
                } finally { publicKey.fill(0) }
            }
        }
        check(linked.keys == expectedDevices) {
            "The verified device set no longer matches the current group roster; refresh before sending"
        }
    }

    @Synchronized
    fun receive(): String {
        val result = receiveVerifiedMessages()
        return "Received ${result.stored} (${result.newlyStored} new); relay acknowledgments ${result.acknowledged}; skipped ${result.skipped}." +
            if (result.failures.isEmpty()) "" else " ${result.failures.size} delivery issue(s) remain unacknowledged."
    }

    /** New-message count for generic local notifications; never includes duplicate retries. */
    @Synchronized
    fun receiveForBackground(): Int = receiveVerifiedMessages().newlyStored

    private fun receiveVerifiedMessages(): SecureReceiveResult {
        val own = requireAccount(); val local = requireLocalDevice(own.getString("id"))
        val peers = verifiedPeers()
        check(peers.isNotEmpty()) { "No verified peer sessions are configured" }
        return messaging(own.getString("id"), local).receivePending(peers)
    }

    @Synchronized
    fun refreshDeliveryStatuses(): String {
        val own = requireAccount(); val local = requireLocalDevice(own.getString("id"))
        val updated = messaging(own.getString("id"), local).refreshDeliveryStatuses()
        return "Updated delivery receipts for $updated message(s); acknowledgments mean saved on the recipient device, not read."
    }

    @Synchronized
    fun retryQueued(): String {
        val own = requireAccount(); val local = requireLocalDevice(own.getString("id"))
        val results = messaging(own.getString("id"), local).retryPending()
        val accepted = results.count { it.state == SendState.RELAY_ACCEPTED_RECIPIENT_NOT_CONFIRMED }
        val stillQueued = results.count { it.state == SendState.ENCRYPTED_QUEUED_NOT_DELIVERED }
        val cleanupPending = results.count { it.state == SendState.RELAY_ACCEPTED_LOCAL_STATE_PENDING }
        return "Queued ciphertext retries: $accepted relay-accepted, $stillQueued still queued, $cleanupPending awaiting local cleanup; recipient receipts remain unconfirmed."
    }

    @Synchronized
    fun currentState(): String {
        return try {
            val config = store.get("setting", CONFIG)
            if (config == null) "Not configured — local-only; no message leaves this device."
            else {
                val token = accessToken()
                val account = relay().currentAccount(token)
                if (account == null) "Signed in, but no GlassChat account is linked. Redeem an Owner invitation."
                else {
                    store.put("account", ACCOUNT, account)
                    val device = store.get("device", deviceRecordId(account.getString("id")))
                    if (device?.optBoolean("registered") != true) "Authenticated; register this device's Signal keys to continue."
                    else "Authenticated as ${account.optString("username")}; device registered. Mutual consent and verified fingerprint are still required before messaging."
                }
            }
        } catch (e: Exception) { "Secure messaging unavailable: ${safeMessage(e)}" }
    }

    @Synchronized
    fun hasVerifiedPeers(): Boolean = try { verifiedPeers().isNotEmpty() } catch (_: Exception) { false }

    @Synchronized
    fun hasVerifiedPeer(conversationId: String): Boolean = try {
        conversationId.isNotBlank() && verifiedPeers().values.any { it.conversationId == conversationId }
    } catch (_: Exception) { false }

    private fun messaging(accountId: String, local: JSONObject): SignalSupabaseMessaging {
        val protocol = SealedSignalProtocolStore(store, accountId)
        return SignalSupabaseMessaging(relay(), SignalMessagePipeline(store, protocol), store,
            ::accessToken, accountId, local.getInt("signalDeviceId"), local.getString("transportId"))
    }

    private fun verifiedPeers(): Map<String, VerifiedPeerTransportDevice> = store.list("device")
        .filter { it.optBoolean("verifiedPeer") }
        .associate { row -> row.getString("transportId") to VerifiedPeerTransportDevice(
            row.getString("accountId"), row.getInt("signalDeviceId"), row.getString("conversationId")) }

    private fun requireLocalDevice(accountId: String): JSONObject {
        val device = store.get("device", deviceRecordId(accountId)) ?: error("Register this device first")
        check(device.optBoolean("registered")) { "This device's Signal keys are not fully published" }
        SealedSignalProtocolStore(store, accountId).requireProvisionedIdentity(accountId, device.getInt("signalDeviceId"))
        return device
    }

    private fun requireOwnerAccount(): JSONObject {
        val account = requireAccount()
        check(account.optString("role") == "owner") { "Only an authenticated active Owner can manage server accounts or devices" }
        return account
    }

    private fun requireAccount(): JSONObject {
        val account = relay().currentAccount(accessToken()) ?: error("No GlassChat account is linked; sign in and redeem an Owner invitation first")
        check(account.optString("status") == "active") { "GlassChat account is not active" }
        store.put("account", ACCOUNT, account)
        return account
    }

    private fun relay(): SupabaseRelayClient {
        val config = store.get("setting", CONFIG) ?: error("Enter the Supabase project URL and public anon key first")
        return SupabaseRelayClient(config.getString("endpoint"), config.getString("anonKey"))
    }

    private fun accessToken(): String {
        var saved = store.get("account", SESSION) ?: error("Sign in to Supabase Auth first")
        val configuredEndpoint = store.get("setting", CONFIG)?.optString("endpoint")
            ?: error("Enter the Supabase project URL and public anon key first")
        check(saved.optString("projectEndpoint") == configuredEndpoint) {
            "Saved sign-in belongs to a different Supabase project; sign in again for the configured project"
        }
        if (saved.optLong("expiresAt") <= System.currentTimeMillis() + TOKEN_REFRESH_MARGIN_MS) {
            val current = SupabaseSession(saved.getString("userId"), saved.getString("accessToken"),
                saved.getString("refreshToken"), 0)
            val refreshed = relay().refresh(current)
            saveSession(refreshed)
            saved = store.get("account", SESSION) ?: error("Refreshed session was not saved")
        }
        return saved.getString("accessToken")
    }

    private fun saveSession(session: SupabaseSession) {
        val endpoint = store.get("setting", CONFIG)?.getString("endpoint")
            ?: error("Configure the Supabase project before saving a sign-in")
        store.put("account", SESSION, JSONObject().put("userId", session.userId)
            .put("projectEndpoint", endpoint).put("accessToken", session.accessToken)
            .put("refreshToken", session.refreshToken)
            .put("expiresAt", System.currentTimeMillis() + session.expiresInSeconds.coerceAtLeast(60) * 1000))
    }

    private fun fingerprint(publicIdentityKey: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(publicIdentityKey)
        return try { digest.joinToString("") { "%02X".format(it.toInt() and 0xff) }.chunked(4).joinToString(" ") }
        finally { digest.fill(0) }
    }

    private fun normalizeFingerprint(value: String): String = value.filter { it.isLetterOrDigit() }.uppercase()
    private fun safeMessage(e: Exception): String = (e.message ?: "request failed").replace(Regex("https?://\\S+"), "project endpoint").take(220)

    private fun deviceRecordId(accountId: String) = "secure_device:$accountId"
    private fun candidateRecordId(deviceId: String) = "secure_candidate:$deviceId"
    private fun verifiedRecordId(deviceId: String) = "secure_peer:$deviceId"

    private companion object {
        const val CONFIG = "supabase_project"
        const val ACCOUNT = "supabase_account"
        const val SESSION = "supabase_session"
        const val INVITATION_LIFETIME_MS = 7L * 24 * 60 * 60 * 1000
        const val ONE_TIME_PREKEY_TARGET = 100
        const val ONE_TIME_PREKEY_LOW_WATER = 20
        const val TOKEN_REFRESH_MARGIN_MS = 60_000L
    }
}
