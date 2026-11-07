package com.glasschat.network

import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets

/** One independently ratcheted Signal ciphertext copy for an atomic server-group fan-out. */
data class GroupCiphertextCopy(
    val deliveryId: String,
    val recipientDeviceId: String,
    val ciphertext: ByteArray
)

/** Authenticated, HTTPS-only adapter for the reviewed GlassChat Supabase REST/RPC contract.
 * No service-role key, password, token, message body or ciphertext is logged or persisted here.
 */
class SupabaseRelayClient(baseUrl: String, anonKey: String) {
    private val root: String
    private val anon: String

    init {
        val parsed = URL(baseUrl.trim().trimEnd('/'))
        require(parsed.protocol == "https" && parsed.host.isNotBlank() && parsed.userInfo == null) {
            "Supabase endpoint must be an HTTPS URL"
        }
        require(parsed.query == null && parsed.ref == null) { "Supabase endpoint must not include a query or fragment" }
        require(parsed.path.isNullOrEmpty() || parsed.path == "/") {
            "Supabase endpoint must be the project root URL, without a path"
        }
        require(anonKey.isNotBlank()) { "Supabase public anon key is not configured" }
        root = parsed.toString().trimEnd('/')
        anon = anonKey.trim()
    }

    /** Create a Supabase Auth user. Email confirmation may be required by project policy. */
    fun signUp(email: String, password: CharArray): SupabaseSession? {
        require(email.isNotBlank() && password.isNotEmpty())
        val body = JSONObject().put("email", email.trim()).put("password", String(password))
        try {
            val result = request("POST", "/auth/v1/signup", body.toString(), null)
            val obj = result as? JSONObject ?: error("Supabase Auth returned an invalid response")
            return if (obj.optString("access_token").isNotBlank()) session(obj) else null
        } finally {
            body.put("password", "")
            password.fill('\u0000')
        }
    }

    fun signIn(email: String, password: CharArray): SupabaseSession {
        require(email.isNotBlank() && password.isNotEmpty())
        val body = JSONObject().put("email", email.trim()).put("password", String(password))
        try {
            val result = request("POST", "/auth/v1/token?grant_type=password", body.toString(), null)
            val obj = result as? JSONObject ?: error("Supabase Auth returned an invalid response")
            return session(obj)
        } finally {
            body.put("password", "")
            password.fill('\u0000')
        }
    }

    fun refresh(session: SupabaseSession): SupabaseSession {
        val body = JSONObject().put("refresh_token", session.refreshToken)
        val result = request("POST", "/auth/v1/token?grant_type=refresh_token", body.toString(), null)
        return session(result as? JSONObject ?: error("Supabase Auth returned an invalid response"))
    }

    fun createInvitation(token: String, expiresAtIso: String): String = scalarText(
        rpc(token, "gc_create_invitation", JSONObject().put("p_expires_at", expiresAtIso))
    )

    fun createGroup(token: String, name: String): String {
        require(name.trim().length in 1..80)
        return scalarText(rpc(token, "gc_create_group", JSONObject().put("p_name", name.trim())))
    }

    fun createGroupInvitation(token: String, groupId: String, expiresAtIso: String): String {
        requireUuid(groupId)
        return scalarText(rpc(token, "gc_create_group_invite", JSONObject()
            .put("p_group_id", groupId).put("p_expires_at", expiresAtIso)))
    }

    fun redeemGroupInvitation(token: String, code: String): JSONArray {
        require(code.matches(Regex("(?i)[0-9a-f]{48}"))) { "Enter the complete one-time group invitation" }
        return rpc(token, "gc_redeem_group_invite", JSONObject().put("p_code", code.lowercase())) as? JSONArray
            ?: error("Group invitation returned an invalid response")
    }

    fun listMyGroups(token: String): JSONArray =
        rpc(token, "gc_list_my_groups", JSONObject()) as? JSONArray
            ?: error("Server group list returned an invalid response")

    fun listGroupMembers(token: String, groupId: String): JSONArray {
        requireUuid(groupId)
        return rpc(token, "gc_list_group_members", JSONObject().put("p_group_id", groupId)) as? JSONArray
            ?: error("Server group roster returned an invalid response")
    }

    fun listGroupInvites(token: String, groupId: String): JSONArray {
        requireUuid(groupId)
        return rpc(token, "gc_list_group_invites", JSONObject().put("p_group_id", groupId)) as? JSONArray
            ?: error("Server group invitations returned an invalid response")
    }

    fun removeGroupMember(token: String, groupId: String, accountId: String): Boolean {
        requireUuid(groupId); requireUuid(accountId)
        return rpc(token, "gc_remove_group_member", JSONObject()
            .put("p_group_id", groupId).put("p_target_account_id", accountId)) as? Boolean
            ?: error("Group member removal returned an invalid response")
    }

    fun revokeGroupInvite(token: String, inviteId: String): Boolean {
        requireUuid(inviteId)
        return rpc(token, "gc_revoke_group_invite", JSONObject().put("p_invite_id", inviteId)) as? Boolean
            ?: error("Group invitation revocation returned an invalid response")
    }

    /** Server-authoritative account/device administration; RPCs enforce the active Owner role. */
    fun ownerListAccounts(token: String): JSONArray =
        rpc(token, "gc_owner_list_accounts", JSONObject()) as? JSONArray
            ?: error("Owner account listing returned an invalid response")

    fun ownerListDevices(token: String, accountId: String): JSONArray {
        requireUuid(accountId)
        return rpc(token, "gc_owner_list_devices", JSONObject().put("p_account_id", accountId)) as? JSONArray
            ?: error("Owner device listing returned an invalid response")
    }

    fun ownerListAdminAudit(token: String, limit: Int = 100): JSONArray {
        require(limit in 1..200)
        return rpc(token, "gc_owner_list_admin_audit", JSONObject().put("p_limit", limit)) as? JSONArray
            ?: error("Owner audit listing returned an invalid response")
    }

    /** Record a nickname only after the Client has explicitly confirmed sharing it with the Owner. */
    fun setOwnerNickname(token: String, ownerAccountId: String, nickname: String): Boolean {
        requireUuid(ownerAccountId)
        val clean = nickname.trim()
        require(clean.isEmpty() || clean.length <= 80) { "Nickname must be at most 80 characters" }
        val value: Any = if (clean.isEmpty()) JSONObject.NULL else clean
        return rpc(token, "gc_set_owner_nickname", JSONObject()
            .put("p_owner_account_id", ownerAccountId).put("p_nickname", value)) as? Boolean
            ?: error("Owner nickname update returned an invalid response")
    }

    /** Owner-only event history; never includes nicknames assigned to other contacts. */
    fun ownerListNicknameEvents(token: String, limit: Int = 100): JSONArray {
        require(limit in 1..200)
        return rpc(token, "gc_owner_list_nickname_events", JSONObject().put("p_limit", limit)) as? JSONArray
            ?: error("Owner nickname activity returned an invalid response")
    }

    fun ownerSetClientStatus(token: String, accountId: String, status: String): Boolean {
        requireUuid(accountId); require(status in setOf("active", "suspended"))
        return rpc(token, "gc_owner_set_client_status", JSONObject()
            .put("p_account_id", accountId).put("p_status", status)) as? Boolean
            ?: error("Owner account status update returned an invalid response")
    }

    fun revokeDevice(token: String, deviceId: String): Boolean {
        requireUuid(deviceId)
        return rpc(token, "gc_revoke_device", JSONObject().put("p_device_id", deviceId)) as? Boolean
            ?: error("Device revocation returned an invalid response")
    }

    fun listOwnDevices(token: String, accountId: String): JSONArray {
        requireUuid(accountId)
        val result = request("GET", "/rest/v1/gc_devices?select=id,signal_device_id,registration_id,public_identity_key,status&account_id=eq.$accountId&status=eq.active&order=created_at.asc", null, token)
        return result as? JSONArray ?: error("Device lookup returned an invalid response")
    }

    fun redeemInvitation(token: String, code: String, username: String, displayName: String): String {
        require(token.isNotBlank() && code.isNotBlank())
        val args = JSONObject().put("p_code", code).put("p_username", username).put("p_display_name", displayName)
        return scalarText(rpc(token, "gc_redeem_invitation", args))
    }

    fun currentAccount(token: String): JSONObject? {
        val query = "/rest/v1/gc_accounts?select=id,username,display_name,role,status&limit=2"
        val result = request("GET", query, null, token) as? JSONArray ?: error("Account lookup returned an invalid response")
        check(result.length() <= 1) { "More than one current account was returned" }
        return if (result.length() == 0) null else result.getJSONObject(0)
    }

    /** Register this device and public identity only; private Signal records never leave the device. */
    fun registerDevice(token: String, accountId: String, deviceId: String, signalDeviceId: Int,
                       registrationId: Int, identityPublicKey: ByteArray): JSONObject {
        requireUuid(accountId); requireUuid(deviceId)
        require(signalDeviceId in 1..127 && registrationId in 1..16380)
        val body = JSONArray().put(JSONObject()
            .put("id", deviceId).put("account_id", accountId)
            .put("signal_device_id", signalDeviceId).put("registration_id", registrationId)
            .put("public_identity_key", pgBytea(identityPublicKey)).put("status", "active"))
        val result = request("POST", "/rest/v1/gc_devices", body.toString(), token,
            mapOf("Prefer" to "return=representation")) as? JSONArray ?: error("Device registration returned an invalid response")
        return result.optJSONObject(0) ?: error("Device registration was not confirmed")
    }

    fun publishSignedAndKyberPreKeys(token: String, accountId: String, deviceId: String,
                                     signedId: Int, signedPublic: ByteArray, signedSignature: ByteArray,
                                     kyberId: Int, kyberPublic: ByteArray, kyberSignature: ByteArray) {
        requireUuid(accountId); requireUuid(deviceId)
        val rows = JSONArray().put(JSONObject()
            .put("account_id", accountId).put("device_id", deviceId)
            .put("signed_prekey_id", signedId).put("signed_prekey_public", pgBytea(signedPublic))
            .put("signed_prekey_signature", pgBytea(signedSignature))
            .put("kyber_prekey_id", kyberId).put("kyber_prekey_public", pgBytea(kyberPublic))
            .put("kyber_prekey_signature", pgBytea(kyberSignature)))
        request("POST", "/rest/v1/gc_signal_public_prekeys?on_conflict=device_id", rows.toString(), token,
            mapOf("Prefer" to "resolution=merge-duplicates,return=minimal"))
    }

    /** Count unconsumed public one-time prekeys for the authenticated owner's active device. */
    fun countOwnOneTimePreKeys(token: String, deviceId: String): Int {
        requireUuid(deviceId)
        val result = rpc(token, "gc_count_own_one_time_prekeys", JSONObject().put("p_device_id", deviceId))
        return (result as? Number)?.toInt()?.also { require(it >= 0) }
            ?: error("Supabase returned an invalid one-time prekey count")
    }

    fun publishOneTimePreKeys(token: String, accountId: String, deviceId: String,
                              keys: List<Pair<Int, ByteArray>>) {
        requireUuid(accountId); requireUuid(deviceId)
        if (keys.isEmpty()) return
        require(keys.size <= 500)
        val rows = JSONArray()
        keys.forEach { (id, publicKey) ->
            require(id > 0)
            rows.put(JSONObject().put("account_id", accountId).put("device_id", deviceId)
                .put("prekey_id", id).put("public_key", pgBytea(publicKey)))
        }
        request("POST", "/rest/v1/gc_signal_one_time_prekeys", rows.toString(), token,
            mapOf("Prefer" to "return=minimal"))
    }

    /** Record this authenticated account's explicit side of contact consent. */
    fun setContactConsent(token: String, accountId: String, peerAccountId: String, accepted: Boolean) {
        requireUuid(accountId); requireUuid(peerAccountId); require(accountId != peerAccountId)
        val body = JSONArray().put(JSONObject().put("account_id", accountId)
            .put("contact_account_id", peerAccountId).put("accepted", accepted))
        request("POST", "/rest/v1/gc_contact_consents?on_conflict=account_id,contact_account_id", body.toString(), token,
            mapOf("Prefer" to "resolution=merge-duplicates,return=minimal"))
    }

    /** Only returns device identities after server-side mutual contact-consent checks. */
    fun listContactDevices(token: String, peerAccountId: String): JSONArray {
        requireUuid(peerAccountId)
        return rpc(token, "gc_list_contact_devices", JSONObject().put("p_peer_account_id", peerAccountId)) as? JSONArray
            ?: error("Contact device lookup returned an invalid response")
    }

    /** Caller must establish that the device belongs to an explicitly verified, mutually approved contact. */
    fun fetchPeerBundle(token: String, peerDeviceId: String): JSONArray {
        requireUuid(peerDeviceId)
        return rpc(token, "gc_fetch_signal_prekey_bundle", JSONObject().put("p_peer_device_id", peerDeviceId)) as? JSONArray
            ?: error("Signal bundle RPC returned an invalid response")
    }

    fun submitCiphertext(token: String, deliveryId: String, senderDeviceId: String, recipientDeviceId: String,
                         ciphertext: ByteArray, expiresAtIso: String): String {
        requireUuid(deliveryId); requireUuid(senderDeviceId); requireUuid(recipientDeviceId)
        require(ciphertext.isNotEmpty() && ciphertext.size <= 1_048_586)
        val result = rpc(token, "gc_submit_ciphertext", JSONObject()
            .put("p_delivery_id", deliveryId).put("p_sender_device_id", senderDeviceId)
            .put("p_recipient_device_id", recipientDeviceId).put("p_ciphertext", pgBytea(ciphertext))
            .put("p_expires_at", expiresAtIso))
        return scalarText(result)
    }

    fun fetchCiphertext(token: String, recipientDeviceId: String, limit: Int = 50): JSONArray {
        requireUuid(recipientDeviceId); require(limit in 1..100)
        return rpc(token, "gc_fetch_ciphertext_v2", JSONObject()
            .put("p_recipient_device_id", recipientDeviceId).put("p_limit", limit)) as? JSONArray
            ?: error("Ciphertext fetch RPC returned an invalid response")
    }

    fun submitGroupCiphertext(token: String, deliveryId: String, groupId: String, membershipVersion: Long,
                              senderDeviceId: String, recipientDeviceId: String,
                              ciphertext: ByteArray, expiresAtIso: String): String {
        requireUuid(deliveryId); requireUuid(groupId); require(membershipVersion > 0)
        requireUuid(senderDeviceId); requireUuid(recipientDeviceId)
        require(ciphertext.isNotEmpty() && ciphertext.size <= 1_048_586)
        return scalarText(rpc(token, "gc_submit_group_ciphertext_v2", JSONObject()
            .put("p_delivery_id", deliveryId).put("p_group_id", groupId)
            .put("p_membership_version", membershipVersion)
            .put("p_sender_device_id", senderDeviceId).put("p_recipient_device_id", recipientDeviceId)
            .put("p_ciphertext", pgBytea(ciphertext)).put("p_expires_at", expiresAtIso)))
    }

    /**
     * Submit a complete server-managed group fan-out in one Postgres transaction. The RPC checks
     * the locked roster version and exact active recipient-device set before accepting any copy.
     */
    fun submitGroupCiphertextBatch(
        token: String,
        groupId: String,
        membershipVersion: Long,
        senderDeviceId: String,
        expiresAtIso: String,
        copies: List<GroupCiphertextCopy>
    ): Set<String> {
        requireUuid(groupId); require(membershipVersion > 0); requireUuid(senderDeviceId)
        require(copies.isNotEmpty() && copies.size <= 127)
        require(copies.map { it.deliveryId }.distinct().size == copies.size)
        require(copies.map { it.recipientDeviceId }.distinct().size == copies.size)
        copies.forEach {
            requireUuid(it.deliveryId); requireUuid(it.recipientDeviceId)
            require(it.ciphertext.isNotEmpty() && it.ciphertext.size <= 1_048_586)
        }
        require(copies.sumOf { it.ciphertext.size.toLong() } <= 8L * 1024 * 1024) {
            "Group ciphertext batch exceeds the 8 MiB limit"
        }
        val payload = JSONArray()
        copies.forEach { copy ->
            payload.put(JSONObject()
                .put("delivery_id", copy.deliveryId)
                .put("recipient_device_id", copy.recipientDeviceId)
                .put("ciphertext_hex", copy.ciphertext.joinToString("") { byte ->
                    "%02x".format(byte.toInt() and 0xff)
                }))
        }
        val result = rpc(token, "gc_submit_group_ciphertext_batch", JSONObject()
            .put("p_group_id", groupId).put("p_membership_version", membershipVersion)
            .put("p_sender_device_id", senderDeviceId).put("p_expires_at", expiresAtIso)
            .put("p_copies", payload)) as? JSONArray
            ?: error("Group relay returned an invalid atomic-batch response")
        val accepted = (0 until result.length()).map { result.getString(it) }.toSet()
        val requested = copies.map { it.deliveryId }.toSet()
        check(accepted == requested) { "Relay did not confirm every requested group delivery ID" }
        return accepted
    }

    fun acknowledgeCiphertext(token: String, deliveryId: String, recipientDeviceId: String): Boolean {
        requireUuid(deliveryId); requireUuid(recipientDeviceId)
        val result = rpc(token, "gc_ack_ciphertext", JSONObject()
            .put("p_delivery_id", deliveryId).put("p_recipient_device_id", recipientDeviceId))
        return result as? Boolean ?: error("Ciphertext acknowledgment returned an invalid response")
    }

    fun expireCiphertext(token: String): Int {
        val result = rpc(token, "gc_expire_ciphertext", JSONObject())
        return (result as? Number)?.toInt() ?: error("Ciphertext expiry RPC returned an invalid response")
    }

    /** Read only sender-owned per-device delivery metadata; no ciphertext is returned. */
    fun fetchDeliveryStatuses(token: String, senderDeviceId: String, deliveryIds: List<String>): JSONArray {
        requireUuid(senderDeviceId)
        require(deliveryIds.isNotEmpty() && deliveryIds.size <= 100) { "Delivery status batch must contain 1–100 IDs" }
        require(deliveryIds.distinct().size == deliveryIds.size) { "Delivery status batch contains duplicate IDs" }
        deliveryIds.forEach { requireUuid(it) }
        val ids = JSONArray().apply { deliveryIds.forEach { put(it) } }
        return rpc(token, "gc_fetch_delivery_status", JSONObject()
            .put("p_sender_device_id", senderDeviceId).put("p_delivery_ids", ids)) as? JSONArray
            ?: error("Delivery status lookup returned an invalid response")
    }

    fun rpc(token: String, function: String, arguments: JSONObject): Any? {
        require(function.matches(Regex("gc_[a-z0-9_]{1,80}")))
        require(token.isNotBlank()) { "Authenticated Supabase session is required" }
        return request("POST", "/rest/v1/rpc/$function", arguments.toString(), token)
    }

    private fun request(method: String, path: String, body: String?, accessToken: String?, extraHeaders: Map<String, String> = emptyMap()): Any? {
        require(path.startsWith("/") && !path.startsWith("//"))
        val connection = (URL(root + path).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            instanceFollowRedirects = false
            connectTimeout = CONNECT_TIMEOUT_MS
            readTimeout = READ_TIMEOUT_MS
            doInput = true
            setRequestProperty("apikey", anon)
            setRequestProperty("Accept", "application/json")
            setRequestProperty("Cache-Control", "no-store")
            if (accessToken != null) setRequestProperty("Authorization", "Bearer $accessToken")
            if (body != null) {
                doOutput = true
                setRequestProperty("Content-Type", "application/json; charset=utf-8")
            }
            extraHeaders.forEach { (key, value) -> setRequestProperty(key, value) }
        }
        try {
            if (body != null) {
                val bytes = body.toByteArray(StandardCharsets.UTF_8)
                connection.setFixedLengthStreamingMode(bytes.size)
                connection.outputStream.use { out: OutputStream -> out.write(bytes) }
                bytes.fill(0)
            }
            val code = connection.responseCode
            val stream = if (code in 200..299) connection.inputStream else connection.errorStream
            val bytes = stream?.use { input ->
                val out = ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                var total = 0
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    total += read
                    check(total <= MAX_RESPONSE_BYTES) { "Supabase response exceeds the size limit" }
                    out.write(buffer, 0, read)
                }
                buffer.fill(0)
                out.toByteArray()
            } ?: ByteArray(0)
            val response = try { String(bytes, StandardCharsets.UTF_8) } finally { bytes.fill(0) }
            if (code !in 200..299) {
                val detail = try { JSONObject(response).optString("message").take(240) } catch (_: Exception) { "" }
                throw SupabaseRequestException(code, detail.ifBlank { "Supabase request failed ($code)" })
            }
            if (response.isBlank()) return null
            return JSONTokener(response).nextValue()
        } finally {
            connection.disconnect()
        }
    }

    private fun session(json: JSONObject): SupabaseSession {
        val access = json.optString("access_token")
        val refresh = json.optString("refresh_token")
        val user = json.optJSONObject("user") ?: error("Supabase Auth omitted the user")
        require(access.isNotBlank() && refresh.isNotBlank() && user.optString("id").isNotBlank()) {
            "Supabase Auth returned an incomplete session"
        }
        return SupabaseSession(user.getString("id"), access, refresh, json.optLong("expires_in"))
    }

    private fun scalarText(value: Any?): String = when (value) {
        is String -> value
        is Number -> value.toString()
        is JSONObject -> value.optString("value")
        else -> error("Supabase returned an invalid scalar response")
    }

    private fun pgBytea(bytes: ByteArray): String = "\\x" + bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    /** PostgREST serializes bytea as the PostgreSQL hex form \"\\x...\" in JSON. */
    fun pgByteaForLocalStorage(bytes: ByteArray): String = pgBytea(bytes)

    fun decodePgBytea(value: String): ByteArray {
        require(value.startsWith("\\x") && value.length > 2 && (value.length - 2) % 2 == 0) {
            "Relay returned malformed ciphertext bytes"
        }
        val hex = value.substring(2)
        require(hex.length <= 2 * 1_048_586 && hex.all { it in '0'..'9' || it.lowercaseChar() in 'a'..'f' }) {
            "Relay ciphertext exceeds the supported size or is malformed"
        }
        return ByteArray(hex.length / 2) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
    }

    private fun requireUuid(value: String) {
        require(value.matches(Regex("(?i)[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"))) {
            "Expected a UUID from the authenticated GlassChat directory"
        }
    }

    companion object {
        private const val CONNECT_TIMEOUT_MS = 12_000
        private const val READ_TIMEOUT_MS = 20_000
        private const val MAX_RESPONSE_BYTES = 2 * 1024 * 1024
    }
}

data class SupabaseSession(
    val userId: String,
    val accessToken: String,
    val refreshToken: String,
    val expiresInSeconds: Long
)

class SupabaseRequestException(val httpStatus: Int, message: String) : IllegalStateException(message)
