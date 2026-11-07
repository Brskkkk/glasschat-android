package com.glasschat.network

import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets

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
        return rpc(token, "gc_fetch_ciphertext", JSONObject()
            .put("p_recipient_device_id", recipientDeviceId).put("p_limit", limit)) as? JSONArray
            ?: error("Ciphertext fetch RPC returned an invalid response")
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
