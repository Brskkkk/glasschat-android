package com.glasschat.ui

import android.content.Context
import android.content.ClipData
import android.content.ClipboardManager
import com.glasschat.data.SealedLocalStore
import com.glasschat.crypto.GlassChatSecureRuntime
import android.os.Handler
import android.os.Looper
import org.json.JSONObject
import java.util.UUID
import java.util.concurrent.Executors
import kotlinx.coroutines.delay
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.text.BasicText
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** Shared Owner/Client workspace: local-first, with an optional fail-closed Signal/Supabase path. */
@Composable
fun LocalMessengerScreen(
    context: Context,
    owner: Boolean,
    ownerServiceStatus: String = "Not running",
    externalNotice: String = "",
    onStartServer: () -> Unit = {},
    onPauseServer: () -> Unit = {},
    onResumeServer: () -> Unit = {},
    onStopServer: () -> Unit = {},
    autoStartEnabled: Boolean = false,
    lastServerStartMillis: Long = 0L,
    onAutoStartChanged: (Boolean) -> Unit = {}
) {
    val appContext = context.applicationContext
    val clipboard = remember(appContext) { appContext.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager }
    val store = remember { SealedLocalStore(appContext) }
    val secureRuntime = remember(store) { GlassChatSecureRuntime(store) }
    val executor = remember { Executors.newSingleThreadExecutor() }
    val main = remember { Handler(Looper.getMainLooper()) }
    val conversations = remember { mutableStateListOf<JSONObject>() }
    val contacts = remember { mutableStateListOf<JSONObject>() }
    val ownerAccounts = remember { mutableStateListOf<JSONObject>() }
    val serverAccounts = remember { mutableStateListOf<JSONObject>() }
    val serverAudit = remember { mutableStateListOf<JSONObject>() }
    val ownerAudit = remember { mutableStateListOf<JSONObject>() }
    val nicknameInputs = remember { mutableStateMapOf<String, String>() }
    val messages = remember { mutableStateListOf<JSONObject>() }
    var selectedId by remember { mutableStateOf<String?>(null) }
    var selectedName by remember { mutableStateOf("") }
    var titleInput by remember { mutableStateOf("") }
    var contactInput by remember { mutableStateOf("") }
    var groupMode by remember { mutableStateOf(false) }
    var groupIdInput by remember { mutableStateOf("") }
    var messageInput by remember { mutableStateOf("") }
    var editingMessageId by remember { mutableStateOf<String?>(null) }
    var searchInput by remember { mutableStateOf("") }
    val searchHits = remember { mutableStateListOf<JSONObject>() }
    var notice by remember { mutableStateOf("") }
    var themeId by remember { mutableStateOf("liquid") }
    var customAccentHex by remember { mutableStateOf("") }
    var accentInput by remember { mutableStateOf("") }
    var profileName by remember { mutableStateOf("") }
    var profileHandle by remember { mutableStateOf("") }
    var profileAbout by remember { mutableStateOf("") }
    var newInviteCode by remember { mutableStateOf("") }
    var revokeInviteInput by remember { mutableStateOf("") }
    var secureState by remember { mutableStateOf("Not configured — local-only; no message leaves this device.") }
    var privateMessageAlertsEnabled by remember { mutableStateOf(SecureMessageNotifications.isEnabled(appContext)) }
    var projectEndpoint by remember { mutableStateOf("") }
    var projectAnonKey by remember { mutableStateOf("") }
    var authEmail by remember { mutableStateOf("") }
    var authPassword by remember { mutableStateOf("") }
    var inviteCodeInput by remember { mutableStateOf("") }
    var accountUsernameInput by remember { mutableStateOf("") }
    var accountDisplayNameInput by remember { mutableStateOf("") }
    var peerAccountIdInput by remember { mutableStateOf("") }
    var peerDeviceInput by remember { mutableStateOf("") }
    var peerFingerprintInput by remember { mutableStateOf("") }
    var accountSummary by remember { mutableStateOf<JSONObject?>(null) }
    val peerCandidates = remember { mutableStateListOf<JSONObject>() }
    var hasVerifiedPeer by remember { mutableStateOf(false) }
    var selectedPeerReady by remember { mutableStateOf(false) }
    val activeSecureSend: ((String, String) -> String)? = if (selectedPeerReady) ({ conversationId, text -> secureRuntime.send(conversationId, text) }) else null
    val activeSecureReceive: (() -> String)? = if (selectedPeerReady) ({ secureRuntime.receive() }) else null
    val baseTheme = glassTheme(themeId)
    val customAccent = parseThemeColor(customAccentHex)
    val theme = if (customAccent == null) baseTheme else baseTheme.copy(accent = customAccent, swatch = customAccent)
    val notificationPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) {
            SecureMessageNotifications.enable(appContext)
            privateMessageAlertsEnabled = true
            notice = "Generic private-message alerts are on. Android may delay polling."
        } else {
            notice = "Notifications remain off. You can enable them in Android Settings."
        }
    }

    fun refreshContacts() {
        executor.execute {
            try {
                val rows = store.list("contact")
                main.post {
                    contacts.clear()
                    contacts.addAll(rows)
                    rows.forEach { contact ->
                        val id = contact.optString("id")
                        if (id.isNotBlank() && id !in nicknameInputs) nicknameInputs[id] = contact.optString("nickname")
                    }
                }
            } catch (e: Exception) {
                main.post { notice = "Could not open local contacts: ${e.message ?: "storage error"}" }
            }
        }
    }

    fun refreshOwnerAudit() {
        if (!owner) return
        executor.execute {
            try {
                val rows = store.localAdminAudit(100)
                main.post { ownerAudit.clear(); ownerAudit.addAll(rows) }
            } catch (e: Exception) {
                main.post { notice = "Could not open local audit history: ${e.message ?: "storage error"}" }
            }
        }
    }

    fun refreshOwnerAccounts() {
        if (!owner) return
        executor.execute {
            try {
                val rows = store.localAccounts()
                main.post { ownerAccounts.clear(); ownerAccounts.addAll(rows) }
            } catch (e: Exception) {
                main.post { notice = "Could not open the local account registry: ${e.message ?: "storage error"}" }
            }
        }
        refreshOwnerAudit()
    }

    fun refreshServerAccounts() {
        if (!owner) return
        executor.execute {
            try {
                val rows = secureRuntime.ownerListAccounts()
                val auditRows = secureRuntime.ownerListAdminAudit(100)
                main.post {
                    serverAccounts.clear(); serverAccounts.addAll(rows)
                    serverAudit.clear(); serverAudit.addAll(auditRows)
                    notice = "Server accounts, device states, and admin audit refreshed."
                }
            } catch (e: Exception) {
                main.post { notice = "Could not refresh server accounts; confirm this is an authenticated Owner and migration 0007 is deployed. ${e.message ?: "request failed"}" }
            }
        }
    }

    fun refreshChats(selectId: String? = selectedId) {
        executor.execute {
            try {
                val rows = store.list("conversation")
                main.post {
                    conversations.clear(); conversations.addAll(rows)
                    if (selectId != null) {
                        selectedId = selectId
                        editingMessageId = null
                        messageInput = ""
                        val selected = rows.firstOrNull { it.optString("id") == selectId }
                        selectedName = selected?.optString("name") ?: selectedName
                        refreshMessages(store, executor, main, selectId, messages, { notice = it })
                        executor.execute {
                            val draft = try { store.get("draft", selectId)?.optString("text").orEmpty() } catch (_: Exception) { "" }
                            main.post { if (selectedId == selectId && editingMessageId == null) messageInput = draft }
                        }
                    }
                }
            } catch (e: Exception) { main.post { notice = "Local storage unavailable: ${e.message ?: "read failed"}" } }
        }
    }

    LaunchedEffect(Unit) {
        refreshChats(null)
        refreshContacts()
        refreshOwnerAccounts()
        refreshOwnerAudit()
        executor.execute {
            val config = try { secureRuntime.projectConfiguration() } catch (_: Exception) { null }
            val secureStatus = try { secureRuntime.currentState() } catch (_: Exception) { "Secure messaging is not configured." }
            val account = try { secureRuntime.currentAccountSummary() } catch (_: Exception) { null }
            val verified = try { secureRuntime.hasVerifiedPeers() } catch (_: Exception) { false }
            val savedTheme = try { store.get("setting", "theme")?.optString("id") } catch (_: Exception) { null }
            val savedAccent = try { store.get("setting", "custom_accent")?.optString("hex") } catch (_: Exception) { null }
            val savedProfile = try { store.get("setting", "local_profile") } catch (_: Exception) { null }
            main.post {
                if (config != null) { projectEndpoint = config.optString("endpoint"); projectAnonKey = config.optString("anonKey") }
                secureState = secureStatus
                accountSummary = account
                hasVerifiedPeer = verified
                if (account != null && verified) SecureSyncScheduler.start(appContext)
                if (!savedTheme.isNullOrBlank()) themeId = savedTheme
                if (!savedAccent.isNullOrBlank()) { customAccentHex = savedAccent; accentInput = savedAccent }
                if (savedProfile != null) {
                    profileName = savedProfile.optString("displayName")
                    profileHandle = savedProfile.optString("handle")
                    profileAbout = savedProfile.optString("about")
                }
            }
        }
    }
    LaunchedEffect(selectedId, hasVerifiedPeer) {
        val conversationId = selectedId
        executor.execute {
            val ready = conversationId != null && secureRuntime.hasVerifiedPeer(conversationId)
            main.post { if (selectedId == conversationId) selectedPeerReady = ready }
        }
    }
    LaunchedEffect(selectedId, messageInput, editingMessageId) {
        val conversationId = selectedId
        if (conversationId != null && editingMessageId == null) {
            delay(600)
            val draft = messageInput
            executor.execute {
                try { store.saveLocalDraft(conversationId, draft) }
                catch (e: Exception) { main.post { notice = "Could not save local draft: ${e.message ?: "storage error"}" } }
            }
        }
    }
    DisposableEffect(store, executor) {
        onDispose { executor.shutdown(); store.close() }
    }

    Box(Modifier.fillMaxSize().background(Brush.linearGradient(listOf(theme.backgroundTop, theme.backgroundMiddle, theme.backgroundBottom)))) {
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(18.dp), verticalArrangement = Arrangement.spacedBy(13.dp)) {
            ChatText("GLASSCHAT  ${if (owner) "OWNER" else "CLIENT"}", Color.White, 13, FontWeight.Bold)
            ChatText("Your private space", Color.White, 28, FontWeight.SemiBold)
            Panel {
                ChatText(if (selectedPeerReady && activeSecureSend != null && activeSecureReceive != null) "VERIFIED PEER SESSION · RELAY STATUS SHOWN PER MESSAGE" else "LOCAL-ONLY · NO VERIFIED SESSION FOR THIS CHAT", theme.accent, 11, FontWeight.Bold)
                Spacer(Modifier.height(6.dp))
                ChatText(
                    secureState + if (hasVerifiedPeer) " A verified Signal session is configured; each send still reports whether the relay accepted ciphertext." else " No verified peer session is ready; local saves stay on this device.",
                    Color(0xFFE8E9F0), 14
                )
            }
            Panel {
                ChatText("PRIVATE-MESSAGE ALERTS", Color.White, 16, FontWeight.SemiBold)
                Spacer(Modifier.height(5.dp))
                ChatText("Optional generic alerts when encrypted messages are saved here. No sender or message text is shown. Delivery depends on Android’s best-effort polling, not instant push.", Color(0xFFBFC4D0), 12)
                Spacer(Modifier.height(8.dp))
                SmallAction(if (privateMessageAlertsEnabled) "Turn off private-message alerts" else "Enable private-message alerts", {
                    if (privateMessageAlertsEnabled) {
                        SecureMessageNotifications.disable(appContext)
                        privateMessageAlertsEnabled = false
                        notice = "Private-message alerts are off."
                    } else if (android.os.Build.VERSION.SDK_INT >= 33 &&
                        androidx.core.content.ContextCompat.checkSelfPermission(appContext, android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED
                    ) {
                        notificationPermissionLauncher.launch(android.Manifest.permission.POST_NOTIFICATIONS)
                    } else {
                        SecureMessageNotifications.enable(appContext)
                        privateMessageAlertsEnabled = true
                        notice = "Generic private-message alerts are on. Android may delay polling."
                    }
                }, secondary = privateMessageAlertsEnabled)
            }
            Panel {
                ChatText("SECURE ACCOUNT + DEVICE SETUP", Color.White, 16, FontWeight.SemiBold)
                Spacer(Modifier.height(5.dp))
                ChatText("Uses your Supabase project URL and public anon key only. Never paste a service-role key. This stays disabled until the service is configured; messages have no plaintext network fallback.", Color(0xFFBFC4D0), 12)
                Spacer(Modifier.height(8.dp))
                Entry(projectEndpoint, { projectEndpoint = it }, "https://your-project.supabase.co")
                Spacer(Modifier.height(6.dp))
                Entry(projectAnonKey, { projectAnonKey = it }, "Supabase public anon key")
                Spacer(Modifier.height(7.dp))
                SmallAction("Save project configuration") {
                    executor.execute {
                        try {
                            secureRuntime.configure(projectEndpoint.trim(), projectAnonKey.trim())
                            val state = secureRuntime.currentState()
                            main.post { secureState = state; notice = "Project configuration saved on this device." }
                        } catch (e: Exception) { main.post { notice = "Could not save project configuration: ${e.message ?: "check HTTPS URL and public anon key"}" } }
                    }
                }
                Spacer(Modifier.height(10.dp))
                Entry(authEmail, { authEmail = it }, "Supabase Auth email")
                Spacer(Modifier.height(6.dp))
                SecretEntry(authPassword, { authPassword = it }, "Supabase Auth password")
                Spacer(Modifier.height(7.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                    SmallAction("Create Supabase login") {
                        val email = authEmail.trim(); val password = authPassword.toCharArray(); authPassword = ""
                        if (email.isBlank() || password.isEmpty()) { password.fill('\u0000'); notice = "Enter your email and password." }
                        else executor.execute {
                            try {
                                val result = secureRuntime.signUp(email, password)
                                val status = secureRuntime.currentState()
                                val account = try { secureRuntime.currentAccountSummary() } catch (_: Exception) { null }
                                val verified = secureRuntime.hasVerifiedPeers()
                                main.post { secureState = status; accountSummary = account; hasVerifiedPeer = verified; notice = result }
                            } catch (e: Exception) { main.post { notice = "Supabase sign-up did not complete: ${e.message ?: "check project settings"}" } }
                        }
                    }
                    SmallAction("Sign in") {
                        val email = authEmail.trim(); val password = authPassword.toCharArray(); authPassword = ""
                        if (email.isBlank() || password.isEmpty()) { password.fill('\u0000'); notice = "Enter your email and password." }
                        else executor.execute {
                            try {
                                val result = secureRuntime.signIn(email, password)
                                val status = secureRuntime.currentState()
                                val account = try { secureRuntime.currentAccountSummary() } catch (_: Exception) { null }
                                val verified = secureRuntime.hasVerifiedPeers()
                                main.post {
                                    secureState = status; accountSummary = account; hasVerifiedPeer = verified; notice = result
                                    if (account != null && verified) SecureSyncScheduler.start(appContext)
                                }
                            } catch (e: Exception) { main.post { notice = "Sign-in did not complete: ${e.message ?: "check credentials and email verification"}" } }
                        }
                    }
                }
                accountSummary?.let { account ->
                    Spacer(Modifier.height(7.dp))
                    ChatText("Account: ${account.optString("username")} · ${account.optString("role")} · ${account.optString("id")}", Color(0xFFE8E9F0), 11)
                }
                Spacer(Modifier.height(8.dp))
                if (owner) {
                    SmallAction("Create server invitation (Owner only)") {
                        executor.execute {
                            try {
                                val code = secureRuntime.createInvitation()
                                main.post { newInviteCode = code; notice = "Server invitation created. Copy it now; it is shown only here." }
                            } catch (e: Exception) { main.post { notice = "Could not create server invitation: ${e.message ?: "sign in with an Owner account"}" } }
                        }
                    }
                    if (newInviteCode.isNotBlank()) {
                        Spacer(Modifier.height(6.dp)); ChatText("One-time server invitation: $newInviteCode", Color(0xFFFFD989), 11)
                        Spacer(Modifier.height(5.dp)); SmallAction("Copy server invitation") {
                            clipboard.setPrimaryClip(ClipData.newPlainText("GlassChat invitation", newInviteCode))
                            notice = "Copied; treat clipboard as sensitive until cleared."
                        }
                    }
                } else {
                    Entry(inviteCodeInput, { inviteCodeInput = it }, "One-time Owner invitation")
                    Spacer(Modifier.height(6.dp)); Entry(accountUsernameInput, { accountUsernameInput = it }, "Username (3–32 lowercase letters, digits, underscore)")
                    Spacer(Modifier.height(6.dp)); Entry(accountDisplayNameInput, { accountDisplayNameInput = it }, "Display name")
                    Spacer(Modifier.height(6.dp))
                    SmallAction("Redeem invitation") {
                        val code = inviteCodeInput.trim(); val username = accountUsernameInput.trim(); val name = accountDisplayNameInput.trim()
                        executor.execute {
                            try {
                                val result = secureRuntime.redeemInvitation(code, username, name)
                                val status = secureRuntime.currentState(); val account = secureRuntime.currentAccountSummary()
                                main.post { secureState = status; accountSummary = account; inviteCodeInput = ""; notice = result }
                            } catch (e: Exception) { main.post { notice = "Invitation redemption failed: ${e.message ?: "check invitation and account state"}" } }
                        }
                    }
                }
                Spacer(Modifier.height(8.dp))
                SmallAction("Register this device + publish Signal public keys") {
                    executor.execute {
                        try {
                            val result = secureRuntime.initializeDevice()
                            val status = secureRuntime.currentState()
                            main.post { secureState = status; notice = result }
                        } catch (e: Exception) { main.post { notice = "Device setup stopped safely: ${e.message ?: "service setup is incomplete"}" } }
                    }
                }
                Spacer(Modifier.height(10.dp))
                ChatText("PEER VERIFICATION", Color.White, 13, FontWeight.SemiBold)
                ChatText("Exchange account UUIDs out of band. Each person must approve the other before public device keys appear. Compare the full Signal fingerprint out of band before fetching a one-time prekey.", Color(0xFFBFC4D0), 11)
                Spacer(Modifier.height(6.dp)); Entry(peerAccountIdInput, { peerAccountIdInput = it }, "Peer GlassChat account UUID")
                Spacer(Modifier.height(6.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                    SmallAction("Approve peer") {
                        executor.execute {
                            try { secureRuntime.approveContact(peerAccountIdInput); main.post { notice = "Your contact approval is saved. The peer must also approve you." } }
                            catch (e: Exception) { main.post { notice = "Could not approve peer: ${e.message ?: "check account UUID and sign-in"}" } }
                        }
                    }
                    SmallAction("Refresh approved devices") {
                        executor.execute {
                            try {
                                val candidates = secureRuntime.loadContactDevices(peerAccountIdInput)
                                main.post { peerCandidates.clear(); peerCandidates.addAll(candidates); notice = if (candidates.isEmpty()) "No active peer devices are published yet." else "Mutually approved device fingerprints loaded. Compare one out of band before continuing." }
                            } catch (e: Exception) { main.post { notice = "Could not load peer devices; both accounts must approve contact first." } }
                        }
                    }
                }
                peerCandidates.forEach { candidate ->
                    Spacer(Modifier.height(6.dp))
                    val device = candidate.optString("transportId")
                    ChatText("Signal device ${candidate.optInt("signalDeviceId")} · ${candidate.optString("fingerprint")}", Color(0xFFE8E9F0), 10)
                    SmallAction(if (device == peerDeviceInput) "Selected peer device" else "Use this device", { peerDeviceInput = device })
                }
                Spacer(Modifier.height(6.dp)); Entry(peerFingerprintInput, { peerFingerprintInput = it }, "Type the full fingerprint you compared in person")
                Spacer(Modifier.height(6.dp))
                SmallAction("Verify fingerprint + establish Signal session") {
                    val conversationId = selectedId
                    if (conversationId == null || peerDeviceInput.isBlank()) notice = "Choose a conversation and peer device first."
                    else executor.execute {
                        try {
                            val result = secureRuntime.verifyPeerAndEstablishSession(peerDeviceInput, conversationId, peerFingerprintInput)
                            val status = secureRuntime.currentState(); val verified = secureRuntime.hasVerifiedPeers()
                            val peerReady = secureRuntime.hasVerifiedPeer(conversationId)
                            main.post {
                                secureState = status; hasVerifiedPeer = verified; selectedPeerReady = peerReady; notice = result
                                if (peerReady) SecureSyncScheduler.start(appContext)
                            }
                        } catch (e: Exception) { main.post { notice = "Peer verification stopped safely: ${e.message ?: "compare the fingerprint and verify mutual consent"}" } }
                    }
                }
                if (hasVerifiedPeer) {
                    Spacer(Modifier.height(7.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                        SmallAction("Retry encrypted queue") {
                            executor.execute { try { val result = secureRuntime.retryQueued(); main.post { notice = result; selectedId?.let { refreshMessages(store, executor, main, it, messages) { msg -> notice = msg } } } } catch (_: Exception) { main.post { notice = "Encrypted queue retry is unavailable; no plaintext was sent." } } }
                        }
                    }
                }
            }
            if (owner) Panel {
                ChatText("SERVER ACCOUNT & DEVICE ADMINISTRATION", Color.White, 16, FontWeight.SemiBold)
                Spacer(Modifier.height(5.dp))
                ChatText("Server-authoritative controls require an active Owner login and migration 0007. Suspending a client or revoking a device immediately blocks its server relay access; device revocation also removes published prekeys. Owner accounts cannot be suspended here.", Color(0xFFBFC4D0), 12)
                Spacer(Modifier.height(8.dp))
                SmallAction("Refresh server accounts + audit", { refreshServerAccounts() })
                serverAccounts.forEach { account ->
                    val accountId = account.optString("account_id")
                    val status = account.optString("status", "unknown")
                    Spacer(Modifier.height(9.dp))
                    ChatText("${account.optString("display_name", account.optString("username"))} · @${account.optString("username")}", Color.White, 13, FontWeight.SemiBold)
                    ChatText("${account.optString("role")} · $status", Color(0xFFBFC4D0), 11)
                    if (account.optString("role") == "client" && status in setOf("active", "suspended")) {
                        SmallAction(if (status == "active") "Suspend client" else "Restore client", {
                            val nextStatus = if (status == "active") "suspended" else "active"
                            executor.execute {
                                try {
                                    val changed = secureRuntime.ownerSetClientStatus(accountId, nextStatus)
                                    main.post { notice = if (changed) "Server client account $nextStatus." else "Server account was already in that state or no longer available."; refreshServerAccounts() }
                                } catch (e: Exception) { main.post { notice = "Server account change failed: ${e.message ?: "Owner authorization required"}" } }
                            }
                        }, true)
                    }
                    val devices = account.optJSONArray("devices")
                    for (deviceIndex in 0 until (devices?.length() ?: 0)) {
                        val device = devices?.optJSONObject(deviceIndex) ?: continue
                        val deviceId = device.optString("device_id")
                        val deviceStatus = device.optString("status", "unknown")
                        Spacer(Modifier.height(5.dp))
                        ChatText("Device ${device.optInt("signal_device_id")} · $deviceStatus · $deviceId", Color(0xFFE8E9F0), 10)
                        if (deviceStatus == "active") SmallAction("Revoke device", {
                            executor.execute {
                                try {
                                    val changed = secureRuntime.ownerRevokeDevice(deviceId)
                                    main.post { notice = if (changed) "Server device revoked; its published prekeys were removed." else "Device was already revoked or is no longer available."; refreshServerAccounts() }
                                } catch (e: Exception) { main.post { notice = "Device revocation failed: ${e.message ?: "Owner authorization required"}" } }
                            }
                        }, true)
                    }
                }
                Spacer(Modifier.height(10.dp))
                ChatText("SERVER ADMIN AUDIT", Color.White, 13, FontWeight.SemiBold)
                ChatText("Recent account and device changes recorded by Supabase; no message content.", Color(0xFFBFC4D0), 11)
                if (serverAudit.isEmpty()) {
                    Spacer(Modifier.height(5.dp)); ChatText("No server admin events returned.", Color(0xFFBFC4D0), 11)
                }
                serverAudit.take(20).forEach { event ->
                    val eventName = event.optString("event_type").replace('_', ' ')
                    val whenText = event.optString("created_at")
                    Spacer(Modifier.height(6.dp))
                    ChatText("$eventName · $whenText", Color.White, 11, FontWeight.Medium)
                    val accountId = event.optString("target_account_id")
                    val deviceId = event.optString("target_device_id")
                    if (accountId.isNotBlank() && accountId != "null") ChatText("Account: $accountId", Color(0xFFBFC4D0), 10)
                    if (deviceId.isNotBlank() && deviceId != "null") ChatText("Device: $deviceId", Color(0xFFBFC4D0), 10)
                }
            }
            Panel {
                ChatText("THEME STUDIO", Color.White, 16, FontWeight.SemiBold)
                Spacer(Modifier.height(5.dp))
                ChatText("Choose a local look for this device.", Color(0xFFBFC4D0), 12)
                Spacer(Modifier.height(8.dp))
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                    glassThemePresets.forEach { preset ->
                        Box(
                            Modifier.background(preset.swatch, RoundedCornerShape(14.dp))
                                .border(if (preset.id == themeId) 2.dp else 1.dp, if (preset.id == themeId) Color.White else Color(0x55FFFFFF), RoundedCornerShape(14.dp))
                                .clickable {
                                    themeId = preset.id
                                    customAccentHex = ""
                                    accentInput = ""
                                    executor.execute {
                                        try {
                                            store.put("setting", "theme", JSONObject().put("id", preset.id))
                                            store.put("setting", "custom_accent", JSONObject().put("hex", ""))
                                        } catch (e: Exception) { main.post { notice = "Could not save theme: ${e.message ?: "storage error"}" } }
                                    }
                                }
                                .padding(horizontal = 12.dp, vertical = 10.dp)
                        ) { ChatText(preset.label, Color.White, 12, FontWeight.Medium) }
                    }
                }
                Spacer(Modifier.height(10.dp))
                ChatText("CUSTOM ACCENT", Color.White, 12, FontWeight.SemiBold)
                Spacer(Modifier.height(5.dp))
                ChatText("Enter a hex color such as #87D8CB. This changes only the local presentation.", Color(0xFFBFC4D0), 11)
                Spacer(Modifier.height(7.dp))
                Entry(accentInput, { accentInput = it }, "#RRGGBB")
                Spacer(Modifier.height(7.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(7.dp), verticalAlignment = Alignment.CenterVertically) {
                    SmallAction("Apply accent") {
                        val parsed = parseThemeColor(accentInput)
                        if (parsed == null) notice = "Use a valid six-digit hex color, for example #87D8CB."
                        else {
                            val normalizedAccent = accentInput.trim().uppercase()
                            customAccentHex = normalizedAccent
                            executor.execute {
                                try { store.put("setting", "custom_accent", JSONObject().put("hex", normalizedAccent)) }
                                catch (e: Exception) { main.post { notice = "Could not save accent: ${e.message ?: "storage error"}" } }
                            }
                            notice = "Custom accent saved on this device."
                        }
                    }
                    if (customAccent != null) Box(Modifier.size(26.dp).background(customAccent, RoundedCornerShape(8.dp)).border(1.dp, Color.White, RoundedCornerShape(8.dp)))
                }
            }
            Panel {
                ChatText("LOCAL PROFILE PREVIEW", Color.White, 16, FontWeight.SemiBold)
                Spacer(Modifier.height(5.dp))
                ChatText("Edit how your profile could look. It is stored on this device only and is not published or tied to an authenticated account.", Color(0xFFBFC4D0), 12)
                Spacer(Modifier.height(8.dp))
                Entry(profileName, { profileName = it.take(64) }, "Display name")
                Spacer(Modifier.height(7.dp))
                Entry(profileHandle, { profileHandle = it.filter { ch -> ch.isLetterOrDigit() || ch == '_' }.take(32) }, "Username")
                Spacer(Modifier.height(7.dp))
                Entry(profileAbout, { profileAbout = it.take(160) }, "About")
                Spacer(Modifier.height(8.dp))
                Panel {
                    ChatText(profileName.ifBlank { "Your name" }, Color.White, 16, FontWeight.SemiBold)
                    ChatText(if (profileHandle.isBlank()) "@username" else "@$profileHandle", theme.accent, 12)
                    if (profileAbout.isNotBlank()) ChatText(profileAbout, Color(0xFFBFC4D0), 12)
                }
                Spacer(Modifier.height(8.dp))
                SmallAction("Save local profile preview") {
                    val value = JSONObject().put("displayName", profileName.trim()).put("handle", profileHandle.trim()).put("about", profileAbout.trim())
                    executor.execute {
                        try { store.put("setting", "local_profile", value); main.post { notice = "Profile preview saved on this device only." } }
                        catch (e: Exception) { main.post { notice = "Could not save profile preview: ${e.message ?: "storage error"}" } }
                    }
                }
            }
            if (owner) Panel {
                ChatText("OWNER SERVICE", Color.White, 17, FontWeight.SemiBold)
                Spacer(Modifier.height(6.dp)); ChatText(ownerServiceStatus, theme.accent, 13)
                Spacer(Modifier.height(4.dp)); ChatText("This foreground service does not host the relay. Supabase messaging works only after an operator deploys the migrations and you configure its HTTPS URL and public anon key above.", Color(0xFFBFC4D0), 13)
                Spacer(Modifier.height(10.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    SmallAction("Start", onStartServer)
                    SmallAction("Pause", onPauseServer, true)
                    SmallAction("Resume", onResumeServer, true)
                    SmallAction("Stop", onStopServer, true)
                }
                Spacer(Modifier.height(10.dp))
                ChatText("Last service start: ${if (lastServerStartMillis > 0L) java.text.DateFormat.getDateTimeInstance(java.text.DateFormat.SHORT, java.text.DateFormat.SHORT).format(java.util.Date(lastServerStartMillis)) else "not started"}", Color(0xFFBFC4D0), 12)
                Spacer(Modifier.height(8.dp))
                SmallAction(if (autoStartEnabled) "Auto-start after reboot: ON" else "Auto-start after reboot: OFF", { onAutoStartChanged(!autoStartEnabled) }, !autoStartEnabled)
                Spacer(Modifier.height(4.dp))
                ChatText("Opt-in only. Android may block or delay startup; force-stop requires reopening the app. Stop Server suppresses automatic restart until you start again or re-enable this setting.", Color(0xFFBFC4D0), 11)
            }
            if (owner) Panel {
                ChatText("LOCAL REGISTRY · OWNER DEVICE ONLY", Color.White, 16, FontWeight.SemiBold)
                Spacer(Modifier.height(5.dp))
                ChatText("These invitation and account controls affect only this phone. They do not register people over the network or authorize remote accounts.", Color(0xFFBFC4D0), 12)
                Spacer(Modifier.height(9.dp))
                SmallAction("Create 7-day local invitation") {
                    executor.execute {
                        try {
                            val code = store.createLocalInvitation(System.currentTimeMillis() + 7L * 24 * 60 * 60 * 1000)
                            main.post { newInviteCode = code; notice = "Invitation created. Only its digest is stored, so save the code now."; refreshOwnerAudit() }
                        } catch (e: Exception) { main.post { notice = "Could not create local invitation: ${e.message ?: "storage error"}" } }
                    }
                }
                if (newInviteCode.isNotBlank()) {
                    Spacer(Modifier.height(7.dp))
                    ChatText("One-time local code: $newInviteCode", Color(0xFFFFD989), 12, FontWeight.Medium)
                    Spacer(Modifier.height(5.dp))
                    SmallAction("Copy invitation code") {
                        clipboard.setPrimaryClip(ClipData.newPlainText("GlassChat local invitation", newInviteCode))
                        notice = "Copied. Treat the clipboard as sensitive until cleared."
                    }
                }
                Spacer(Modifier.height(9.dp))
                Entry(revokeInviteInput, { revokeInviteInput = it }, "Paste local invitation code to revoke")
                Spacer(Modifier.height(7.dp))
                SmallAction("Revoke local invitation", secondary = true) {
                    val code = revokeInviteInput.trim()
                    if (code.isBlank()) {
                        notice = "Paste a local invitation code first."
                    } else {
                        executor.execute {
                            try {
                                val revoked = store.revokeLocalInvitation(code)
                                main.post {
                                    revokeInviteInput = ""
                                    if (revoked && newInviteCode == code) newInviteCode = ""
                                    notice = if (revoked) "Local invitation revoked." else "Invitation was not found, was already used, or was already revoked."
                                    refreshOwnerAudit()
                                }
                            } catch (e: Exception) { main.post { notice = "Could not revoke invitation: ${e.message ?: "storage error"}" } }
                        }
                    }
                }
                Spacer(Modifier.height(10.dp))
                ChatText("LOCAL ACCOUNTS (${ownerAccounts.size})", Color.White, 13, FontWeight.SemiBold)
                if (ownerAccounts.isEmpty()) {
                    Spacer(Modifier.height(4.dp)); ChatText("No local accounts registered.", Color(0xFFBFC4D0), 12)
                }
                ownerAccounts.forEach { account ->
                    val accountId = account.optString("id")
                    val status = account.optString("status", "unknown")
                    Spacer(Modifier.height(7.dp))
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            ChatText(account.optString("displayName", account.optString("username")), Color.White, 13, FontWeight.Medium)
                            ChatText("@${account.optString("username")} · $status", Color(0xFFBFC4D0), 11)
                        }
                        if (status == "active" || status == "suspended") SmallAction(if (status == "active") "Suspend" else "Restore", {
                            val next = if (status == "active") "suspended" else "active"
                            executor.execute {
                                try {
                                    val changed = store.setLocalAccountStatus(accountId, next)
                                    main.post { notice = if (changed) "Local account marked $next." else "Local account was not found."; refreshOwnerAccounts(); refreshOwnerAudit() }
                                } catch (e: Exception) { main.post { notice = "Could not update local account: ${e.message ?: "storage error"}" } }
                            }
                        }, true)
                    }
                }
            }
            if (owner) Panel {
                ChatText("LOCAL ADMIN AUDIT", Color.White, 16, FontWeight.SemiBold)
                Spacer(Modifier.height(4.dp))
                ChatText("Recent registry changes recorded on this phone only; not server-authenticated.", Color(0xFFBFC4D0), 12)
                if (ownerAudit.isEmpty()) {
                    Spacer(Modifier.height(6.dp)); ChatText("No local admin events yet.", Color(0xFFBFC4D0), 12)
                }
                ownerAudit.take(20).forEach { event ->
                    val eventName = event.optString("event").replace('_', ' ').replace(':', ' ')
                    val whenText = java.text.DateFormat.getDateTimeInstance(java.text.DateFormat.SHORT, java.text.DateFormat.SHORT)
                        .format(java.util.Date(event.optLong("createdAt")))
                    Spacer(Modifier.height(7.dp))
                    ChatText("$eventName · $whenText", Color.White, 12, FontWeight.Medium)
                    val subject = event.optString("subjectId")
                    if (subject.isNotBlank() && subject != "null") ChatText("${event.optString("subjectType")}: $subject", Color(0xFFBFC4D0), 10)
                }
            }
            Panel {
                ChatText("NEW CONVERSATION", Color.White, 16, FontWeight.SemiBold)
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                    SmallAction("One-to-one", { groupMode = false }, groupMode)
                    SmallAction("Group", { groupMode = true }, !groupMode)
                }
                Spacer(Modifier.height(8.dp))
                Entry(titleInput, { titleInput = it }, if (groupMode) "Group name" else "Conversation name")
                Spacer(Modifier.height(8.dp))
                if (groupMode) {
                    Entry(groupIdInput, { groupIdInput = it.trim() }, "Shared group ID (optional; generated if blank)")
                    Spacer(Modifier.height(5.dp))
                    ChatText("Use the same ID on each member’s device, then add and verify each member’s devices in this conversation. Membership is managed locally; there’s no shared roster yet.", Color(0xFFBFC4D0), 11)
                    if (groupIdInput.isNotBlank()) {
                        Spacer(Modifier.height(6.dp))
                        SmallAction("Copy group ID") {
                            clipboard.setPrimaryClip(ClipData.newPlainText("GlassChat group ID", groupIdInput.trim()))
                            notice = "Copied group ID. Share it with members; verify each peer fingerprint separately."
                        }
                    }
                } else {
                    Entry(contactInput, { contactInput = it }, "Contact's GlassChat ID (stored locally only)")
                }
                Spacer(Modifier.height(8.dp))
                SmallAction(if (groupMode) "Create local group" else "Save contact and start local conversation") {
                    val label = titleInput.trim().ifBlank { if (groupMode) "" else contactInput.trim() }
                    val suppliedGroupId = groupIdInput.trim()
                    val parsedGroupId = if (groupMode && suppliedGroupId.isNotBlank()) {
                        try {
                            val uuid = UUID.fromString(suppliedGroupId)
                            if (uuid.toString().equals(suppliedGroupId, ignoreCase = true)) uuid.toString() else null
                        } catch (_: IllegalArgumentException) { null }
                    } else null
                    if (label.isBlank()) notice = if (groupMode) "Enter a group name." else "Enter a conversation name or contact ID."
                    else if (groupMode && suppliedGroupId.isNotBlank() && parsedGroupId == null) notice = "Enter a valid UUID group ID, or leave it blank to generate one."
                    else {
                        val creatingGroup = groupMode
                        val contactAddress = contactInput.trim()
                        val id = if (creatingGroup) parsedGroupId ?: UUID.randomUUID().toString() else UUID.randomUUID().toString()
                        val now = System.currentTimeMillis()
                        val conversation = JSONObject().put("id", id).put("name", label).put("createdAt", now)
                            .put("kind", if (creatingGroup) "group" else "local")
                        executor.execute {
                            try {
                                check(store.get("conversation", id) == null) { "A conversation with this group ID already exists on this device" }
                                store.put("conversation", id, conversation, id, now)
                                if (!creatingGroup && contactAddress.isNotBlank()) {
                                    val contactId = UUID.randomUUID().toString()
                                    store.put("contact", contactId, JSONObject().put("id", contactId).put("label", label).put("glasschatId", contactAddress).put("createdAt", now), null, now)
                                }
                                main.post {
                                    titleInput = ""
                                    contactInput = ""
                                    if (creatingGroup) groupIdInput = id
                                    notice = if (creatingGroup) "Local group created. Share its ID, then verify every member’s devices; no server roster exists." else "Saved on this device only."
                                    refreshChats(id)
                                    refreshContacts()
                                }
                            } catch (e: Exception) { main.post { notice = "Could not create locally: ${e.message ?: "storage error"}" } }
                        }
                    }
                }
            }
            Panel {
                ChatText("CONTACTS · PRIVATE ON THIS DEVICE", Color.White, 16, FontWeight.SemiBold)
                Spacer(Modifier.height(5.dp))
                ChatText("Nicknames stay on your device; the contact and Owner cannot see them.", Color(0xFFBFC4D0), 12)
                if (contacts.isEmpty()) {
                    Spacer(Modifier.height(7.dp)); ChatText("No saved local contacts yet.", Color(0xFFBFC4D0), 13)
                }
                contacts.forEach { contact ->
                    val contactId = contact.optString("id")
                    val nickname = nicknameInputs[contactId] ?: contact.optString("nickname")
                    Spacer(Modifier.height(8.dp))
                    Panel {
                        ChatText(contact.optString("label", "Contact"), Color.White, 14, FontWeight.SemiBold)
                        Spacer(Modifier.height(3.dp))
                        ChatText(contact.optString("glasschatId"), Color(0xFFBFC4D0), 11)
                        Spacer(Modifier.height(6.dp))
                        Entry(nickname, { nicknameInputs[contactId] = it }, "Private nickname")
                        Spacer(Modifier.height(6.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            SmallAction("Save nickname", {
                                val value = nicknameInputs[contactId].orEmpty()
                                executor.execute {
                                    try {
                                        check(store.setLocalContactNickname(contactId, value)) { "Contact no longer exists" }
                                        main.post { notice = if (value.isBlank()) "Private nickname removed." else "Private nickname saved on this device."; refreshContacts() }
                                    } catch (e: Exception) { main.post { notice = "Could not save nickname: ${e.message ?: "storage error"}" } }
                                }
                            }, true)
                            SmallAction("Remove contact", {
                                executor.execute {
                                    try {
                                        store.removeLocalContact(contactId)
                                        main.post { nicknameInputs.remove(contactId); notice = "Contact removed from this device only."; refreshContacts() }
                                    } catch (e: Exception) { main.post { notice = "Could not remove contact: ${e.message ?: "storage error"}" } }
                                }
                            }, true)
                        }
                    }
                }
            }
            Panel {
                ChatText("CONVERSATIONS", Color.White, 16, FontWeight.SemiBold)
                if (conversations.isEmpty()) {
                    Spacer(Modifier.height(7.dp)); ChatText("No local conversations yet.", Color(0xFFBFC4D0), 13)
                }
                conversations.forEach { conversation ->
                    val id = conversation.optString("id")
                    Spacer(Modifier.height(7.dp))
                    SmallAction(conversation.optString("name", "Conversation"), { refreshChats(id) }, id == selectedId)
                }
            }
            if (selectedId != null) Panel {
                val selectedConversation = conversations.firstOrNull { it.optString("id") == selectedId }
                ChatText(selectedName, Color.White, 17, FontWeight.SemiBold)
                if (selectedConversation?.optString("kind") == "group") {
                    val groupId = selectedConversation.optString("id")
                    Spacer(Modifier.height(5.dp))
                    ChatText("LOCAL GROUP · PAIRWISE ENCRYPTED PER VERIFIED DEVICE", theme.accent, 11, FontWeight.SemiBold)
                    ChatText("Group ID: $groupId", Color(0xFFBFC4D0), 11)
                    Spacer(Modifier.height(5.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                        SmallAction("Copy group ID") {
                            clipboard.setPrimaryClip(ClipData.newPlainText("GlassChat group ID", groupId))
                            notice = "Copied group ID. Members need the same ID and individually verified peer devices."
                        }
                    }
                    ChatText("There’s no shared roster or Sender-Key group ratchet yet. Each message is encrypted separately to the verified devices linked to this ID.", Color(0xFFBFC4D0), 11)
                }
                Spacer(Modifier.height(5.dp)); ChatText(
                    if (activeSecureSend != null) "Encrypted messaging · delivery state shown per message" else "Stored locally · not sent",
                    theme.accent, 12
                )
                Spacer(Modifier.height(7.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    listOf("pinned" to "Pin", "archived" to "Archive", "muted" to "Mute").forEach { (flag, label) ->
                        val active = selectedConversation?.optBoolean(flag) == true
                        SmallAction(if (active) "Un$label" else label, {
                            val conversationId = selectedId
                            if (conversationId != null) executor.execute {
                                try {
                                    store.setLocalConversationFlag(conversationId, flag, !active)
                                    main.post { refreshChats(conversationId) }
                                } catch (e: Exception) { main.post { notice = "Could not update local setting: ${e.message ?: "storage error"}" } }
                            }
                        }, active)
                    }
                }
                Spacer(Modifier.height(8.dp))
                if (activeSecureReceive != null) {
                    SmallAction("Check encrypted messages", {
                        executor.execute {
                            try {
                                val result = activeSecureReceive.invoke()
                                val conversationId = selectedId
                                main.post { notice = result; if (conversationId != null) refreshChats(conversationId) }
                            } catch (_: Exception) {
                                main.post { notice = "Could not receive encrypted messages; no relay copy was acknowledged." }
                            }
                        }
                    })
                    Spacer(Modifier.height(8.dp))
                }
                if (messages.isEmpty()) ChatText("No messages yet.", Color(0xFFBFC4D0), 13)
                messages.forEach { item ->
                    val messageId = item.optString("id")
                    Spacer(Modifier.height(8.dp))
                    Panel {
                        ChatText(item.optString("sender", "You"), theme.accent, 11, FontWeight.SemiBold)
                        Spacer(Modifier.height(3.dp))
                        ChatText(item.optString("text"), Color(0xFFE8E9F0), 14)
                        val deliveryState = item.optString("delivery")
                        if (deliveryState.isNotBlank()) {
                            Spacer(Modifier.height(4.dp))
                            ChatText(deliveryLabel(deliveryState), Color(0xFF9FA6B5), 10)
                        }
                        item.optJSONArray("deviceDeliveries")?.let { copies ->
                            for (index in 0 until copies.length()) {
                                val copy = copies.optJSONObject(index) ?: continue
                                Spacer(Modifier.height(2.dp))
                                ChatText(
                                    "Signal device ${copy.optInt("signalDeviceId")}: ${deliveryLabel(copy.optString("state"))}",
                                    Color(0xFF9FA6B5), 9
                                )
                            }
                        }
                        Spacer(Modifier.height(7.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            SmallAction("Edit local", {
                                editingMessageId = messageId
                                messageInput = item.optString("text")
                            }, true)
                            SmallAction("Delete local", {
                                executor.execute {
                                    try {
                                        store.deleteLocalMessage(messageId)
                                        store.setLocalBookmark(messageId, false)
                                        main.post { notice = "Removed from this device only."; refreshChats(selectedId) }
                                    } catch (e: Exception) { main.post { notice = "Could not remove local copy: ${e.message ?: "storage error"}" } }
                                }
                            }, true)
                            SmallAction("👍", {
                                executor.execute {
                                    try {
                                        val key = "$messageId:local-device:👍"
                                        val enabled = store.get("reaction", key) == null
                                        store.setLocalReaction(messageId, "local-device", "👍", enabled)
                                        main.post { notice = "Reaction changed on this device only." }
                                    } catch (e: Exception) { main.post { notice = "Could not save reaction: ${e.message ?: "storage error"}" } }
                                }
                            }, true)
                            SmallAction("Save", {
                                executor.execute {
                                    try {
                                        val saved = store.get("saved", messageId) == null
                                        store.setLocalBookmark(messageId, saved)
                                        main.post { notice = if (saved) "Bookmarked on this device." else "Bookmark removed from this device." }
                                    } catch (e: Exception) { main.post { notice = "Could not update bookmark: ${e.message ?: "storage error"}" } }
                                }
                            }, true)
                        }
                    }
                }
                Spacer(Modifier.height(10.dp))
                if (editingMessageId != null) ChatText("Editing this device’s copy only", Color(0xFFFFD7A8), 12)
                Entry(messageInput, { messageInput = it }, "Write a local note/message")
                Spacer(Modifier.height(8.dp))
                SmallAction(if (editingMessageId == null && activeSecureSend != null) "Send encrypted" else if (editingMessageId == null) "Save message on this device" else "Save local edit") {
                    val text = messageInput.trim(); val conversationId = selectedId; val editingId = editingMessageId
                    if (text.isBlank() || conversationId == null) notice = "Write a message first."
                    else if (editingId != null) {
                        executor.execute {
                            try {
                                check(store.editLocalMessage(editingId, text)) { "Message no longer exists" }
                                main.post { messageInput = ""; editingMessageId = null; notice = "Edited this device’s copy only."; refreshChats(conversationId) }
                            } catch (e: Exception) { main.post { notice = "Could not edit local message: ${e.message ?: "storage error"}" } }
                        }
                    } else if (activeSecureSend != null) {
                        executor.execute {
                            try {
                                val status = activeSecureSend.invoke(conversationId, text)
                                main.post { messageInput = ""; notice = status; refreshChats(conversationId) }
                            } catch (_: Exception) {
                                main.post { notice = "Encrypted send failed; the message was not sent and remains in the composer." }
                            }
                        }
                    } else {
                        val now = System.currentTimeMillis(); val id = UUID.randomUUID().toString()
                        val item = JSONObject().put("id", id).put("conversationId", conversationId).put("sender", "You").put("text", text).put("createdAt", now).put("delivery", "local_only")
                        val conversation = JSONObject().put("id", conversationId).put("name", selectedName).put("createdAt", now).put("kind", "local")
                        executor.execute {
                            try {
                                store.put("message", id, item, conversationId, now)
                                store.put("conversation", conversationId, conversation, conversationId, now)
                                main.post { messageInput = ""; notice = "Saved locally; not delivered."; refreshChats(conversationId) }
                            } catch (e: Exception) { main.post { notice = "Could not save message: ${e.message ?: "storage error"}" } }
                        }
                    }
                }
                if (editingMessageId != null) {
                    Spacer(Modifier.height(6.dp))
                    SmallAction("Cancel edit", { editingMessageId = null; messageInput = "" }, true)
                }
                Spacer(Modifier.height(12.dp))
                Entry(searchInput, { searchInput = it }, "Search local message text")
                Spacer(Modifier.height(7.dp))
                SmallAction("Search this device") {
                    val query = searchInput.trim()
                    if (query.isBlank()) searchHits.clear()
                    else executor.execute { try { val rows = store.searchMessages(query); main.post { searchHits.clear(); searchHits.addAll(rows) } } catch (e: Exception) { main.post { notice = "Search failed: ${e.message ?: "storage error"}" } } }
                }
                searchHits.forEach { hit -> Spacer(Modifier.height(4.dp)); ChatText(hit.optString("text"), Color(0xFFBFC4D0), 12) }
            }
            if (externalNotice.isNotBlank()) ChatText(externalNotice, Color(0xFFFFC6A5), 13)
            if (notice.isNotBlank()) ChatText(notice, Color(0xFFFFC6A5), 13)
            ChatText(
                if (activeSecureSend != null && activeSecureReceive != null) "No plaintext send or receive fallback is available."
                else "No remote account or service is configured.",
                Color(0xFF9FA6B5), 12
            )
        }
    }
}

private fun deliveryLabel(state: String): String = when (state) {
    "local_only" -> "Only on this device · not delivered"
    "encrypted_queued_not_delivered" -> "Encrypted · queued on this device · not delivered"
    "relay_accepted_recipient_not_confirmed" -> "Encrypted · relay accepted · recipient receipt unconfirmed"
    "encrypted_partially_accepted" -> "Encrypted · relay accepted on some devices; remaining copies are queued"
    "recipient_stored_all_devices" -> "Encrypted · saved on all recipient devices"
    "recipient_stored_some_devices" -> "Encrypted · saved on some recipient devices"
    "encrypted_expired" -> "Encrypted · expired before recipient storage was confirmed"
    "encrypted_partial_expiry" -> "Encrypted · some device deliveries expired"
    "recipient_stored" -> "Encrypted · saved on this recipient device"
    "relay_expired" -> "Encrypted · expired before storage was confirmed"
    "received_encrypted_local" -> "Received encrypted · saved on this device"
    else -> state.replace('_', ' ')
}

private fun parseThemeColor(value: String): Color? {
    val normalized = value.trim()
    if (!normalized.matches(Regex("#[0-9a-fA-F]{6}"))) return null
    return try { Color(android.graphics.Color.parseColor(normalized)) } catch (_: IllegalArgumentException) { null }
}

private fun refreshMessages(
    store: SealedLocalStore, executor: java.util.concurrent.ExecutorService, main: Handler,
    conversationId: String, target: MutableList<JSONObject>, reportError: (String) -> Unit
) {
    executor.execute {
        try { val rows = store.list("message", conversationId); main.post { target.clear(); target.addAll(rows) } }
        catch (e: Exception) { main.post { reportError("Could not open local messages: ${e.message ?: "storage error"}") } }
    }
}

@Composable private fun ChatText(text: String, color: Color, size: Int, weight: FontWeight = FontWeight.Normal) {
    BasicText(text, style = TextStyle(color = color, fontSize = size.sp, fontWeight = weight, lineHeight = (size + 6).sp))
}

@Composable private fun Entry(value: String, update: (String) -> Unit, hint: String) {
    Box(Modifier.fillMaxWidth().background(Color(0x283FFFFFF), RoundedCornerShape(12.dp)).border(1.dp, Color(0x42FFFFFF), RoundedCornerShape(12.dp)).padding(12.dp)) {
        if (value.isEmpty()) ChatText(hint, Color(0xFF9FA6B5), 13)
        BasicTextField(value, update, modifier = Modifier.fillMaxWidth(), textStyle = TextStyle(color = Color.White, fontSize = 14.sp), singleLine = true)
    }
}

@Composable private fun SecretEntry(value: String, update: (String) -> Unit, hint: String) {
    Box(Modifier.fillMaxWidth().background(Color(0x283FFFFFF), RoundedCornerShape(12.dp)).border(1.dp, Color(0x42FFFFFF), RoundedCornerShape(12.dp)).padding(12.dp)) {
        if (value.isEmpty()) ChatText(hint, Color(0xFF9FA6B5), 13)
        BasicTextField(value, update, modifier = Modifier.fillMaxWidth(), textStyle = TextStyle(color = Color.White, fontSize = 14.sp), singleLine = true, visualTransformation = PasswordVisualTransformation())
    }
}

@Composable private fun Panel(content: @Composable ColumnScope.() -> Unit) {
    Column(Modifier.fillMaxWidth().background(Color(0x30FFFFFF), RoundedCornerShape(21.dp)).border(1.dp, Color(0x42FFFFFF), RoundedCornerShape(21.dp)).padding(16.dp), content = content)
}

@Composable private fun SmallAction(label: String, action: () -> Unit, secondary: Boolean = false) {
    Box(Modifier.background(if (secondary) Color(0xFF343849) else Color(0xFF4D9C91), RoundedCornerShape(13.dp)).clickable(onClick = action).padding(horizontal = 12.dp, vertical = 10.dp), contentAlignment = Alignment.Center) {
        ChatText(label, Color.White, 12, FontWeight.Medium)
    }
}
