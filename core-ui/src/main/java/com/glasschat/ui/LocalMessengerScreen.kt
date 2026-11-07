package com.glasschat.ui

import android.content.Context
import com.glasschat.data.SealedLocalStore
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
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.text.BasicText
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

private val ChatInk = Color(0xFF10111D)
private val ChatAccent = Color(0xFF87D8CB)

/** Local-device messaging workspace. It deliberately makes no network/E2EE delivery claim. */
@Composable
fun LocalMessengerScreen(
    context: Context,
    owner: Boolean,
    ownerServiceStatus: String = "Not running",
    externalNotice: String = "",
    onStartServer: () -> Unit = {},
    onPauseServer: () -> Unit = {},
    onResumeServer: () -> Unit = {},
    onStopServer: () -> Unit = {}
) {
    val appContext = context.applicationContext
    val store = remember { SealedLocalStore(appContext) }
    val executor = remember { Executors.newSingleThreadExecutor() }
    val main = remember { Handler(Looper.getMainLooper()) }
    val conversations = remember { mutableStateListOf<JSONObject>() }
    val contacts = remember { mutableStateListOf<JSONObject>() }
    val nicknameInputs = remember { mutableStateMapOf<String, String>() }
    val messages = remember { mutableStateListOf<JSONObject>() }
    var selectedId by remember { mutableStateOf<String?>(null) }
    var selectedName by remember { mutableStateOf("") }
    var titleInput by remember { mutableStateOf("") }
    var contactInput by remember { mutableStateOf("") }
    var messageInput by remember { mutableStateOf("") }
    var editingMessageId by remember { mutableStateOf<String?>(null) }
    var searchInput by remember { mutableStateOf("") }
    val searchHits = remember { mutableStateListOf<JSONObject>() }
    var notice by remember { mutableStateOf("") }

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

    LaunchedEffect(Unit) { refreshChats(null); refreshContacts() }
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

    Box(Modifier.fillMaxSize().background(Brush.linearGradient(listOf(Color(0xFF182C3D), ChatInk, Color(0xFF30213D))))) {
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(18.dp), verticalArrangement = Arrangement.spacedBy(13.dp)) {
            ChatText("GLASSCHAT  ${if (owner) "OWNER" else "CLIENT"}", Color.White, 13, FontWeight.Bold)
            ChatText("Your private space", Color.White, 28, FontWeight.SemiBold)
            Panel {
                ChatText("LOCAL-ONLY FOUNDATION", ChatAccent, 11, FontWeight.Bold)
                Spacer(Modifier.height(6.dp))
                ChatText("Messages and contact records are saved encrypted on this device. This build does not send messages or implement end-to-end encryption; nothing reaches another person yet.", Color(0xFFE8E9F0), 14)
            }
            if (owner) Panel {
                ChatText("OWNER SERVICE", Color.White, 17, FontWeight.SemiBold)
                Spacer(Modifier.height(6.dp)); ChatText(ownerServiceStatus, ChatAccent, 13)
                Spacer(Modifier.height(4.dp)); ChatText("The foreground-service lifecycle is present, but no API, relay, registration authority or gateway is connected.", Color(0xFFBFC4D0), 13)
                Spacer(Modifier.height(10.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    SmallAction("Start", onStartServer)
                    SmallAction("Pause", onPauseServer, true)
                    SmallAction("Resume", onResumeServer, true)
                    SmallAction("Stop", onStopServer, true)
                }
            }
            Panel {
                ChatText("NEW CONVERSATION", Color.White, 16, FontWeight.SemiBold)
                Spacer(Modifier.height(8.dp))
                Entry(titleInput, { titleInput = it }, "Conversation name")
                Spacer(Modifier.height(8.dp))
                Entry(contactInput, { contactInput = it }, "Contact's GlassChat ID (stored locally only)")
                Spacer(Modifier.height(8.dp))
                SmallAction("Save contact and start local conversation") {
                    val label = titleInput.trim().ifBlank { contactInput.trim() }
                    if (label.isBlank()) notice = "Enter a conversation name or contact ID."
                    else {
                        val id = UUID.randomUUID().toString()
                        val now = System.currentTimeMillis()
                        val conversation = JSONObject().put("id", id).put("name", label).put("createdAt", now).put("kind", "local")
                        executor.execute {
                            try {
                                store.put("conversation", id, conversation, id, now)
                                if (contactInput.isNotBlank()) {
                                    val contactId = UUID.randomUUID().toString()
                                    store.put("contact", contactId, JSONObject().put("id", contactId).put("label", label).put("glasschatId", contactInput.trim()).put("createdAt", now), null, now)
                                }
                                main.post { titleInput = ""; contactInput = ""; notice = "Saved on this device only."; refreshChats(id); refreshContacts() }
                            } catch (e: Exception) { main.post { notice = "Could not save locally: ${e.message ?: "storage error"}" } }
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
                Spacer(Modifier.height(5.dp)); ChatText("Stored locally · not sent", ChatAccent, 12)
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
                if (messages.isEmpty()) ChatText("No messages yet.", Color(0xFFBFC4D0), 13)
                messages.forEach { item ->
                    val messageId = item.optString("id")
                    Spacer(Modifier.height(8.dp))
                    Panel {
                        ChatText(item.optString("sender", "You"), ChatAccent, 11, FontWeight.SemiBold)
                        Spacer(Modifier.height(3.dp))
                        ChatText(item.optString("text"), Color(0xFFE8E9F0), 14)
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
                SmallAction(if (editingMessageId == null) "Save message on this device" else "Save local edit") {
                    val text = messageInput.trim(); val conversationId = selectedId; val editingId = editingMessageId
                    if (text.isBlank() || conversationId == null) notice = "Write a message first."
                    else if (editingId != null) {
                        executor.execute {
                            try {
                                check(store.editLocalMessage(editingId, text)) { "Message no longer exists" }
                                main.post { messageInput = ""; editingMessageId = null; notice = "Edited this device’s copy only."; refreshChats(conversationId) }
                            } catch (e: Exception) { main.post { notice = "Could not edit local message: ${e.message ?: "storage error"}" } }
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
            ChatText("No remote account or service is configured.", Color(0xFF9FA6B5), 12)
        }
    }
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

@Composable private fun Panel(content: @Composable ColumnScope.() -> Unit) {
    Column(Modifier.fillMaxWidth().background(Color(0x30FFFFFF), RoundedCornerShape(21.dp)).border(1.dp, Color(0x42FFFFFF), RoundedCornerShape(21.dp)).padding(16.dp), content = content)
}

@Composable private fun SmallAction(label: String, action: () -> Unit, secondary: Boolean = false) {
    Box(Modifier.background(if (secondary) Color(0xFF343849) else Color(0xFF4D9C91), RoundedCornerShape(13.dp)).clickable(onClick = action).padding(horizontal = 12.dp, vertical = 10.dp), contentAlignment = Alignment.Center) {
        ChatText(label, Color.White, 12, FontWeight.Medium)
    }
}
