package com.glasschat.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.text.BasicText
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

private val Ink = Color(0xFF10111D)
private val Glass = Color(0x30FFFFFF)
private val Accent = Color(0xFF87D8CB)

@Composable
fun GlassChatScreen(
    owner: Boolean,
    serviceStatus: String = "Stopped",
    notice: String = "",
    onStart: () -> Unit = {},
    onPause: () -> Unit = {},
    onResume: () -> Unit = {},
    onStop: () -> Unit = {}
) {
    Box(Modifier.fillMaxSize().background(Brush.linearGradient(listOf(Color(0xFF182C3D), Ink, Color(0xFF30213D))))) {
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(22.dp),
            verticalArrangement = Arrangement.spacedBy(18.dp)
        ) {
            GCText("GLASSCHAT", Color.White, 13, FontWeight.Bold, letterSpacing = 3.sp)
            GCText(if (owner) "Your private space" else "Messages, kept yours.", Color.White, 30, FontWeight.SemiBold)
            GlassCard {
                GCText("FOUNDATION BUILD", Accent, 11, FontWeight.Bold, letterSpacing = 1.8.sp)
                Spacer(Modifier.height(10.dp))
                GCText(
                    "This build is an early foundation, not yet a working messenger. Account services, conversations, encryption and the relay are still being built.",
                    Color(0xFFE8E9F0), 15, lineHeight = 22.sp
                )
            }
            GlassCard {
                GCText("CONVERSATIONS", Color.White, 18, FontWeight.SemiBold)
                Spacer(Modifier.height(6.dp))
                GCText(
                    "No conversations yet. Local encrypted storage and messaging are not implemented in this build.",
                    Color(0xFFBFC4D0), 14, lineHeight = 20.sp
                )
            }
            if (owner) {
                GlassCard {
                    GCText("OWNER SERVICE STATUS", Color.White, 18, FontWeight.SemiBold)
                    Spacer(Modifier.height(8.dp))
                    GCText(serviceStatus, Accent, 14)
                    Spacer(Modifier.height(8.dp))
                    GCText(
                        "Lifecycle controls and a persistent notification are implemented. No Owner API, account registry, database, relay, gateway or health checks are configured, so this service does not accept clients or deliver messages.",
                        Color(0xFFBFC4D0), 14, lineHeight = 20.sp
                    )
                    if (notice.isNotBlank()) {
                        Spacer(Modifier.height(8.dp))
                        GCText(notice, Color(0xFFFFC6A5), 13, lineHeight = 19.sp)
                    }
                    Spacer(Modifier.height(14.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        ActionButton("Start", onStart)
                        ActionButton("Pause", onPause, secondary = true)
                    }
                    Spacer(Modifier.height(10.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        ActionButton("Resume", onResume, secondary = true)
                        ActionButton("Stop", onStop, secondary = true)
                    }
                }
            }
            GCText(if (owner) "Owner edition · incomplete foundation" else "Client edition · incomplete foundation", Color(0xFF9FA6B5), 12)
        }
    }
}

@Composable
private fun GCText(
    text: String,
    color: Color,
    size: Int,
    weight: FontWeight = FontWeight.Normal,
    letterSpacing: androidx.compose.ui.unit.TextUnit = 0.sp,
    lineHeight: androidx.compose.ui.unit.TextUnit = androidx.compose.ui.unit.TextUnit.Unspecified
) {
    BasicText(text, style = TextStyle(color = color, fontSize = size.sp, fontWeight = weight, letterSpacing = letterSpacing, lineHeight = lineHeight))
}

@Composable
private fun GlassCard(content: @Composable ColumnScope.() -> Unit) {
    Column(
        Modifier.fillMaxWidth().background(Glass, RoundedCornerShape(24.dp))
            .border(1.dp, Color(0x42FFFFFF), RoundedCornerShape(24.dp)).padding(20.dp),
        content = content
    )
}

@Composable
private fun ActionButton(label: String, onClick: () -> Unit, secondary: Boolean = false) {
    Box(
        Modifier.background(if (secondary) Color(0xFF343849) else Color(0xFF4D9C91), RoundedCornerShape(16.dp))
            .clickable(onClick = onClick).padding(horizontal = 16.dp, vertical = 12.dp),
        contentAlignment = Alignment.Center
    ) { GCText(label, Color.White, 14, FontWeight.Medium) }
}
