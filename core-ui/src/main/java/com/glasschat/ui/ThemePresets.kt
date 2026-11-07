package com.glasschat.ui

import androidx.compose.ui.graphics.Color

/** Preset colors for the local theme picker. These change presentation only. */
data class GlassThemePreset(
    val id: String,
    val label: String,
    val backgroundTop: Color,
    val backgroundMiddle: Color,
    val backgroundBottom: Color,
    val accent: Color,
    val swatch: Color
)

val glassThemePresets = listOf(
    GlassThemePreset("liquid", "Liquid Glass", Color(0xFF182C3D), Color(0xFF10111D), Color(0xFF30213D), Color(0xFF87D8CB), Color(0xFF87D8CB)),
    GlassThemePreset("black_edge", "Black Edge", Color(0xFF18191D), Color(0xFF08090B), Color(0xFF25262B), Color(0xFFB7C5D8), Color(0xFFB7C5D8)),
    GlassThemePreset("crystal", "Crystal", Color(0xFF3B586B), Color(0xFF182A3B), Color(0xFF3F3A57), Color(0xFFB7E5F2), Color(0xFFB7E5F2)),
    GlassThemePreset("midnight", "Midnight", Color(0xFF18294D), Color(0xFF090F20), Color(0xFF241C43), Color(0xFF9CB8FF), Color(0xFF9CB8FF)),
    GlassThemePreset("gwen", "I Love Gwen", Color(0xFF572C4C), Color(0xFF21162A), Color(0xFF4B2742), Color(0xFFFFA7CC), Color(0xFFFFA7CC)),
    GlassThemePreset("aurora", "Aurora", Color(0xFF164C50), Color(0xFF111B31), Color(0xFF40305D), Color(0xFF8CE8C8), Color(0xFF8CE8C8)),
    GlassThemePreset("sunset", "Sunset", Color(0xFF704331), Color(0xFF2C1F36), Color(0xFF632F4B), Color(0xFFFFB078), Color(0xFFFFB078)),
    GlassThemePreset("cyber", "Cyber", Color(0xFF242653), Color(0xFF0E1227), Color(0xFF3C2454), Color(0xFF73E6E0), Color(0xFF73E6E0))
)

fun glassTheme(id: String): GlassThemePreset = glassThemePresets.firstOrNull { it.id == id } ?: glassThemePresets.first()
