package com.glasschat.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class SupabaseRelayClientConfigurationTest {
    @Test
    fun acceptsHttpsProjectRootAndNormalizesTrailingSlash() {
        val client = SupabaseRelayClient(" https://project.example/ ", " public-anon-key ")

        // Construction is local-only; no request is made until a client operation is invoked.
        assertEquals("https://project.example", client.javaClass.getDeclaredField("root").apply {
            isAccessible = true
        }.get(client))
        assertEquals("public-anon-key", client.javaClass.getDeclaredField("anon").apply {
            isAccessible = true
        }.get(client))
    }

    @Test
    fun rejectsNonHttpsEndpoint() {
        assertThrows(IllegalArgumentException::class.java) {
            SupabaseRelayClient("http://project.example", "public-anon-key")
        }
    }

    @Test
    fun rejectsEndpointCredentials() {
        assertThrows(IllegalArgumentException::class.java) {
            SupabaseRelayClient("https://user:password@project.example", "public-anon-key")
        }
    }

    @Test
    fun rejectsEndpointQueryAndFragment() {
        assertThrows(IllegalArgumentException::class.java) {
            SupabaseRelayClient("https://project.example?token=x", "public-anon-key")
        }
        assertThrows(IllegalArgumentException::class.java) {
            SupabaseRelayClient("https://project.example#fragment", "public-anon-key")
        }
    }

    @Test
    fun rejectsEndpointPath() {
        assertThrows(IllegalArgumentException::class.java) {
            SupabaseRelayClient("https://project.example/dashboard", "public-anon-key")
        }
    }

    @Test
    fun rejectsBlankPublicKey() {
        assertThrows(IllegalArgumentException::class.java) {
            SupabaseRelayClient("https://project.example", "  ")
        }
    }
    @Test
    fun ownerNicknameUpdateRejectsInvalidOwnerIdBeforeNetworkAccess() {
        val client = SupabaseRelayClient("https://project.example", "public-anon-key")
        assertThrows(IllegalArgumentException::class.java) {
            client.setOwnerNickname("test-token", "not-a-uuid", "Owner name")
        }
    }

    @Test
    fun ownerNicknameUpdateRejectsOverlongNicknameBeforeNetworkAccess() {
        val client = SupabaseRelayClient("https://project.example", "public-anon-key")
        assertThrows(IllegalArgumentException::class.java) {
            client.setOwnerNickname("test-token", "123e4567-e89b-12d3-a456-426614174000", "x".repeat(81))
        }
    }

    @Test
    fun ownerNicknameActivityRejectsOutOfRangeLimitBeforeNetworkAccess() {
        val client = SupabaseRelayClient("https://project.example", "public-anon-key")
        assertThrows(IllegalArgumentException::class.java) {
            client.ownerListNicknameEvents("test-token", 201)
        }
    }

}
