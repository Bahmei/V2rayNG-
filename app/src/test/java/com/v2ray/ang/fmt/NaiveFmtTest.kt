package com.v2ray.ang.fmt

import com.v2ray.ang.AppConfig
import com.v2ray.ang.enums.EConfigType
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class NaiveFmtTest {

    @Test
    fun parseStandardNaiveHttps() {
        val uri = "naive+https://alice:secret123@example.com:443?sni=example.com&insecure=1#MyServer"
        val profile = NaiveFmt.parse(uri)

        assertEquals(EConfigType.NAIVE, profile.configType)
        assertEquals("example.com", profile.server)
        assertEquals("443", profile.serverPort)
        assertEquals("alice", profile.username)
        assertEquals("secret123", profile.password)
        assertEquals("example.com", profile.sni)
        assertEquals(true, profile.insecure)
        assertEquals("MyServer", profile.remarks)
        assertEquals("https", profile.network)
    }

    @Test
    fun parseNaiveQuic() {
        val uri = "naive+quic://user:pass@quic.example.org:8443#QuicNode"
        val profile = NaiveFmt.parse(uri)

        assertEquals(EConfigType.NAIVE, profile.configType)
        assertEquals("quic.example.org", profile.server)
        assertEquals("8443", profile.serverPort)
        assertEquals("user", profile.username)
        assertEquals("pass", profile.password)
        assertEquals("quic", profile.network)
        assertEquals("QuicNode", profile.remarks)
    }

    @Test
    fun roundTripNaiveUri() {
        val original = "naive+https://user:pass@example.com:443?sni=example.com&insecure=1&padding=true#TestNode"
        val profile = NaiveFmt.parse(original)
        val exported = NaiveFmt.toUri(profile)
        val reparsed = NaiveFmt.parse(exported)

        assertEquals(profile.server, reparsed.server)
        assertEquals(profile.serverPort, reparsed.serverPort)
        assertEquals(profile.username, reparsed.username)
        assertEquals(profile.password, reparsed.password)
        assertEquals(profile.sni, reparsed.sni)
        assertEquals(profile.insecure, reparsed.insecure)
        assertEquals(profile.remarks, reparsed.remarks)
    }
}
