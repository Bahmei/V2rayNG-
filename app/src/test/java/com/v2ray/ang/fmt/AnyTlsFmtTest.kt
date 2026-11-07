package com.v2ray.ang.fmt

import com.v2ray.ang.enums.EConfigType
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class AnyTlsFmtTest {

    @Test
    fun parseStandardAnyTlsWithUserinfo() {
        val uri = "anytls://mysecret@example.com:443?sni=example.org&insecure=1#FastNode"
        val profile = AnyTlsFmt.parse(uri)

        assertEquals(EConfigType.ANYTLS, profile.configType)
        assertEquals("example.com", profile.server)
        assertEquals("443", profile.serverPort)
        assertEquals("mysecret", profile.password)
        assertEquals("example.org", profile.sni)
        assertEquals(true, profile.insecure)
        assertEquals("FastNode", profile.remarks)
    }

    @Test
    fun parseAnyTlsWithPasswordQuery() {
        val uri = "anytls://example.com:8443?password=pass123&sni=sni.net#AnyNode"
        val profile = AnyTlsFmt.parse(uri)

        assertEquals(EConfigType.ANYTLS, profile.configType)
        assertEquals("example.com", profile.server)
        assertEquals("8443", profile.serverPort)
        assertEquals("pass123", profile.password)
        assertEquals("sni.net", profile.sni)
        assertEquals("AnyNode", profile.remarks)
    }

    @Test
    fun roundTripAnyTlsUri() {
        val original = "anytls://mysecret@example.com:443?sni=example.com&insecure=1#AnyTLSTest"
        val profile = AnyTlsFmt.parse(original)
        val exported = AnyTlsFmt.toUri(profile)
        val reparsed = AnyTlsFmt.parse(exported)

        assertEquals(profile.server, reparsed.server)
        assertEquals(profile.serverPort, reparsed.serverPort)
        assertEquals(profile.password, reparsed.password)
        assertEquals(profile.sni, reparsed.sni)
        assertEquals(profile.insecure, reparsed.insecure)
        assertEquals(profile.remarks, reparsed.remarks)
    }
}
