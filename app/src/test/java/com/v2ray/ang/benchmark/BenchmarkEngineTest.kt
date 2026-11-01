package com.v2ray.ang.benchmark

import com.google.gson.Gson
import com.v2ray.ang.dto.entities.ServerAffiliationInfo
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class BenchmarkEngineTest {

    @Test
    fun test_calculateJitter_emptyOrSingle() {
        assertNull(BenchmarkEngine.calculateJitter(emptyList()))
        assertNull(BenchmarkEngine.calculateJitter(listOf(120.0)))
    }

    @Test
    fun test_calculateJitter_mathematicalCorrectness() {
        // Given consecutive RTT measurements: 100ms, 110ms, 95ms, 105ms
        // Diffs: |110 - 100| = 10, |95 - 110| = 15, |105 - 95| = 10
        // diffSum = 35.0, count = 4, pairs = 3 -> jitter = 35.0 / 3 = 11.6666...
        val rtts = listOf(100.0, 110.0, 95.0, 105.0)
        val jitter = BenchmarkEngine.calculateJitter(rtts)
        assertNotNull(jitter)
        assertEquals(35.0 / 3.0, jitter!!, 0.0001)
    }

    @Test
    fun test_calculateJitter_zeroJitter() {
        val rtts = listOf(50.0, 50.0, 50.0, 50.0)
        val jitter = BenchmarkEngine.calculateJitter(rtts)
        assertNotNull(jitter)
        assertEquals(0.0, jitter!!, 0.0001)
    }

    @Test
    fun test_calculateThroughputMbps_formula() {
        // Formula: Download/Upload Mbps = (Bytes * 8) / (Elapsed Seconds * 1,000,000)
        // 12,500,000 bytes transferred in 1.0 second = 100,000,000 bits / 1,000,000 = 100.0 Mbps
        val throughput = BenchmarkEngine.calculateThroughputMbps(12_500_000L, 1.0)
        assertEquals(100.0, throughput, 0.0001)

        // 10 Megabytes (10 * 1024 * 1024 = 10,485,760 bytes) in 2 seconds
        val throughput2 = BenchmarkEngine.calculateThroughputMbps(10_485_760L, 2.0)
        assertEquals(41.94304, throughput2, 0.0001)

        // 0 bytes or zero duration
        assertEquals(0.0, BenchmarkEngine.calculateThroughputMbps(0L, 1.0), 0.0001)
        assertEquals(0.0, BenchmarkEngine.calculateThroughputMbps(1000L, 0.0), 0.0001)
    }

    @Test
    fun test_endpointResolution_cloudflare() {
        val base = "https://speed.cloudflare.com"
        val ping = BenchmarkEngine.resolvePingEndpoint(base)
        val down = BenchmarkEngine.resolveDownloadEndpoint(base, 25)
        val up = BenchmarkEngine.resolveUploadEndpoint(base)

        assertTrue(ping.contains("__down?bytes=0"))
        assertTrue(down.contains("__down?bytes=26214400")) // 25 MB in bytes
        assertTrue(up.contains("__up"))
    }

    @Test
    fun test_endpointResolution_librespeed() {
        val base = "https://librespeed.example.com"
        val ping = BenchmarkEngine.resolvePingEndpoint(base)
        val down = BenchmarkEngine.resolveDownloadEndpoint(base, 10)
        val up = BenchmarkEngine.resolveUploadEndpoint(base)

        assertTrue(ping.contains("/empty.php") || ping.contains("/speedtest"))
        assertTrue(down.contains("/garbage.php"))
        assertTrue(up.contains("/empty.php"))
    }

    @Test
    fun test_serverAffiliationInfo_backwardCompatibility() {
        val gson = Gson()

        // Legacy JSON without any benchmark metrics
        val legacyJson = """{"testDelayMillis":120}"""
        val legacyObj = gson.fromJson(legacyJson, ServerAffiliationInfo::class.java)

        assertEquals(120L, legacyObj.testDelayMillis)
        assertNull(legacyObj.downloadSpeedMbps)
        assertNull(legacyObj.uploadSpeedMbps)
        assertNull(legacyObj.pingMs)
        assertNull(legacyObj.jitterMs)
        assertNull(legacyObj.testStatus)

        // Benchmark JSON with full 4-metric results
        val benchmarkObj = ServerAffiliationInfo(
            testDelayMillis = 65L,
            downloadSpeedMbps = 85.42,
            uploadSpeedMbps = 24.18,
            pingMs = 65L,
            jitterMs = 4.25,
            testStatus = "SUCCESS",
            testTimestamp = 1700000000000L,
            benchmarkServer = "https://speed.cloudflare.com"
        )
        val serialized = gson.toJson(benchmarkObj)
        val deserialized = gson.fromJson(serialized, ServerAffiliationInfo::class.java)

        assertEquals(65L, deserialized.testDelayMillis)
        assertEquals(85.42, deserialized.downloadSpeedMbps!!, 0.001)
        assertEquals(24.18, deserialized.uploadSpeedMbps!!, 0.001)
        assertEquals(65L, deserialized.pingMs)
        assertEquals(4.25, deserialized.jitterMs!!, 0.001)
        assertEquals("SUCCESS", deserialized.testStatus)
        assertEquals(1700000000000L, deserialized.testTimestamp)
        assertEquals("https://speed.cloudflare.com", deserialized.benchmarkServer)
    }
}
