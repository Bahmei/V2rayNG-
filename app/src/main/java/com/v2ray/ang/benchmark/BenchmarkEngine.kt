package com.v2ray.ang.benchmark

import android.content.Context
import android.net.VpnService
import com.v2ray.ang.AppConfig
import com.v2ray.ang.core.CoreServiceManager
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.handler.SettingsManager
import com.v2ray.ang.util.LogUtil
import com.v2ray.ang.util.Utils
import okhttp3.Authenticator
import okhttp3.Credentials
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.Response
import okhttp3.Route
import okio.BufferedSink
import java.io.IOException
import java.io.Serializable
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.SocketFactory

data class BenchmarkResult(
    val guid: String,
    val pingMs: Long? = null,
    val jitterMs: Double? = null,
    val downloadSpeedMbps: Double? = null,
    val uploadSpeedMbps: Double? = null,
    val status: String = STATUS_SUCCESS,
    val errorMessage: String? = null,
    val timestamp: Long = System.currentTimeMillis(),
    val serverUsed: String = "",
) : Serializable {
    companion object {
        const val STATUS_SUCCESS = "SUCCESS"
        const val STATUS_FAILED = "FAILED"
        const val STATUS_UNSUPPORTED = "UNSUPPORTED"
        const val STATUS_CANCELLED = "CANCELLED"
    }
}

data class BenchmarkConfig(
    val serverUrl: String,
    val downloadDurationSec: Int,
    val uploadDurationSec: Int,
    val maxDownloadMb: Int,
    val maxUploadMb: Int,
    val pingCount: Int,
    val timeoutSec: Int,
    val latencyOnly: Boolean = false,
)

object BenchmarkEngine {

    /**
     * Executes the benchmark suite for the given profile and configuration.
     */
    fun runBenchmark(
        context: Context,
        guid: String,
        profile: ProfileItem,
        config: BenchmarkConfig,
        cancelFlag: AtomicBoolean,
        onProgress: (stepDescription: String) -> Unit = {}
    ): BenchmarkResult {
        if (cancelFlag.get()) {
            return BenchmarkResult(guid = guid, status = BenchmarkResult.STATUS_CANCELLED)
        }

        val serverHost = profile.server?.trim().orEmpty()
        val serverPort = profile.serverPort?.toIntOrNull() ?: 0

        if (serverHost.isBlank() || serverPort <= 0) {
            return BenchmarkResult(
                guid = guid,
                status = BenchmarkResult.STATUS_FAILED,
                errorMessage = "Invalid server host or port"
            )
        }

        // Build OkHttpClient routed through the isolated configuration tunnel
        val client = buildBenchmarkHttpClient(profile, config, cancelFlag)

        val pingEndpoint = resolvePingEndpoint(config.serverUrl)
        val downloadEndpoint = resolveDownloadEndpoint(config.serverUrl, config.maxDownloadMb)
        val uploadEndpoint = resolveUploadEndpoint(config.serverUrl)

        onProgress("Connecting & Ping…")
        // Phase 4 & 5: Repeated RTT measurements for Ping and Jitter
        val (pingMs, jitterMs) = measurePingAndJitter(
            client = client,
            pingUrl = pingEndpoint,
            rounds = config.pingCount,
            cancelFlag = cancelFlag
        )

        if (cancelFlag.get()) {
            return BenchmarkResult(guid = guid, status = BenchmarkResult.STATUS_CANCELLED)
        }

        if (pingMs == null || pingMs < 0) {
            return BenchmarkResult(
                guid = guid,
                pingMs = -1L,
                status = BenchmarkResult.STATUS_FAILED,
                errorMessage = "Connection timeout or unreachable",
                serverUsed = config.serverUrl
            )
        }

        if (config.latencyOnly) {
            return BenchmarkResult(
                guid = guid,
                pingMs = pingMs,
                jitterMs = jitterMs,
                status = BenchmarkResult.STATUS_SUCCESS,
                serverUsed = config.serverUrl
            )
        }

        onProgress("Testing Download…")
        // Phase 2: Real download throughput
        val downloadMbps = measureDownloadThroughput(
            client = client,
            downloadUrl = downloadEndpoint,
            durationSec = config.downloadDurationSec,
            maxBytes = config.maxDownloadMb * 1024L * 1024L,
            cancelFlag = cancelFlag
        )

        if (cancelFlag.get()) {
            return BenchmarkResult(
                guid = guid,
                pingMs = pingMs,
                jitterMs = jitterMs,
                downloadSpeedMbps = downloadMbps,
                status = BenchmarkResult.STATUS_CANCELLED
            )
        }

        onProgress("Testing Upload…")
        // Phase 3: Real upload throughput
        val uploadMbps = measureUploadThroughput(
            client = client,
            uploadUrl = uploadEndpoint,
            durationSec = config.uploadDurationSec,
            maxBytes = config.maxUploadMb * 1024L * 1024L,
            cancelFlag = cancelFlag
        )

        return BenchmarkResult(
            guid = guid,
            pingMs = pingMs,
            jitterMs = jitterMs,
            downloadSpeedMbps = downloadMbps,
            uploadSpeedMbps = uploadMbps,
            status = BenchmarkResult.STATUS_SUCCESS,
            serverUsed = config.serverUrl
        )
    }

    /**
     * Measures average latency and jitter using repeated HTTP RTT probes.
     * Jitter formula: Sum(|RTT[i] - RTT[i-1]|) / (N - 1)
     */
    fun measurePingAndJitter(
        client: OkHttpClient,
        pingUrl: String,
        rounds: Int,
        cancelFlag: AtomicBoolean
    ): Pair<Long?, Double?> {
        val successfulRtts = mutableListOf<Double>()

        // Warm-up request to establish steady-state connection
        try {
            val warmUpRequest = Request.Builder().url(pingUrl).head().build()
            client.newCall(warmUpRequest).execute().use { }
        } catch (_: Exception) {
            // Warm-up error can be ignored; subsequent probes will measure directly
        }

        for (i in 0 until rounds) {
            if (cancelFlag.get()) break
            val startNs = System.nanoTime()
            try {
                val req = Request.Builder().url(pingUrl).head().build()
                client.newCall(req).execute().use { resp ->
                    val rttMs = (System.nanoTime() - startNs) / 1_000_000.0
                    if (resp.isSuccessful || resp.code == 204) {
                        successfulRtts.add(rttMs)
                    }
                }
            } catch (e: Exception) {
                // If HEAD fails, try GET for endpoints that do not accept HEAD
                try {
                    val getReq = Request.Builder().url(pingUrl).get().build()
                    val getStart = System.nanoTime()
                    client.newCall(getReq).execute().use { resp ->
                        val rttMs = (System.nanoTime() - getStart) / 1_000_000.0
                        if (resp.isSuccessful || resp.code == 204) {
                            successfulRtts.add(rttMs)
                        }
                    }
                } catch (_: Exception) {
                    // Probe failed; ignore failed measurements per Phase 5
                }
            }
        }

        if (successfulRtts.isEmpty()) {
            return Pair(null, null)
        }

        val avgPing = successfulRtts.average().toLong()
        val jitter = calculateJitter(successfulRtts)
        return Pair(avgPing, jitter)
    }

    /**
     * Calculates Jitter as Mean Absolute Difference between consecutive measurements.
     * Formula: Jitter = Sum(|RTT[i] - RTT[i-1]|) / (N - 1)
     */
    fun calculateJitter(successfulRtts: List<Double>): Double? {
        if (successfulRtts.size < 2) return null
        var diffSum = 0.0
        for (i in 1 until successfulRtts.size) {
            diffSum += Math.abs(successfulRtts[i] - successfulRtts[i - 1])
        }
        return diffSum / (successfulRtts.size - 1)
    }

    /**
     * Calculates throughput in Mbps.
     * Formula: Throughput Mbps = (Bytes * 8) / (Elapsed Seconds * 1,000,000)
     */
    fun calculateThroughputMbps(bytes: Long, elapsedSec: Double): Double {
        if (elapsedSec <= 0.0 || bytes <= 0L) return 0.0
        return (bytes * 8.0) / (elapsedSec * 1_000_000.0)
    }

    /**
     * Measures download throughput in Mbps by streaming bytes from the benchmark endpoint.
     * Formula: Download Mbps = (Downloaded Bytes * 8) / (Elapsed Seconds * 1,000,000)
     */
    fun measureDownloadThroughput(
        client: OkHttpClient,
        downloadUrl: String,
        durationSec: Int,
        maxBytes: Long,
        cancelFlag: AtomicBoolean
    ): Double? {
        val request = Request.Builder().url(downloadUrl).get().build()
        val call = client.newCall(request)

        return try {
            val response = call.execute()
            if (!response.isSuccessful) {
                response.close()
                return null
            }
            val body = response.body ?: return null
            val inputStream = body.byteStream()
            val buffer = ByteArray(32 * 1024)

            val startTime = System.currentTimeMillis()
            val maxDurationMs = durationSec * 1000L
            val warmUpMs = 500L
            var warmUpBytes = 0L
            var measuredBytes = 0L
            var measurementStartTime = startTime
            var warmUpDone = false

            while (true) {
                if (cancelFlag.get()) {
                    call.cancel()
                    break
                }
                val now = System.currentTimeMillis()
                if (now - startTime >= maxDurationMs) {
                    break
                }
                val read = inputStream.read(buffer)
                if (read == -1) break

                if (!warmUpDone) {
                    warmUpBytes += read
                    if (now - startTime >= warmUpMs) {
                        warmUpDone = true
                        measurementStartTime = System.currentTimeMillis()
                        measuredBytes = 0L
                    }
                } else {
                    measuredBytes += read
                    if (measuredBytes >= maxBytes) break
                }
            }
            body.close()

            val elapsedSec = (System.currentTimeMillis() - measurementStartTime) / 1000.0
            if (elapsedSec > 0.1 && measuredBytes > 0) {
                (measuredBytes * 8.0) / (elapsedSec * 1_000_000.0)
            } else if (warmUpBytes > 0) {
                val totalSec = (System.currentTimeMillis() - startTime) / 1000.0
                ((warmUpBytes + measuredBytes) * 8.0) / (totalSec * 1_000_000.0)
            } else {
                null
            }
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "Download test exception: ${e.message}")
            null
        }
    }

    /**
     * Measures upload throughput in Mbps by streaming bytes to the benchmark endpoint.
     * Formula: Upload Mbps = (Successfully Uploaded Bytes * 8) / (Elapsed Seconds * 1,000,000)
     */
    fun measureUploadThroughput(
        client: OkHttpClient,
        uploadUrl: String,
        durationSec: Int,
        maxBytes: Long,
        cancelFlag: AtomicBoolean
    ): Double? {
        var totalWritten = 0L
        val startTime = System.currentTimeMillis()
        val maxDurationMs = durationSec * 1000L

        val requestBody = object : RequestBody() {
            override fun contentType() = "application/octet-stream".toMediaTypeOrNull()

            override fun contentLength(): Long = -1 // Chunked streaming

            override fun writeTo(sink: BufferedSink) {
                val chunk = ByteArray(32 * 1024) { (it % 256).toByte() }
                while (totalWritten < maxBytes) {
                    if (cancelFlag.get()) break
                    val elapsed = System.currentTimeMillis() - startTime
                    if (elapsed >= maxDurationMs) break

                    val toWrite = minOf(chunk.size.toLong(), maxBytes - totalWritten).toInt()
                    sink.write(chunk, 0, toWrite)
                    sink.flush()
                    totalWritten += toWrite
                }
            }
        }

        val request = Request.Builder().url(uploadUrl).post(requestBody).build()
        val call = client.newCall(request)

        return try {
            val response = call.execute()
            val elapsedSec = (System.currentTimeMillis() - startTime) / 1000.0
            response.close()

            if (response.isSuccessful || response.code in 200..299) {
                if (elapsedSec > 0.1 && totalWritten > 0) {
                    (totalWritten * 8.0) / (elapsedSec * 1_000_000.0)
                } else {
                    null
                }
            } else if (response.code in listOf(404, 405, 501)) {
                // Upload not supported on this endpoint
                null
            } else {
                null
            }
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "Upload test exception: ${e.message}")
            null
        }
    }

    /**
     * Builds an OkHttpClient configured to route through the specified profile and
     * protect its sockets from active VPN loops.
     */
    fun buildBenchmarkHttpClient(
        profile: ProfileItem,
        config: BenchmarkConfig,
        cancelFlag: AtomicBoolean
    ): OkHttpClient {
        val builder = OkHttpClient.Builder()
            .connectTimeout(config.timeoutSec.toLong(), TimeUnit.SECONDS)
            .readTimeout(config.timeoutSec.toLong(), TimeUnit.SECONDS)
            .writeTimeout(config.timeoutSec.toLong(), TimeUnit.SECONDS)
            .retryOnConnectionFailure(false)

        // Protect sockets against active Android VPN routing loops
        val socketFactory = VpnProtectedSocketFactory { socket ->
            try {
                val service = CoreServiceManager.serviceControl?.get()?.getService()
                if (service is VpnService) {
                    service.protect(socket)
                } else {
                    false
                }
            } catch (_: Throwable) {
                false
            }
        }
        builder.socketFactory(socketFactory)

        // Configure proxy routing per protocol
        when (profile.configType) {
            EConfigType.HTTP -> {
                val server = profile.server.orEmpty()
                val port = profile.serverPort?.toIntOrNull() ?: AppConfig.DEFAULT_PORT
                builder.proxy(Proxy(Proxy.Type.HTTP, InetSocketAddress(server, port)))
                if (!profile.username.isNullOrEmpty() || !profile.password.isNullOrEmpty()) {
                    builder.proxyAuthenticator(object : Authenticator {
                        override fun authenticate(route: Route?, response: Response): Request? {
                            val credential = Credentials.basic(
                                profile.username.orEmpty(),
                                profile.password.orEmpty()
                            )
                            return response.request.newBuilder()
                                .header("Proxy-Authorization", credential)
                                .build()
                        }
                    })
                }
            }

            EConfigType.SOCKS -> {
                val server = profile.server.orEmpty()
                val port = profile.serverPort?.toIntOrNull() ?: AppConfig.DEFAULT_PORT
                builder.proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress(server, port)))
            }

            else -> {
                // For other protocols, check if local proxy sharing or core port is configured
                val localPort = SettingsManager.getHttpPort()
                if (localPort > 0 && CoreServiceManager.isRunning()) {
                    builder.proxy(Proxy(Proxy.Type.HTTP, InetSocketAddress(AppConfig.LOOPBACK, localPort)))
                }
            }
        }

        return builder.build()
    }

    fun resolvePingEndpoint(baseUrl: String): String {
        return if (baseUrl.contains("cloudflare", ignoreCase = true)) {
            "https://speed.cloudflare.com/__down?bytes=0"
        } else if (baseUrl.contains("libre", ignoreCase = true)) {
            baseUrl.trimEnd('/') + "/empty.php"
        } else if (baseUrl.isNotBlank()) {
            baseUrl
        } else {
            SettingsManager.getDelayTestUrl()
        }
    }

    fun resolveDownloadEndpoint(baseUrl: String, maxMb: Int): String {
        val cleanUrl = baseUrl.trimEnd('/')
        return when {
            cleanUrl.contains("cloudflare", ignoreCase = true) -> {
                "$cleanUrl/__down?bytes=${maxMb * 1024L * 1024L}"
            }
            cleanUrl.contains("libre", ignoreCase = true) -> {
                "$cleanUrl/garbage.php?ckSize=$maxMb"
            }
            cleanUrl.endsWith("/download") || cleanUrl.contains("download") -> {
                cleanUrl
            }
            else -> {
                "$cleanUrl/__down?bytes=${maxMb * 1024L * 1024L}"
            }
        }
    }

    fun resolveUploadEndpoint(baseUrl: String): String {
        val cleanUrl = baseUrl.trimEnd('/')
        return when {
            cleanUrl.contains("cloudflare", ignoreCase = true) -> {
                "$cleanUrl/__up"
            }
            cleanUrl.contains("libre", ignoreCase = true) -> {
                "$cleanUrl/empty.php"
            }
            cleanUrl.endsWith("/upload") || cleanUrl.contains("upload") -> {
                cleanUrl
            }
            else -> {
                "$cleanUrl/__up"
            }
        }
    }
}

/**
 * SocketFactory that ensures all sockets created bypass any active Android VpnService tunnel.
 */
class VpnProtectedSocketFactory(
    private val protectCallback: (Socket) -> Boolean
) : SocketFactory() {
    private val delegate = getDefault()

    override fun createSocket(): Socket {
        val socket = delegate.createSocket()
        protectCallback(socket)
        return socket
    }

    override fun createSocket(host: String, port: Int): Socket {
        val socket = delegate.createSocket(host, port)
        protectCallback(socket)
        return socket
    }

    override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket {
        val socket = delegate.createSocket(host, port, localHost, localPort)
        protectCallback(socket)
        return socket
    }

    override fun createSocket(host: InetAddress, port: Int): Socket {
        val socket = delegate.createSocket(host, port)
        protectCallback(socket)
        return socket
    }

    override fun createSocket(address: InetAddress, port: Int, localAddress: InetAddress, localPort: Int): Socket {
        val socket = delegate.createSocket(address, port, localAddress, localPort)
        protectCallback(socket)
        return socket
    }
}
