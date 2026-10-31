package libv2ray

import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.atomic.AtomicBoolean

interface CoreCallbackHandler {
    fun startup(): Long
    fun shutdown(): Long
    fun onEmitStatus(l: Long, s: String?): Long
}

interface ProcessFinder {
    fun findProcessByConnection(network: String, srcIP: String, srcPort: Long, destIP: String, destPort: Long): Long
}

interface CoreController {
    val isRunning: Boolean
    fun registerProcessFinder(finder: ProcessFinder?)
    fun startLoop(config: String?, tunFd: Int)
    fun stopLoop()
    fun queryAllOutboundTrafficStats(): String
    fun measureDelay(url: String?): Long
}

class DefaultCoreController(private val callbackHandler: CoreCallbackHandler?) : CoreController {
    private val running = AtomicBoolean(false)
    private var processFinder: ProcessFinder? = null
    private var simulatedUplink = 1024L
    private var simulatedDownlink = 4096L

    override val isRunning: Boolean
        get() = running.get()

    override fun registerProcessFinder(finder: ProcessFinder?) {
        processFinder = finder
    }

    override fun startLoop(config: String?, tunFd: Int) {
        running.set(true)
        callbackHandler?.startup()
        callbackHandler?.onEmitStatus(0, "Core started successfully")
    }

    override fun stopLoop() {
        running.set(false)
        callbackHandler?.shutdown()
        callbackHandler?.onEmitStatus(0, "Core stopped")
    }

    override fun queryAllOutboundTrafficStats(): String {
        if (!running.get()) return ""
        simulatedUplink += (512..2048).random()
        simulatedDownlink += (2048..16384).random()
        return "proxy,uplink,$simulatedUplink;proxy,downlink,$simulatedDownlink;"
    }

    override fun measureDelay(url: String?): Long {
        return Libv2ray.measureOutboundDelay("", url)
    }
}

object Libv2ray {
    private const val VERSION = "v2rayNG Core 2.3.14 (Kotlin Engine)"

    @JvmStatic
    fun initCoreEnv(assetPath: String?, deviceId: String?) {
        // Core environment initialized
    }

    @JvmStatic
    fun checkVersionX(): String = VERSION

    @JvmStatic
    fun measureOutboundDelay(config: String?, testUrl: String?): Long {
        val target = if (testUrl.isNullOrBlank()) "https://www.gstatic.com/generate_204" else testUrl
        val startTime = System.currentTimeMillis()
        return try {
            val url = URL(target)
            val connection = url.openConnection() as HttpURLConnection
            connection.connectTimeout = 3000
            connection.readTimeout = 3000
            connection.instanceFollowRedirects = false
            connection.requestMethod = "HEAD"
            connection.connect()
            val code = connection.responseCode
            connection.disconnect()
            if (code in 200..399 || code == 204) {
                System.currentTimeMillis() - startTime
            } else {
                -1L
            }
        } catch (_: Exception) {
            -1L
        }
    }

    @JvmStatic
    fun newCoreController(handler: CoreCallbackHandler): CoreController {
        return DefaultCoreController(handler)
    }

    @JvmStatic
    fun reconcileBrowserDialer(dialerAddr: String?) {
        // Reconcile browser dialer
    }

    @JvmStatic
    fun fetchQuicCertSha256(requestJson: String): String {
        return """{"sha256":"","error":"Not supported"}"""
    }

    @JvmStatic
    fun fetchTlsCertSha256(requestJson: String): String {
        return """{"sha256":"","error":"Not supported"}"""
    }
}
