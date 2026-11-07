package com.v2ray.ang.core

import android.util.Base64
import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.handler.SettingsManager
import com.v2ray.ang.util.LogUtil
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.PushbackInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * High-performance dual-protocol (SOCKS5 & HTTP Proxy) local proxy engine.
 * Handles app traffic via Android VpnService Direct HTTP Proxy and SOCKS5 inbounds,
 * routing all connections through NaïveProxy, AnyTLS, or other configured outbounds.
 */
object LocalProxyEngine {

    private val runningState = AtomicBoolean(false)
    private val serverSockets = ConcurrentHashMap.newKeySet<ServerSocket>()
    private var udpSocket: DatagramSocket? = null
    private var executor: ExecutorService? = null
    private val activeSockets = ConcurrentHashMap.newKeySet<Socket>()

    val uplinkBytes = AtomicLong(0L)
    val downlinkBytes = AtomicLong(0L)

    private var activeProfile: ProfileItem? = null

    fun isRunning(): Boolean = runningState.get()

    fun start(profile: ProfileItem?, port: Int = SettingsManager.getSocksPort()) {
        if (runningState.get()) {
            stop()
        }

        activeProfile = profile ?: MmkvManager.getSelectServer()?.let { MmkvManager.decodeServerConfig(it) }
        runningState.set(true)
        executor = Executors.newCachedThreadPool()

        val socksPort = port
        val httpPort = SettingsManager.getHttpPort()

        // 1. Start listener on socksPort (10808)
        startListener(socksPort, "SOCKS5/HTTP")

        // 2. Start listener on httpPort (10809) if different
        if (httpPort != socksPort) {
            startListener(httpPort, "HTTP/SOCKS5")
        }
    }

    fun stop() {
        runningState.set(false)
        serverSockets.forEach {
            try {
                it.close()
            } catch (_: Exception) {}
        }
        serverSockets.clear()

        try {
            udpSocket?.close()
        } catch (_: Exception) {}
        udpSocket = null

        activeSockets.forEach { safeClose(it) }
        activeSockets.clear()

        executor?.shutdownNow()
        executor = null
        LogUtil.i(AppConfig.TAG, "LocalProxyEngine: Stopped")
    }

    private fun startListener(port: Int, name: String) {
        executor?.submit {
            try {
                val sSocket = ServerSocket()
                sSocket.reuseAddress = true
                sSocket.bind(InetSocketAddress(AppConfig.LOOPBACK, port))
                serverSockets.add(sSocket)
                LogUtil.i(AppConfig.TAG, "LocalProxyEngine: Listening for $name on 127.0.0.1:$port")

                while (runningState.get() && !sSocket.isClosed) {
                    try {
                        val client = sSocket.accept()
                        client.tcpNoDelay = true
                        activeSockets.add(client)
                        executor?.submit {
                            try {
                                handleIncomingClient(client)
                            } catch (_: Exception) {
                            } finally {
                                activeSockets.remove(client)
                                safeClose(client)
                            }
                        }
                    } catch (e: Exception) {
                        if (!runningState.get()) break
                    }
                }
            } catch (e: Exception) {
                LogUtil.e(AppConfig.TAG, "LocalProxyEngine: Server error on port $port", e)
            }
        }
    }

    private fun handleIncomingClient(client: Socket) {
        val rawIn = client.getInputStream()
        val pushback = PushbackInputStream(BufferedInputStream(rawIn, 16384), 8)
        val firstByte = pushback.read()
        if (firstByte == -1) return
        pushback.unread(firstByte)

        if (firstByte == 0x05) {
            handleSocks5Client(client, pushback)
        } else {
            handleHttpClient(client, pushback)
        }
    }

    //region SOCKS5 Protocol Handling
    private fun handleSocks5Client(client: Socket, inStream: InputStream) {
        val outStream = BufferedOutputStream(client.getOutputStream(), 16384)

        // 1. SOCKS5 Greeting
        val ver = inStream.read()
        if (ver != 5) return
        val nMethods = inStream.read()
        if (nMethods <= 0) return
        val methods = ByteArray(nMethods)
        inStream.readFully(methods)

        // Reply: No Auth Required (0x05, 0x00)
        outStream.write(byteArrayOf(0x05, 0x00))
        outStream.flush()

        // 2. SOCKS5 Request
        val reqVer = inStream.read()
        if (reqVer != 5) return
        val cmd = inStream.read()
        val rsv = inStream.read()
        val atyp = inStream.read()

        val targetHost: String
        when (atyp) {
            1 -> {
                // IPv4
                val ipBytes = ByteArray(4)
                inStream.readFully(ipBytes)
                targetHost = InetAddress.getByAddress(ipBytes).hostAddress ?: return
            }
            3 -> {
                // Domain name
                val len = inStream.read()
                if (len <= 0) return
                val domainBytes = ByteArray(len)
                inStream.readFully(domainBytes)
                targetHost = String(domainBytes, Charsets.UTF_8)
            }
            4 -> {
                // IPv6
                val ipBytes = ByteArray(16)
                inStream.readFully(ipBytes)
                targetHost = InetAddress.getByAddress(ipBytes).hostAddress ?: return
            }
            else -> return
        }

        val portHi = inStream.read()
        val portLo = inStream.read()
        if (portHi < 0 || portLo < 0) return
        val targetPort = (portHi shl 8) or portLo

        when (cmd) {
            1 -> {
                // CMD_CONNECT
                val remoteSocket = connectToRemote(targetHost, targetPort)
                if (remoteSocket != null) {
                    // Send SOCKS5 Success (0x00)
                    outStream.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                    outStream.flush()
                    pipeBidirectional(client, inStream, outStream, remoteSocket)
                } else {
                    outStream.write(byteArrayOf(0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                    outStream.flush()
                }
            }
            3 -> {
                // CMD_UDP_ASSOCIATE
                handleUdpAssociate(client, outStream)
            }
            else -> {
                outStream.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                outStream.flush()
            }
        }
    }
    //endregion

    //region HTTP Proxy Protocol Handling
    private fun handleHttpClient(client: Socket, inStream: InputStream) {
        val outStream = BufferedOutputStream(client.getOutputStream(), 16384)
        val initialLine = readLine(inStream)
        if (initialLine.isBlank()) return

        val parts = initialLine.split(" ")
        if (parts.size < 2) return
        val method = parts[0].uppercase()
        val target = parts[1]

        val targetHost: String
        val targetPort: Int

        if (method == "CONNECT") {
            // HTTPS Tunnel via CONNECT host:port
            val hp = target.split(":")
            targetHost = hp[0].removePrefix("[").removeSuffix("]")
            targetPort = hp.getOrNull(1)?.toIntOrNull() ?: 443

            // Read headers until blank line
            while (true) {
                val line = readLine(inStream)
                if (line.isEmpty() || line == "\r") break
            }

            val remoteSocket = connectToRemote(targetHost, targetPort)
            if (remoteSocket != null) {
                outStream.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray(Charsets.ISO_8859_1))
                outStream.flush()
                pipeBidirectional(client, inStream, outStream, remoteSocket)
            } else {
                outStream.write("HTTP/1.1 502 Bad Gateway\r\n\r\n".toByteArray(Charsets.ISO_8859_1))
                outStream.flush()
            }
        } else {
            // Direct HTTP (GET, POST, etc.)
            var hostHeader: String? = null
            val headerLines = mutableListOf<String>()
            while (true) {
                val line = readLine(inStream)
                if (line.isEmpty() || line == "\r") break
                if (line.startsWith("Host:", ignoreCase = true)) {
                    hostHeader = line.substring(5).trim()
                }
                if (!line.startsWith("Proxy-Connection:", ignoreCase = true)) {
                    headerLines.add(line)
                }
            }
            headerLines.add("Connection: close")

            val uriStr = if (target.startsWith("http://", ignoreCase = true)) {
                target.substring(7)
            } else {
                target
            }
            val slashIdx = uriStr.indexOf('/')
            val hostPortStr = if (slashIdx != -1) uriStr.substring(0, slashIdx) else uriStr
            val path = if (slashIdx != -1) uriStr.substring(slashIdx) else "/"

            val hp = (hostHeader ?: hostPortStr).split(":")
            targetHost = hp[0].removePrefix("[").removeSuffix("]")
            targetPort = hp.getOrNull(1)?.toIntOrNull() ?: 80

            val remoteSocket = connectToRemote(targetHost, targetPort)
            if (remoteSocket != null) {
                val remoteOut = BufferedOutputStream(remoteSocket.getOutputStream(), 16384)
                val rewrittenReq = "$method $path ${parts.getOrNull(2) ?: "HTTP/1.1"}\r\n" +
                        headerLines.joinToString("\r\n") + "\r\n\r\n"
                remoteOut.write(rewrittenReq.toByteArray(Charsets.ISO_8859_1))
                remoteOut.flush()
                pipeBidirectional(client, inStream, outStream, remoteSocket)
            } else {
                outStream.write("HTTP/1.1 502 Bad Gateway\r\n\r\n".toByteArray(Charsets.ISO_8859_1))
                outStream.flush()
            }
        }
    }
    //endregion

    //region Remote Connection & Streaming
    private fun connectToRemote(targetHost: String, targetPort: Int): Socket? {
        val profile = activeProfile ?: MmkvManager.getSelectServer()?.let { MmkvManager.decodeServerConfig(it) }
        return try {
            val remoteSocket: Socket = when {
                profile != null && profile.configType == EConfigType.NAIVE -> {
                    connectViaNaiveProxy(profile, targetHost, targetPort)
                }
                profile != null && profile.configType == EConfigType.ANYTLS -> {
                    connectViaAnyTls(profile, targetHost, targetPort)
                }
                profile != null && !profile.server.isNullOrBlank() && profile.serverPort?.toIntOrNull() != null -> {
                    connectDirectOrProxy(profile, targetHost, targetPort)
                }
                else -> {
                    val raw = Socket()
                    CoreServiceManager.protect(raw)
                    raw.connect(InetSocketAddress(targetHost, targetPort), 10000)
                    raw
                }
            }
            activeSockets.add(remoteSocket)
            remoteSocket.tcpNoDelay = true
            remoteSocket
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "LocalProxyEngine: Failed to connect to $targetHost:$targetPort: ${e.message}")
            null
        }
    }

    private fun pipeBidirectional(
        clientSocket: Socket,
        clientIn: InputStream,
        clientOut: OutputStream,
        remoteSocket: Socket
    ) {
        val remoteIn = BufferedInputStream(remoteSocket.getInputStream(), 16384)
        val remoteOut = BufferedOutputStream(remoteSocket.getOutputStream(), 16384)

        val t1 = Thread({
            pipeStreams(clientIn, remoteOut, uplinkBytes)
            safeClose(remoteSocket)
            safeClose(clientSocket)
        }, "LocalProxy-UpPipe")

        val t2 = Thread({
            pipeStreams(remoteIn, clientOut, downlinkBytes)
            safeClose(clientSocket)
            safeClose(remoteSocket)
        }, "LocalProxy-DownPipe")

        t1.isDaemon = true
        t2.isDaemon = true
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    }

    private fun connectViaNaiveProxy(profile: ProfileItem, targetHost: String, targetPort: Int): Socket {
        val rawSocket = Socket()
        CoreServiceManager.protect(rawSocket)
        val server = profile.server.orEmpty()
        val port = profile.serverPort?.toIntOrNull() ?: 443
        rawSocket.connect(InetSocketAddress(server, port), 10000)
        rawSocket.tcpNoDelay = true

        val sslSocket = createSSLSocket(
            rawSocket = rawSocket,
            host = server,
            port = port,
            sni = profile.sni ?: server,
            insecure = profile.insecure == true
        )

        val out = BufferedOutputStream(sslSocket.getOutputStream(), 4096)
        val inStream = BufferedInputStream(sslSocket.getInputStream(), 4096)

        val auth = if (!profile.username.isNullOrEmpty() || !profile.password.isNullOrEmpty()) {
            val cred = "${profile.username.orEmpty()}:${profile.password.orEmpty()}"
            "Proxy-Authorization: Basic ${Base64.encodeToString(cred.toByteArray(), Base64.NO_WRAP)}\r\n"
        } else {
            ""
        }

        val connectReq = "CONNECT $targetHost:$targetPort HTTP/1.1\r\n" +
                "Host: $targetHost:$targetPort\r\n" +
                auth +
                "User-Agent: Mozilla/5.0 (Android; Mobile)\r\n" +
                "Proxy-Connection: Keep-Alive\r\n" +
                "\r\n"

        out.write(connectReq.toByteArray(Charsets.ISO_8859_1))
        out.flush()

        val statusLine = readLine(inStream)
        if (!statusLine.contains("200")) {
            safeClose(sslSocket)
            error("NaïveProxy connection rejected: $statusLine")
        }

        while (true) {
            val line = readLine(inStream)
            if (line.isEmpty() || line == "\r") break
        }

        return sslSocket
    }

    private fun connectViaAnyTls(profile: ProfileItem, targetHost: String, targetPort: Int): Socket {
        val rawSocket = Socket()
        CoreServiceManager.protect(rawSocket)
        val server = profile.server.orEmpty()
        val port = profile.serverPort?.toIntOrNull() ?: 443
        rawSocket.connect(InetSocketAddress(server, port), 10000)
        rawSocket.tcpNoDelay = true

        val sslSocket = createSSLSocket(
            rawSocket = rawSocket,
            host = server,
            port = port,
            sni = profile.sni ?: server,
            insecure = profile.insecure == true
        )

        val out = BufferedOutputStream(sslSocket.getOutputStream(), 4096)
        val inStream = BufferedInputStream(sslSocket.getInputStream(), 4096)

        val password = profile.password.orEmpty()
        val authHeader = if (password.isNotEmpty()) {
            "Proxy-Authorization: Basic ${Base64.encodeToString(":$password".toByteArray(), Base64.NO_WRAP)}\r\n" +
                    "X-AnyTLS-Password: $password\r\n"
        } else ""

        val connectReq = "CONNECT $targetHost:$targetPort HTTP/1.1\r\n" +
                "Host: $targetHost:$targetPort\r\n" +
                authHeader +
                "User-Agent: Mozilla/5.0 (Android; Mobile)\r\n" +
                "Proxy-Connection: Keep-Alive\r\n" +
                "\r\n"

        out.write(connectReq.toByteArray(Charsets.ISO_8859_1))
        out.flush()

        val statusLine = readLine(inStream)
        if (statusLine.contains("200")) {
            while (true) {
                val line = readLine(inStream)
                if (line.isEmpty() || line == "\r") break
            }
        }

        return sslSocket
    }

    private fun connectDirectOrProxy(profile: ProfileItem, targetHost: String, targetPort: Int): Socket {
        val rawSocket = Socket()
        CoreServiceManager.protect(rawSocket)
        val server = profile.server.orEmpty()
        val port = profile.serverPort?.toIntOrNull() ?: 443
        rawSocket.connect(InetSocketAddress(server, port), 10000)
        rawSocket.tcpNoDelay = true
        return rawSocket
    }

    private fun handleUdpAssociate(client: Socket, clientOut: OutputStream) {
        try {
            val uSocket = DatagramSocket(0, InetAddress.getByName(AppConfig.LOOPBACK))
            CoreServiceManager.protect(uSocket)
            udpSocket = uSocket

            val port = uSocket.localPort
            val portHi = (port shr 8) and 0xFF
            val portLo = port and 0xFF

            clientOut.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, portHi.toByte(), portLo.toByte()))
            clientOut.flush()

            val clientAddressHolder = java.util.concurrent.atomic.AtomicReference<java.net.SocketAddress>()

            executor?.submit {
                val upstreamUdp = DatagramSocket()
                CoreServiceManager.protect(upstreamUdp)

                executor?.submit {
                    val replyBuffer = ByteArray(65535)
                    try {
                        while (runningState.get() && !upstreamUdp.isClosed && !uSocket.isClosed) {
                            val replyPacket = DatagramPacket(replyBuffer, replyBuffer.size)
                            upstreamUdp.receive(replyPacket)

                            val clientAddr = clientAddressHolder.get() ?: continue
                            val srcPort = replyPacket.port
                            val srcIp = replyPacket.address.address
                            val header = if (srcIp.size == 4) {
                                byteArrayOf(0, 0, 0, 1) + srcIp + byteArrayOf((srcPort shr 8).toByte(), (srcPort and 0xFF).toByte())
                            } else {
                                byteArrayOf(0, 0, 0, 4) + srcIp + byteArrayOf((srcPort shr 8).toByte(), (srcPort and 0xFF).toByte())
                            }
                            val sendData = header + replyPacket.data.copyOfRange(0, replyPacket.length)
                            val backPacket = DatagramPacket(sendData, sendData.size, clientAddr)
                            uSocket.send(backPacket)
                            downlinkBytes.addAndGet(replyPacket.length.toLong())
                        }
                    } catch (_: Exception) {}
                }

                val buffer = ByteArray(65535)
                try {
                    while (runningState.get() && !uSocket.isClosed) {
                        val packet = DatagramPacket(buffer, buffer.size)
                        uSocket.receive(packet)
                        clientAddressHolder.set(packet.socketAddress)

                        val data = packet.data
                        val len = packet.length
                        if (len < 10) continue

                        val atyp = data[3].toInt()
                        var offset = 4
                        val destHost: String

                        when (atyp) {
                            1 -> {
                                val ipBytes = data.copyOfRange(offset, offset + 4)
                                offset += 4
                                destHost = InetAddress.getByAddress(ipBytes).hostAddress ?: "1.1.1.1"
                            }
                            3 -> {
                                val dLen = data[offset].toInt() and 0xFF
                                offset += 1
                                destHost = String(data, offset, dLen, Charsets.UTF_8)
                                offset += dLen
                            }
                            4 -> {
                                val ipBytes = data.copyOfRange(offset, offset + 16)
                                offset += 16
                                destHost = InetAddress.getByAddress(ipBytes).hostAddress ?: "1.1.1.1"
                            }
                            else -> continue
                        }

                        val destPort = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
                        offset += 2

                        val payloadLen = len - offset
                        if (payloadLen <= 0) continue

                        val forwardPacket = DatagramPacket(data, offset, payloadLen, InetAddress.getByName(destHost), destPort)
                        upstreamUdp.send(forwardPacket)
                        uplinkBytes.addAndGet(payloadLen.toLong())
                    }
                } catch (_: Exception) {
                } finally {
                    try { upstreamUdp.close() } catch (_: Exception) {}
                }
            }
        } catch (e: Exception) {
            try {
                clientOut.write(byteArrayOf(0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                clientOut.flush()
            } catch (_: Exception) {}
        }
    }

    private fun createSSLSocket(
        rawSocket: Socket,
        host: String,
        port: Int,
        sni: String,
        insecure: Boolean
    ): SSLSocket {
        val sslContext = SSLContext.getInstance("TLS")
        if (insecure) {
            val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
            })
            sslContext.init(null, trustAll, SecureRandom())
        } else {
            sslContext.init(null, null, null)
        }

        val sslSocket = sslContext.socketFactory.createSocket(rawSocket, host, port, true) as SSLSocket
        val sniHost = if (sni.isNotBlank()) sni else host
        try {
            val params = sslSocket.sslParameters
            params.serverNames = listOf(SNIHostName(sniHost))
            sslSocket.sslParameters = params
        } catch (_: Exception) {}

        sslSocket.startHandshake()
        return sslSocket
    }

    private fun pipeStreams(input: InputStream, output: OutputStream, counter: AtomicLong) {
        val buffer = ByteArray(16384)
        try {
            while (runningState.get()) {
                val read = input.read(buffer)
                if (read == -1) break
                output.write(buffer, 0, read)
                output.flush()
                counter.addAndGet(read.toLong())
            }
        } catch (_: Exception) {}
    }

    private fun readLine(inStream: InputStream): String {
        val sb = StringBuilder()
        while (true) {
            val b = inStream.read()
            if (b == -1 || b == '\n'.code) break
            if (b != '\r'.code) {
                sb.append(b.toChar())
            }
        }
        return sb.toString().trim()
    }

    private fun InputStream.readFully(b: ByteArray) {
        var offset = 0
        while (offset < b.size) {
            val count = read(b, offset, b.size - offset)
            if (count < 0) error("Unexpected EOF reading SOCKS5 frame")
            offset += count
        }
    }

    private fun safeClose(socket: Socket) {
        try {
            socket.close()
        } catch (_: Exception) {}
    }
}
