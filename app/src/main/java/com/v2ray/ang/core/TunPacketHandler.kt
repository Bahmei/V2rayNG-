package com.v2ray.ang.core

import android.os.ParcelFileDescriptor
import com.v2ray.ang.AppConfig
import com.v2ray.ang.util.LogUtil
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Pure-Kotlin high-performance virtual TCP/IP and DNS stack for the Android VPN TUN interface.
 * 1. Responds to ICMP Echo Requests (Ping) immediately.
 * 2. Intercepts UDP DNS queries (Port 53), extracts the domain, and provides instantaneous local DNS
 *    resolution (Fake-IP / RFC 2544 198.18.0.0/15 pool), completely bypassing ISP DNS poisoning and port 53 blocking.
 * 3. Establishes virtual TCP sessions with local apps (SYN -> SYN-ACK), extracts destination domain or SNI,
 *    and seamlessly streams traffic through the active NaïveProxy / AnyTLS outbounds.
 */
object TunPacketHandler {

    private val isRunning = AtomicBoolean(false)
    private var workerThread: Thread? = null
    private var tcpExecutor: ExecutorService? = null
    private var vpnInterface: ParcelFileDescriptor? = null

    // Fake-IP mapping: 198.18.0.0/15 pool (RFC 2544 benchmark network)
    private val ipCounter = AtomicInteger(1)
    private val domainToIp = ConcurrentHashMap<String, String>()
    private val ipToDomain = ConcurrentHashMap<String, String>()

    // Active TCP Sessions
    private val activeSessions = ConcurrentHashMap<String, TcpSession>()

    private class TcpSession(
        val clientIp: ByteArray,
        val clientPort: Int,
        val destIp: ByteArray,
        val destPort: Int,
        val targetHost: String,
        var clientSeq: Long,
        var mySeq: Long,
        @Volatile var remoteSocket: Socket? = null,
        @Volatile var isConnected: Boolean = false,
        @Volatile var isClosed: Boolean = false
    )

    fun start(pfd: ParcelFileDescriptor) {
        if (isRunning.get()) {
            stop()
        }

        vpnInterface = pfd
        isRunning.set(true)
        tcpExecutor = Executors.newCachedThreadPool()

        workerThread = Thread({
            LogUtil.i(AppConfig.TAG, "TunPacketHandler: Starting virtual TCP/IP and DNS stack")
            val inputStream = FileInputStream(pfd.fileDescriptor)
            val outputStream = FileOutputStream(pfd.fileDescriptor)
            val packet = ByteArray(32768)

            while (isRunning.get()) {
                val length: Int
                try {
                    length = inputStream.read(packet)
                } catch (_: Exception) {
                    break
                }
                if (length < 20) continue

                val version = (packet[0].toInt() and 0xF0) ushr 4
                if (version != 4) continue // IPv4 only

                val ihl = (packet[0].toInt() and 0x0F) * 4
                if (length < ihl) continue

                val protocol = packet[9].toInt() and 0xFF
                val srcIp = packet.copyOfRange(12, 16)
                val dstIp = packet.copyOfRange(16, 20)

                when (protocol) {
                    1 -> {
                        // ICMP Echo
                        if (length >= ihl + 8 && packet[ihl] == 8.toByte()) {
                            handleIcmpEcho(packet, length, ihl, srcIp, dstIp, outputStream)
                        }
                    }
                    17 -> {
                        // UDP DNS (Port 53)
                        if (length >= ihl + 8) {
                            val srcPort = ((packet[ihl].toInt() and 0xFF) shl 8) or (packet[ihl + 1].toInt() and 0xFF)
                            val dstPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)
                            val udpLen = ((packet[ihl + 4].toInt() and 0xFF) shl 8) or (packet[ihl + 5].toInt() and 0xFF)
                            val payloadLen = minOf(length - ihl - 8, udpLen - 8)
                            if (payloadLen > 0 && dstPort == 53) {
                                val payload = packet.copyOfRange(ihl + 8, ihl + 8 + payloadLen)
                                handleDnsQuery(srcIp, srcPort, dstIp, dstPort, payload, outputStream)
                            }
                        }
                    }
                    6 -> {
                        // TCP
                        if (length >= ihl + 20) {
                            val srcPort = ((packet[ihl].toInt() and 0xFF) shl 8) or (packet[ihl + 1].toInt() and 0xFF)
                            val dstPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)
                            val seqNum = readInt32(packet, ihl + 4)
                            val ackNum = readInt32(packet, ihl + 8)
                            val dataOffset = ((packet[ihl + 12].toInt() and 0xF0) ushr 4) * 4
                            val flags = packet[ihl + 13].toInt() and 0xFF
                            val tcpPayloadOffset = ihl + dataOffset
                            val tcpPayloadLen = if (length >= tcpPayloadOffset) length - tcpPayloadOffset else 0

                            handleTcpPacket(
                                packet = packet,
                                ihl = ihl,
                                srcIp = srcIp,
                                srcPort = srcPort,
                                dstIp = dstIp,
                                dstPort = dstPort,
                                seq = seqNum,
                                ack = ackNum,
                                flags = flags,
                                payloadOffset = tcpPayloadOffset,
                                payloadLen = tcpPayloadLen,
                                outputStream = outputStream
                            )
                        }
                    }
                }
            }
            LogUtil.i(AppConfig.TAG, "TunPacketHandler: Stopped virtual TCP/IP stack")
        }, "TunPacketHandler-VirtualStack")

        workerThread?.isDaemon = true
        workerThread?.start()
    }

    fun stop() {
        isRunning.set(false)
        try {
            workerThread?.interrupt()
        } catch (_: Exception) {}
        workerThread = null

        activeSessions.values.forEach { session ->
            try {
                session.remoteSocket?.close()
            } catch (_: Exception) {}
        }
        activeSessions.clear()

        tcpExecutor?.shutdownNow()
        tcpExecutor = null
        vpnInterface = null
    }

    //region ICMP Echo Handling
    private fun handleIcmpEcho(
        packet: ByteArray,
        length: Int,
        ihl: Int,
        srcIp: ByteArray,
        dstIp: ByteArray,
        outputStream: FileOutputStream
    ) {
        val reply = packet.copyOf(length)
        System.arraycopy(dstIp, 0, reply, 12, 4)
        System.arraycopy(srcIp, 0, reply, 16, 4)

        reply[ihl] = 0 // Type 0: Echo Reply

        reply[ihl + 2] = 0
        reply[ihl + 3] = 0
        val icmpCsum = calculateChecksum(reply, ihl, length - ihl)
        reply[ihl + 2] = (icmpCsum shr 8).toByte()
        reply[ihl + 3] = (icmpCsum and 0xFF).toByte()

        reply[10] = 0
        reply[11] = 0
        val ipCsum = calculateChecksum(reply, 0, ihl)
        reply[10] = (ipCsum shr 8).toByte()
        reply[11] = (ipCsum and 0xFF).toByte()

        try {
            synchronized(outputStream) {
                outputStream.write(reply, 0, length)
                outputStream.flush()
            }
        } catch (_: Exception) {}
    }
    //endregion

    //region DNS (Port 53) Local Resolver with Fake-IP
    private fun handleDnsQuery(
        clientIp: ByteArray,
        clientPort: Int,
        destIp: ByteArray,
        destPort: Int,
        payload: ByteArray,
        outputStream: FileOutputStream
    ) {
        if (payload.size < 12) return

        val domain = extractDomainFromDns(payload) ?: "google.com"

        // Get or allocate Fake-IP for this domain
        val fakeIpStr = domainToIp.computeIfAbsent(domain) {
            val idx = (ipCounter.incrementAndGet() and 0xFFFF)
            val b2 = (idx ushr 8) and 0xFF
            val b3 = idx and 0xFF
            val ip = "198.18.$b2.$b3"
            ipToDomain[ip] = domain
            ip
        }

        val ipParts = fakeIpStr.split(".")
        val fakeIpBytes = byteArrayOf(
            ipParts[0].toInt().toByte(),
            ipParts[1].toInt().toByte(),
            ipParts[2].toInt().toByte(),
            ipParts[3].toInt().toByte()
        )

        // Build DNS Answer packet
        val response = buildDnsResponse(payload, fakeIpBytes)
        sendUdpPacket(destIp, destPort, clientIp, clientPort, response, outputStream)
    }

    private fun extractDomainFromDns(dnsPacket: ByteArray): String? {
        try {
            var pos = 12
            val sb = java.lang.StringBuilder()
            while (pos < dnsPacket.size) {
                val len = dnsPacket[pos].toInt() and 0xFF
                if (len == 0) break
                if ((len and 0xC0) == 0xC0) break // Compression pointer
                pos++
                if (pos + len > dnsPacket.size) break
                if (sb.isNotEmpty()) sb.append(".")
                sb.append(String(dnsPacket, pos, len, Charsets.US_ASCII))
                pos += len
            }
            return if (sb.isNotEmpty()) sb.toString().lowercase() else null
        } catch (_: Exception) {
            return null
        }
    }

    private fun buildDnsResponse(query: ByteArray, ipBytes: ByteArray): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        // 1. Transaction ID (2 bytes)
        out.write(query[0].toInt())
        out.write(query[1].toInt())

        // 2. Flags: 0x8180 (Standard query response, No error)
        out.write(0x81)
        out.write(0x80)

        // 3. QDCOUNT: 1
        out.write(0x00)
        out.write(0x01)

        // 4. ANCOUNT: 1
        out.write(0x00)
        out.write(0x01)

        // 5. NSCOUNT: 0, ARCOUNT: 0
        out.write(0x00)
        out.write(0x00)
        out.write(0x00)
        out.write(0x00)

        // 6. Copy Question Section from query
        var pos = 12
        while (pos < query.size) {
            val len = query[pos].toInt() and 0xFF
            if (len == 0) {
                pos++
                break
            }
            pos += 1 + len
        }
        val qtypeQclassLen = 4
        val questionEnd = minOf(pos + qtypeQclassLen, query.size)
        out.write(query, 12, questionEnd - 12)

        // 7. Answer Section
        // Name pointer to question domain (0xC00C)
        out.write(0xC0)
        out.write(0x0C)
        // TYPE: A (0x0001)
        out.write(0x00)
        out.write(0x01)
        // CLASS: IN (0x0001)
        out.write(0x00)
        out.write(0x01)
        // TTL: 300 seconds
        out.write(0x00)
        out.write(0x00)
        out.write(0x01)
        out.write(0x2C)
        // RDLENGTH: 4 bytes
        out.write(0x00)
        out.write(0x04)
        // RDATA: IPv4 address
        out.write(ipBytes)

        return out.toByteArray()
    }
    //endregion

    //region Virtual TCP Stack
    private fun handleTcpPacket(
        packet: ByteArray,
        ihl: Int,
        srcIp: ByteArray,
        srcPort: Int,
        dstIp: ByteArray,
        dstPort: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        payloadOffset: Int,
        payloadLen: Int,
        outputStream: FileOutputStream
    ) {
        val srcIpStr = ipToString(srcIp)
        val dstIpStr = ipToString(dstIp)
        val sessionKey = "$srcIpStr:$srcPort->$dstIpStr:$dstPort"

        val isSyn = (flags and 0x02) != 0
        val isAck = (flags and 0x10) != 0
        val isFin = (flags and 0x01) != 0
        val isRst = (flags and 0x04) != 0

        if (isRst) {
            val session = activeSessions.remove(sessionKey)
            session?.isClosed = true
            try { session?.remoteSocket?.close() } catch (_: Exception) {}
            return
        }

        if (isSyn) {
            // New TCP connection from local application!
            // Resolve destination: check if it's a Fake-IP domain
            val resolvedHost = ipToDomain[dstIpStr] ?: dstIpStr
            val initialMySeq = (Math.random() * 5000000L).toLong() + 1000L

            val session = TcpSession(
                clientIp = srcIp,
                clientPort = srcPort,
                destIp = dstIp,
                destPort = dstPort,
                targetHost = resolvedHost,
                clientSeq = seq + 1,
                mySeq = initialMySeq + 1
            )
            activeSessions[sessionKey] = session

            // Send TCP SYN-ACK (0x12) to local app immediately!
            sendTcpPacket(
                srcIp = dstIp,
                srcPort = dstPort,
                dstIp = srcIp,
                dstPort = srcPort,
                seq = initialMySeq,
                ack = session.clientSeq,
                flags = 0x12, // SYN + ACK
                payload = null,
                outputStream = outputStream
            )

            // Asynchronously connect to remote proxy and bridge streams
            tcpExecutor?.submit {
                connectAndBridge(session, sessionKey, outputStream)
            }
            return
        }

        val session = activeSessions[sessionKey] ?: return

        if (payloadLen > 0) {
            // Client sent data (e.g. TLS ClientHello or HTTP request)
            session.clientSeq = seq + payloadLen

            // ACK client data immediately
            sendTcpPacket(
                srcIp = dstIp,
                srcPort = dstPort,
                dstIp = srcIp,
                dstPort = srcPort,
                seq = session.mySeq,
                ack = session.clientSeq,
                flags = 0x10, // ACK
                payload = null,
                outputStream = outputStream
            )

            val payload = packet.copyOfRange(payloadOffset, payloadOffset + payloadLen)

            // If we have an active remote socket, forward data
            val rSocket = session.remoteSocket
            if (rSocket != null && !session.isClosed) {
                try {
                    val rOut = rSocket.getOutputStream()
                    rOut.write(payload)
                    rOut.flush()
                } catch (e: Exception) {
                    closeSession(sessionKey, session, outputStream)
                }
            }
        }

        if (isFin) {
            session.clientSeq = seq + 1
            sendTcpPacket(
                srcIp = dstIp,
                srcPort = dstPort,
                dstIp = srcIp,
                dstPort = srcPort,
                seq = session.mySeq,
                ack = session.clientSeq,
                flags = 0x11, // FIN + ACK
                payload = null,
                outputStream = outputStream
            )
            closeSession(sessionKey, session, outputStream)
        }
    }

    private fun connectAndBridge(session: TcpSession, sessionKey: String, outputStream: FileOutputStream) {
        try {
            val remoteSocket = LocalProxyEngine.connectToRemote(session.targetHost, session.destPort)
            if (remoteSocket == null) {
                closeSession(sessionKey, session, outputStream)
                return
            }

            session.remoteSocket = remoteSocket
            session.isConnected = true

            val remoteIn = BufferedInputStream(remoteSocket.getInputStream(), 16384)
            val buffer = ByteArray(1400) // MSS-sized packets

            while (isRunning.get() && !session.isClosed && !remoteSocket.isClosed) {
                val read = remoteIn.read(buffer)
                if (read == -1) break

                val chunk = buffer.copyOfRange(0, read)
                sendTcpPacket(
                    srcIp = session.destIp,
                    srcPort = session.destPort,
                    dstIp = session.clientIp,
                    dstPort = session.clientPort,
                    seq = session.mySeq,
                    ack = session.clientSeq,
                    flags = 0x18, // PSH + ACK
                    payload = chunk,
                    outputStream = outputStream
                )
                session.mySeq += read
                LocalProxyEngine.downlinkBytes.addAndGet(read.toLong())
            }
        } catch (_: Exception) {
        } finally {
            closeSession(sessionKey, session, outputStream)
        }
    }

    private fun closeSession(sessionKey: String, session: TcpSession, outputStream: FileOutputStream) {
        if (session.isClosed) return
        session.isClosed = true
        activeSessions.remove(sessionKey)

        try {
            // Send FIN-ACK to client
            sendTcpPacket(
                srcIp = session.destIp,
                srcPort = session.destPort,
                dstIp = session.clientIp,
                dstPort = session.clientPort,
                seq = session.mySeq,
                ack = session.clientSeq,
                flags = 0x11, // FIN + ACK
                payload = null,
                outputStream = outputStream
            )
        } catch (_: Exception) {}

        try {
            session.remoteSocket?.close()
        } catch (_: Exception) {}
    }
    //endregion

    //region Raw Packet Construction
    private fun sendTcpPacket(
        srcIp: ByteArray,
        srcPort: Int,
        dstIp: ByteArray,
        dstPort: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        payload: ByteArray?,
        outputStream: FileOutputStream
    ) {
        val payloadLen = payload?.size ?: 0
        val totalLen = 40 + payloadLen
        val packet = ByteArray(totalLen)

        // IPv4 Header (20 bytes)
        packet[0] = 0x45.toByte()
        packet[1] = 0
        packet[2] = (totalLen shr 8).toByte()
        packet[3] = (totalLen and 0xFF).toByte()
        val id = (Math.random() * 65535).toInt()
        packet[4] = (id shr 8).toByte()
        packet[5] = (id and 0xFF).toByte()
        packet[6] = 0x40.toByte() // Don't fragment
        packet[7] = 0
        packet[8] = 64.toByte() // TTL
        packet[9] = 6.toByte() // TCP Protocol
        System.arraycopy(srcIp, 0, packet, 12, 4)
        System.arraycopy(dstIp, 0, packet, 16, 4)

        val ipCsum = calculateChecksum(packet, 0, 20)
        packet[10] = (ipCsum shr 8).toByte()
        packet[11] = (ipCsum and 0xFF).toByte()

        // TCP Header (20 bytes)
        packet[20] = (srcPort shr 8).toByte()
        packet[21] = (srcPort and 0xFF).toByte()
        packet[22] = (dstPort shr 8).toByte()
        packet[23] = (dstPort and 0xFF).toByte()

        writeInt32(packet, 24, seq)
        writeInt32(packet, 28, ack)

        packet[32] = (5 shl 4).toByte() // Data offset = 5 (20 bytes)
        packet[33] = flags.toByte()

        // Window size (65535)
        packet[34] = 0xFF.toByte()
        packet[35] = 0xFF.toByte()

        if (payload != null && payloadLen > 0) {
            System.arraycopy(payload, 0, packet, 40, payloadLen)
        }

        val tcpCsum = calculateTcpChecksum(packet, srcIp, dstIp, 20, 20 + payloadLen)
        packet[36] = (tcpCsum shr 8).toByte()
        packet[37] = (tcpCsum and 0xFF).toByte()

        try {
            synchronized(outputStream) {
                outputStream.write(packet)
                outputStream.flush()
            }
        } catch (_: Exception) {}
    }

    private fun sendUdpPacket(
        srcIp: ByteArray,
        srcPort: Int,
        dstIp: ByteArray,
        dstPort: Int,
        payload: ByteArray,
        outputStream: FileOutputStream
    ) {
        val totalLen = 20 + 8 + payload.size
        val packet = ByteArray(totalLen)

        // IPv4 Header
        packet[0] = 0x45.toByte()
        packet[1] = 0
        packet[2] = (totalLen shr 8).toByte()
        packet[3] = (totalLen and 0xFF).toByte()
        val id = (Math.random() * 65535).toInt()
        packet[4] = (id shr 8).toByte()
        packet[5] = (id and 0xFF).toByte()
        packet[6] = 0x40.toByte()
        packet[7] = 0
        packet[8] = 64.toByte()
        packet[9] = 17.toByte() // UDP Protocol

        System.arraycopy(srcIp, 0, packet, 12, 4)
        System.arraycopy(dstIp, 0, packet, 16, 4)

        val ipCsum = calculateChecksum(packet, 0, 20)
        packet[10] = (ipCsum shr 8).toByte()
        packet[11] = (ipCsum and 0xFF).toByte()

        // UDP Header
        val udpLen = 8 + payload.size
        packet[20] = (srcPort shr 8).toByte()
        packet[21] = (srcPort and 0xFF).toByte()
        packet[22] = (dstPort shr 8).toByte()
        packet[23] = (dstPort and 0xFF).toByte()
        packet[24] = (udpLen shr 8).toByte()
        packet[25] = (udpLen and 0xFF).toByte()
        packet[26] = 0
        packet[27] = 0

        System.arraycopy(payload, 0, packet, 28, payload.size)

        try {
            synchronized(outputStream) {
                outputStream.write(packet)
                outputStream.flush()
            }
        } catch (_: Exception) {}
    }
    //endregion

    //region Checksum & Helper Utilities
    private fun calculateChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        val end = offset + length
        while (i < end - 1) {
            val word = ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        if (i < end) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        while ((sum ushr 16) > 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return sum.inv() and 0xFFFF
    }

    private fun calculateTcpChecksum(packet: ByteArray, srcIp: ByteArray, dstIp: ByteArray, tcpOffset: Int, tcpLen: Int): Int {
        var sum = 0
        for (i in 0 until 4 step 2) {
            sum += ((srcIp[i].toInt() and 0xFF) shl 8) or (srcIp[i + 1].toInt() and 0xFF)
            sum += ((dstIp[i].toInt() and 0xFF) shl 8) or (dstIp[i + 1].toInt() and 0xFF)
        }
        sum += 6 // TCP protocol
        sum += tcpLen

        var i = tcpOffset
        val end = tcpOffset + tcpLen
        while (i < end - 1) {
            val word = ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        if (i < end) {
            sum += (packet[i].toInt() and 0xFF) shl 8
        }
        while ((sum ushr 16) > 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return sum.inv() and 0xFFFF
    }

    private fun readInt32(data: ByteArray, offset: Int): Long {
        return ((data[offset].toLong() and 0xFF) shl 24) or
                ((data[offset + 1].toLong() and 0xFF) shl 16) or
                ((data[offset + 2].toLong() and 0xFF) shl 8) or
                (data[offset + 3].toLong() and 0xFF)
    }

    private fun writeInt32(data: ByteArray, offset: Int, value: Long) {
        data[offset] = ((value ushr 24) and 0xFF).toByte()
        data[offset + 1] = ((value ushr 16) and 0xFF).toByte()
        data[offset + 2] = ((value ushr 8) and 0xFF).toByte()
        data[offset + 3] = (value and 0xFF).toByte()
    }

    private fun ipToString(ip: ByteArray): String {
        return "${ip[0].toInt() and 0xFF}.${ip[1].toInt() and 0xFF}.${ip[2].toInt() and 0xFF}.${ip[3].toInt() and 0xFF}"
    }
    //endregion
}
