package com.v2ray.ang.core

import android.os.ParcelFileDescriptor
import com.v2ray.ang.AppConfig
import com.v2ray.ang.util.LogUtil
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Pure-Kotlin high-performance TUN packet processor.
 * Intercepts packets on the VPN TUN interface:
 * 1. Responds to ICMP Echo Requests (Ping) so Android network verification detects healthy internet.
 * 2. Intercepts and resolves UDP DNS queries (Port 53) using protected upstream sockets.
 * 3. Gracefully responds to direct TCP SYN packets with RST+ACK to prevent client sockets from hanging.
 */
object TunPacketHandler {

    private val isRunning = AtomicBoolean(false)
    private var workerThread: Thread? = null
    private var dnsExecutor: ExecutorService? = null
    private var vpnInterface: ParcelFileDescriptor? = null

    fun start(pfd: ParcelFileDescriptor) {
        if (isRunning.get()) {
            stop()
        }

        vpnInterface = pfd
        isRunning.set(true)
        dnsExecutor = Executors.newFixedThreadPool(8)

        workerThread = Thread({
            LogUtil.i(AppConfig.TAG, "TunPacketHandler: Started packet pump on TUN interface")
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
                        // ICMP
                        if (length >= ihl + 8 && packet[ihl] == 8.toByte()) {
                            // Echo Request -> Reply
                            handleIcmpEcho(packet, length, ihl, srcIp, dstIp, outputStream)
                        }
                    }
                    17 -> {
                        // UDP
                        if (length >= ihl + 8) {
                            val srcPort = ((packet[ihl].toInt() and 0xFF) shl 8) or (packet[ihl + 1].toInt() and 0xFF)
                            val dstPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)
                            val udpLen = ((packet[ihl + 4].toInt() and 0xFF) shl 8) or (packet[ihl + 5].toInt() and 0xFF)
                            val payloadLen = minOf(length - ihl - 8, udpLen - 8)
                            if (payloadLen > 0) {
                                val payload = packet.copyOfRange(ihl + 8, ihl + 8 + payloadLen)
                                handleUdpPacket(srcIp, srcPort, dstIp, dstPort, payload, outputStream)
                            }
                        }
                    }
                    6 -> {
                        // TCP
                        if (length >= ihl + 20) {
                            val srcPort = ((packet[ihl].toInt() and 0xFF) shl 8) or (packet[ihl + 1].toInt() and 0xFF)
                            val dstPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)
                            val seqNum = readInt32(packet, ihl + 4)
                            val flags = packet[ihl + 13].toInt() and 0xFF
                            val isSyn = (flags and 0x02) != 0
                            val isRst = (flags and 0x04) != 0
                            if (isSyn && !isRst) {
                                handleTcpSyn(srcIp, srcPort, dstIp, dstPort, seqNum, outputStream)
                            }
                        }
                    }
                }
            }
            LogUtil.i(AppConfig.TAG, "TunPacketHandler: Stopped packet pump")
        }, "TunPacketHandler-Thread")

        workerThread?.isDaemon = true
        workerThread?.start()
    }

    fun stop() {
        isRunning.set(false)
        try {
            workerThread?.interrupt()
        } catch (_: Exception) {}
        workerThread = null

        dnsExecutor?.shutdownNow()
        dnsExecutor = null
        vpnInterface = null
    }

    private fun handleIcmpEcho(
        packet: ByteArray,
        length: Int,
        ihl: Int,
        srcIp: ByteArray,
        dstIp: ByteArray,
        outputStream: FileOutputStream
    ) {
        val reply = packet.copyOf(length)
        // Swap IP addresses
        System.arraycopy(dstIp, 0, reply, 12, 4)
        System.arraycopy(srcIp, 0, reply, 16, 4)

        // Change type to 0 (Echo Reply)
        reply[ihl] = 0

        // Recalculate ICMP checksum
        reply[ihl + 2] = 0
        reply[ihl + 3] = 0
        val icmpCsum = calculateChecksum(reply, ihl, length - ihl)
        reply[ihl + 2] = (icmpCsum shr 8).toByte()
        reply[ihl + 3] = (icmpCsum and 0xFF).toByte()

        // Recalculate IP header checksum
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

    private fun handleUdpPacket(
        clientIp: ByteArray,
        clientPort: Int,
        destIp: ByteArray,
        destPort: Int,
        payload: ByteArray,
        outputStream: FileOutputStream
    ) {
        dnsExecutor?.submit {
            try {
                val udpSocket = DatagramSocket()
                CoreServiceManager.protect(udpSocket)
                udpSocket.soTimeout = 4000

                val destAddress = InetAddress.getByAddress(destIp)
                val targetAddress = if (destPort == 53) {
                    if (destAddress.isLoopbackAddress || destAddress.isAnyLocalAddress || destAddress.isSiteLocalAddress) {
                        InetAddress.getByName("1.1.1.1")
                    } else {
                        destAddress
                    }
                } else {
                    destAddress
                }

                val queryPacket = DatagramPacket(payload, payload.size, targetAddress, destPort)
                udpSocket.send(queryPacket)

                val replyBuf = ByteArray(4096)
                val replyPacket = DatagramPacket(replyBuf, replyBuf.size)
                udpSocket.receive(replyPacket)
                val replyPayload = replyPacket.data.copyOfRange(0, replyPacket.length)

                sendUdpResponse(destIp, destPort, clientIp, clientPort, replyPayload, outputStream)
                udpSocket.close()
            } catch (_: Exception) {}
        }
    }

    private fun sendUdpResponse(
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
        packet[0] = 0x45.toByte() // Version 4, IHL 5
        packet[1] = 0 // TOS
        packet[2] = (totalLen shr 8).toByte()
        packet[3] = (totalLen and 0xFF).toByte()
        val id = (Math.random() * 65535).toInt()
        packet[4] = (id shr 8).toByte()
        packet[5] = (id and 0xFF).toByte()
        packet[6] = 0x40.toByte() // Don't fragment
        packet[7] = 0
        packet[8] = 64.toByte() // TTL
        packet[9] = 17.toByte() // Protocol UDP

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

        // Payload
        System.arraycopy(payload, 0, packet, 28, payload.size)

        try {
            synchronized(outputStream) {
                outputStream.write(packet)
                outputStream.flush()
            }
        } catch (_: Exception) {}
    }

    private fun handleTcpSyn(
        srcIp: ByteArray,
        srcPort: Int,
        dstIp: ByteArray,
        dstPort: Int,
        clientSeq: Long,
        outputStream: FileOutputStream
    ) {
        // Send TCP RST+ACK so connecting sockets fail fast instead of hanging forever
        val totalLen = 40 // 20 byte IP + 20 byte TCP
        val packet = ByteArray(totalLen)

        // IP Header
        packet[0] = 0x45.toByte()
        packet[1] = 0
        packet[2] = 0
        packet[3] = 40
        packet[6] = 0x40.toByte()
        packet[8] = 64.toByte()
        packet[9] = 6.toByte() // TCP
        System.arraycopy(dstIp, 0, packet, 12, 4)
        System.arraycopy(srcIp, 0, packet, 16, 4)

        val ipCsum = calculateChecksum(packet, 0, 20)
        packet[10] = (ipCsum shr 8).toByte()
        packet[11] = (ipCsum and 0xFF).toByte()

        // TCP Header
        packet[20] = (dstPort shr 8).toByte()
        packet[21] = (dstPort and 0xFF).toByte()
        packet[22] = (srcPort shr 8).toByte()
        packet[23] = (srcPort and 0xFF).toByte()

        // Sequence number = 0
        writeInt32(packet, 24, 0L)
        // Ack number = clientSeq + 1
        writeInt32(packet, 28, clientSeq + 1)

        // Header length (5 words = 20 bytes)
        packet[32] = (5 shl 4).toByte()
        // Flags: RST (0x04) + ACK (0x10) = 0x14
        packet[33] = 0x14.toByte()
        packet[34] = 0
        packet[35] = 0 // Window size

        // Calculate TCP checksum with pseudo-header
        val tcpCsum = calculateTcpChecksum(packet, dstIp, srcIp, 20, 20)
        packet[36] = (tcpCsum shr 8).toByte()
        packet[37] = (tcpCsum and 0xFF).toByte()

        try {
            synchronized(outputStream) {
                outputStream.write(packet)
                outputStream.flush()
            }
        } catch (_: Exception) {}
    }

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
        // Pseudo header: srcIp + dstIp + zero + proto(6) + tcpLen
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
}
