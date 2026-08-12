package com.flotron.lanscanner

import android.content.Context
import android.os.Handler
import android.os.Looper
import java.io.File
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Socket
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.math.max

class LanScanEngine(context: Context, private val onState: (ScanState) -> Unit) {
    private val main = Handler(Looper.getMainLooper())
    private val coordinator = Executors.newSingleThreadExecutor()
    private val vendors = VendorDatabase(context)
    private val history = DeviceHistory(context)
    @Volatile private var cancelled = false
    @Volatile private var state = ScanState()

    fun currentRange(): NetworkRange? {
        val interfaces = Collections.list(NetworkInterface.getNetworkInterfaces())
        val candidates = interfaces.filter { it.isUp && !it.isLoopback }.flatMap { network ->
            network.interfaceAddresses.mapNotNull { entry ->
                val address = entry.address
                if (address is Inet4Address && !address.isLoopbackAddress && !address.isLinkLocalAddress) {
                    Triple(network.name, address.hostAddress ?: return@mapNotNull null, entry.networkPrefixLength.toInt())
                } else null
            }
        }
        val (_, ip, actualPrefix) = candidates.firstOrNull() ?: return null
        // A phone should not accidentally flood a corporate supernet. Scan its containing /24 at most.
        val prefix = max(actualPrefix, 24)
        val bytes = ip.split('.').map(String::toInt)
        val raw = (bytes[0] shl 24) or (bytes[1] shl 16) or (bytes[2] shl 8) or bytes[3]
        val mask = if (prefix == 0) 0 else -1 shl (32 - prefix)
        val network = raw and mask
        val broadcast = network or mask.inv()
        val hosts = ((network + 1) until broadcast).map { value ->
            "${value ushr 24 and 255}.${value ushr 16 and 255}.${value ushr 8 and 255}.${value and 255}"
        }
        return NetworkRange(ip, prefix, hosts, intToIp(network))
    }

    fun scan(cidrOverride: String? = null) {
        if (state.scanning) return
        cancelled = false
        coordinator.execute {
            val range = if (cidrOverride.isNullOrBlank()) currentRange() else parseRange(cidrOverride)
            if (range == null) return@execute publish(ScanState(message = "CONNECT TO WI-FI OR ETHERNET"))
            publish(ScanState(range.cidr, true, 0, message = "ACTIVATING NETWORK NEIGHBORS"))
            vendors.refresh()
            val responsive = ConcurrentHashMap<String, Long>()
            val pool = Executors.newFixedThreadPool(48)
            range.hosts.forEachIndexed { index, ip -> pool.execute {
                if (!cancelled) {
                    val latency = probe(ip)
                    if (latency != null) responsive[ip] = latency
                    if (index % 8 == 0) publish(state.copy(progress = ((index + 1) * 70 / range.hosts.size).coerceIn(1, 70)))
                }
            } }
            pool.shutdown(); pool.awaitTermination(35, TimeUnit.SECONDS)
            if (cancelled) return@execute
            Thread.sleep(500)
            publish(state.copy(progress = 78, message = "READING IP / MAC NEIGHBOR TABLE"))
            val arp = readArpTable()
            if (arp == null) {
                return@execute publish(state.copy(scanning = false, progress = 0, macAccessAvailable = false,
                    message = "MAC ACCESS BLOCKED ON THIS ANDROID VERSION"))
            }

            val previous = history.load()
            val found = arp.filterKeys { it in range.hosts }.map { (ip, mac) ->
                val latency = responsive[ip] ?: probe(ip)
                val old = previous[ip]
                val resolvedName = resolveName(ip)
                LanDevice(
                    ip = ip,
                    mac = mac,
                    vendor = vendors.find(mac).takeUnless { it == "Unknown" } ?: old?.vendor ?: "Unknown",
                    name = resolvedName.takeUnless { it == "Unknown host" } ?: old?.name ?: "Unknown host",
                    online = latency != null,
                    latencyMs = latency,
                    lastSeen = if (latency != null) System.currentTimeMillis() else old?.lastSeen ?: 0L
                )
            }.sortedWith(compareBy { ipValue(it.ip) })

            val merged = previous.toMutableMap()
            found.forEach { merged[it.ip] = it }
            history.save(merged.values)
            val currentIps = found.mapTo(mutableSetOf()) { it.ip }
            val offline = merged.values.filter { it.ip in range.hosts && it.ip !in currentIps }.map { it.copy(online = false) }
            publish(ScanState(range.cidr, false, 100, (found + offline).sortedBy { ipValue(it.ip) },
                "${found.size} CLIENTS WITH VERIFIED MAC", true))
        }
    }

    fun cancel() { cancelled = true }

    fun probe(ip: String): Long? {
        val started = System.nanoTime()
        stimulateNeighbor(ip)
        val reachable = runCatching { InetAddress.getByName(ip).isReachable(350) }.getOrDefault(false)
        if (!reachable) {
            val ports = intArrayOf(80, 443, 22, 445, 9100, 53)
            if (ports.none { tcpOpen(ip, it, 180) }) return null
        }
        return (System.nanoTime() - started) / 1_000_000
    }

    fun scanPorts(ip: String, callback: (List<Int>) -> Unit) {
        coordinator.execute {
            val ports = intArrayOf(20,21,22,23,25,53,67,68,80,81,110,123,135,137,138,139,143,161,389,443,445,
                515,548,554,587,631,993,995,1433,1883,2049,3306,3389,5000,5353,5432,5900,8000,8080,8443,9100)
            val open = ConcurrentHashMap.newKeySet<Int>()
            val pool = Executors.newFixedThreadPool(24)
            ports.forEach { port -> pool.execute { if (tcpOpen(ip, port, 350)) open += port } }
            pool.shutdown(); pool.awaitTermination(20, TimeUnit.SECONDS)
            main.post { callback(open.sorted()) }
        }
    }

    private fun tcpOpen(ip: String, port: Int, timeout: Int): Boolean = runCatching {
        Socket().use { socket -> socket.connect(InetSocketAddress(ip, port), timeout); true }
    }.getOrDefault(false)

    private fun stimulateNeighbor(ip: String) {
        runCatching {
            DatagramSocket().use { socket ->
                socket.soTimeout = 100
                val payload = byteArrayOf(0)
                socket.send(DatagramPacket(payload, payload.size, InetAddress.getByName(ip), 9))
            }
        }
    }

    private fun readArpTable(): Map<String, String>? {
        val file = File("/proc/net/arp")
        if (!file.canRead()) return null
        return runCatching {
            file.readLines().drop(1).mapNotNull { line ->
                val fields = line.trim().split(Regex("\\s+"))
                if (fields.size >= 4 && fields[2] != "0x0" && fields[3].matches(Regex("(?i)([0-9a-f]{2}:){5}[0-9a-f]{2}")) && fields[3] != "00:00:00:00:00:00")
                    fields[0] to fields[3].uppercase() else null
            }.toMap()
        }.getOrNull()
    }

    private fun resolveName(ip: String): String {
        val dns = runCatching {
        val address = InetAddress.getByName(ip)
        address.canonicalHostName.takeUnless { it == ip } ?: "Unknown host"
        }.getOrDefault("Unknown host")
        return dns.takeUnless { it == "Unknown host" } ?: netbiosName(ip) ?: "Unknown host"
    }

    private fun netbiosName(ip: String): String? = runCatching {
        val packet = ByteBuffer.allocate(50).order(ByteOrder.BIG_ENDIAN).apply {
            putShort((System.nanoTime() and 0xffff).toShort())
            putShort(0); putShort(1); putShort(0); putShort(0); putShort(0)
            put(32)
            val rawName = ByteArray(16).also { bytes -> bytes[0] = '*'.code.toByte() }
            rawName.forEach { byte ->
                val value = byte.toInt() and 0xff
                put(('A'.code + (value ushr 4)).toByte())
                put(('A'.code + (value and 0x0f)).toByte())
            }
            put(0); putShort(0x21); putShort(1)
        }.array()
        DatagramSocket().use { socket ->
            socket.soTimeout = 300
            socket.send(DatagramPacket(packet, packet.size, InetAddress.getByName(ip), 137))
            val response = ByteArray(576)
            val reply = DatagramPacket(response, response.size)
            socket.receive(reply)
            // Node-status names are fixed 15-byte ASCII records. Prefer the workstation name.
            for (offset in 0..(reply.length - 18)) {
                val suffix = response[offset + 15].toInt() and 0xff
                val flags = ((response[offset + 16].toInt() and 0xff) shl 8) or (response[offset + 17].toInt() and 0xff)
                if (suffix == 0x00 && flags and 0x8000 == 0) {
                    val name = response.copyOfRange(offset, offset + 15).toString(Charsets.US_ASCII).trim()
                    if (name.matches(Regex("[A-Za-z0-9_.-]{1,15}"))) return@use name
                }
            }
            null
        }
    }.getOrNull()

    private fun publish(value: ScanState) {
        state = value
        main.post { onState(value) }
    }

    private fun parseRange(cidr: String): NetworkRange? = runCatching {
        val parts = cidr.trim().split('/')
        require(parts.size == 2)
        val prefix = parts[1].toInt()
        // Keep mobile scans bounded. Larger-than-/24 ranges are intentionally rejected.
        require(prefix in 24..30)
        val octets = parts[0].split('.').map(String::toInt)
        require(octets.size == 4 && octets.all { it in 0..255 })
        val raw = (octets[0] shl 24) or (octets[1] shl 16) or (octets[2] shl 8) or octets[3]
        val mask = -1 shl (32 - prefix)
        val network = raw and mask
        val broadcast = network or mask.inv()
        val hosts = ((network + 1) until broadcast).map(::intToIp)
        NetworkRange(currentRange()?.localIp ?: parts[0], prefix, hosts, intToIp(network))
    }.getOrNull()

    private fun intToIp(value: Int): String =
        "${value ushr 24 and 255}.${value ushr 16 and 255}.${value ushr 8 and 255}.${value and 255}"

    private fun ipValue(ip: String): Long = ip.split('.').fold(0L) { total, octet -> total * 256 + octet.toLong() }
}
