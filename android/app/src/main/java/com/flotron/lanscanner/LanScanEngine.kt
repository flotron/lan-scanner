package com.flotron.lanscanner

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
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
    private val appContext = context.applicationContext
    private val main = Handler(Looper.getMainLooper())
    private val coordinator = Executors.newSingleThreadExecutor()
    private val vendors = VendorDatabase(context)
    private val history = DeviceHistory(context)
    @Volatile private var cancelled = false
    @Volatile private var state = ScanState()

    fun currentRange(): NetworkRange? {
        val connectivity = appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val candidates = connectivity.allNetworks.mapNotNull { androidNetwork ->
            val capabilities = connectivity.getNetworkCapabilities(androidNetwork) ?: return@mapNotNull null
            val transportPriority = when {
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 0
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 1
                else -> return@mapNotNull null
            }
            val properties = connectivity.getLinkProperties(androidNetwork) ?: return@mapNotNull null
            val address = properties.linkAddresses.firstOrNull {
                it.address is Inet4Address && !it.address.isLoopbackAddress && !it.address.isLinkLocalAddress &&
                    isPrivateIpv4(it.address as Inet4Address)
            } ?: return@mapNotNull null
            val ip = address.address.hostAddress ?: return@mapNotNull null
            Candidate(transportPriority, properties.interfaceName ?: return@mapNotNull null, ip, address.prefixLength)
        }.sortedBy { it.priority }
        val selected = candidates.firstOrNull() ?: return null
        val ip = selected.ip
        val actualPrefix = selected.prefix
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
        return NetworkRange(ip, prefix, hosts, intToIp(network), selected.interfaceName)
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
            val localLayer2Hosts = currentRange()?.hosts?.toHashSet().orEmpty()
            val directSubnet = range.hosts.any { it in localLayer2Hosts }
            if (!directSubnet) {
                publish(state.copy(progress = 78, message = "ROUTED VLAN — RESOLVING HOSTS"))
                return@execute publishRoutedResults(range, responsive)
            }
            publish(state.copy(progress = 78, message = "READING IP / MAC NEIGHBOR TABLE"))
            val arp = readArpTable(range)
            if (arp == null) {
                return@execute publish(state.copy(scanning = false, progress = 100, macAccessAvailable = false,
                    message = "MAC ACCESS BLOCKED: ${NativeArp.lastError.ifBlank { "NEIGHBOR TABLE UNAVAILABLE" }}"))
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
            val foundByIp = found.associateBy { it.ip }
            val allAddresses = range.hosts.map { ip ->
                foundByIp[ip]
                    ?: merged[ip]?.copy(online = false, latencyMs = null)
                    ?: LanDevice(ip, "Not recorded", "Unknown", "No client recorded", online = false, lastSeen = 0)
            }
            publish(ScanState(range.cidr, false, 100, allAddresses,
                "${found.size} CLIENTS WITH VERIFIED MAC", true))
        }
    }

    private fun publishRoutedResults(range: NetworkRange, responsive: Map<String, Long>) {
        val previous = history.load()
        val now = System.currentTimeMillis()
        val onlineByIp = responsive.mapValues { (ip, latency) ->
            val old = previous[ip]
            val resolvedName = resolveName(ip)
            LanDevice(
                ip = ip,
                mac = "Unavailable (routed)",
                vendor = "Layer 3 route",
                name = resolvedName.takeUnless { it == "Unknown host" } ?: old?.name ?: "Unknown host",
                online = true,
                latencyMs = latency,
                lastSeen = now
            )
        }
        val allAddresses = range.hosts.map { ip ->
            onlineByIp[ip] ?: LanDevice(
                ip = ip,
                mac = "Unavailable (routed)",
                vendor = "Layer 3 route",
                name = previous[ip]?.name ?: "No client recorded",
                online = false,
                latencyMs = null,
                lastSeen = previous[ip]?.lastSeen ?: 0L
            )
        }
        publish(ScanState(
            range.cidr,
            false,
            100,
            allAddresses,
            "${responsive.size} ROUTED HOSTS — MAC REQUIRES SAME VLAN",
            true
        ))
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

    private fun readArpTable(range: NetworkRange): Map<String, String>? {
        val file = File("/proc/net/arp")
        val fromProc = if (file.canRead()) runCatching {
            file.readLines().drop(1).mapNotNull { line ->
                val fields = line.trim().split(Regex("\\s+"))
                if (fields.size >= 4 && fields[2] != "0x0" && fields[3].matches(Regex("(?i)([0-9a-f]{2}:){5}[0-9a-f]{2}")) && fields[3] != "00:00:00:00:00:00")
                    fields[0] to fields[3].uppercase() else null
            }.toMap()
        }.getOrNull() else null
        if (!fromProc.isNullOrEmpty()) return fromProc
        if (!NativeArp.available) return if (fromProc != null) emptyMap() else null
        val allowed = range.hosts.toHashSet()
        val nativeEntries = NativeArp.dump(range.interfaceName)
            ?.filterKeys { it in allowed }
            .orEmpty()
            .ifEmpty {
                // Older kernels without a neighbor dump still support individual ARP queries.
                range.hosts.mapNotNull { ip ->
                    NativeArp.lookup(ip, range.interfaceName)?.let { ip to it }
                }.toMap()
            }
        return nativeEntries.takeIf { it.isNotEmpty() || fromProc != null }
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
        val active = currentRange() ?: return@runCatching null
        NetworkRange(active.localIp, prefix, hosts, intToIp(network), active.interfaceName)
    }.getOrNull()

    private fun intToIp(value: Int): String =
        "${value ushr 24 and 255}.${value ushr 16 and 255}.${value ushr 8 and 255}.${value and 255}"

    private fun isPrivateIpv4(address: Inet4Address): Boolean {
        val bytes = address.address.map { it.toInt() and 0xff }
        return bytes[0] == 10 ||
            (bytes[0] == 172 && bytes[1] in 16..31) ||
            (bytes[0] == 192 && bytes[1] == 168)
    }

    private fun ipValue(ip: String): Long = ip.split('.').fold(0L) { total, octet -> total * 256 + octet.toLong() }

    private data class Candidate(val priority: Int, val interfaceName: String, val ip: String, val prefix: Int)
}
