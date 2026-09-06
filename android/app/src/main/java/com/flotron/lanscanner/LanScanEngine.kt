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
import java.net.Socket
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.Callable
import java.util.concurrent.ExecutorService
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.TimeUnit
import kotlin.math.max

class LanScanEngine(context: Context, private val onState: (ScanState) -> Unit) {
    private val appContext = context.applicationContext
    private val main = Handler(Looper.getMainLooper())
    private val coordinator = Executors.newSingleThreadExecutor()
    private val workers = Executors.newFixedThreadPool(48)
    private val portCoordinator = Executors.newSingleThreadExecutor()
    private val portWorkers = Executors.newFixedThreadPool(24)
    private val vendorWorker = Executors.newSingleThreadExecutor()
    private val nameWorkers = Executors.newFixedThreadPool(8)
    private val scanRunning = AtomicBoolean(false)
    @Volatile private var closed = false
    private val vendors = VendorDatabase(appContext)
    private val history = DeviceHistory(appContext)
    @Volatile private var cancelled = false
    @Volatile private var state = ScanState()

    init {
        if (BuildConfig.MAC_DISCOVERY_ENABLED) vendorWorker.execute { vendors.refresh() }
    }

    fun currentRange(): NetworkRange? = runCatching { detectRange() }.getOrNull()

    private fun detectRange(): NetworkRange? {
        val connectivity = appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val candidates = connectivity.allNetworks.mapNotNull { androidNetwork ->
            val capabilities = connectivity.getNetworkCapabilities(androidNetwork) ?: return@mapNotNull null
            val transportPriority = when {
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> return@mapNotNull null
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
        if (prefix > 30) return null
        return NetworkRange(ip, prefix, Ipv4Subnet.hosts(ip, prefix),
            Ipv4Subnet.address(Ipv4Subnet.network(ip, prefix)), selected.interfaceName, actualPrefix)
    }

    fun scan(cidrOverride: String? = null) {
        if (closed || !scanRunning.compareAndSet(false, true)) return
        cancelled = false
        coordinator.execute {
            try {
                performScan(cidrOverride)
            } catch (error: InterruptedException) {
                Thread.currentThread().interrupt()
            } catch (error: Exception) {
                publish(state.copy(scanning = false, message = "SCAN FAILED — TAP TO RETRY"))
            } finally {
                if (state.scanning) publish(state.copy(scanning = false, message = "SCAN STOPPED"))
                scanRunning.set(false)
            }
        }
    }

    private fun performScan(cidrOverride: String?) {
        val range = if (cidrOverride.isNullOrBlank()) currentRange() else parseRange(cidrOverride)
        if (range == null) return publish(state.copy(scanning = false,
            message = if (currentRange() == null) "CONNECT TO WI-FI OR ETHERNET" else "INVALID RANGE — USE IPv4 /24 TO /30"))
        publish(ScanState(range.cidr, true, 0, message = "ACTIVATING NETWORK NEIGHBORS"))
        val responsive = ConcurrentHashMap<String, Long>()
        val completed = AtomicInteger()
        runBatch(workers, range.hosts.map { ip -> Callable {
            if (!cancelled && !closed) {
                probe(ip)?.let { responsive[ip] = it }
                val count = completed.incrementAndGet()
                if (count % 8 == 0 || count == range.hosts.size) synchronized(completed) {
                    val progress = (completed.get() * 70 / range.hosts.size).coerceIn(1, 70)
                    publish(state.copy(progress = max(state.progress, progress)))
                }
            }
        } }, 35)
        if (cancelled) return
        Thread.sleep(500)
        if (!BuildConfig.MAC_DISCOVERY_ENABLED) {
            publish(state.copy(progress = 78, message = "RESOLVING HOSTS — MAC DISABLED"))
            return publishLayer3Results(
                range,
                responsive,
                "Unavailable",
                "MAC discovery disabled",
                "${responsive.size} HOSTS — MAC UNAVAILABLE IN THIS DISTRIBUTION"
            )
    }
    val active = currentRange()
    if (active == null || active.localIp != range.localIp || active.interfaceName != range.interfaceName) {
        return publish(state.copy(scanning = false, message = "NETWORK CHANGED — SCAN AGAIN"))
    }
    val directSubnet = range.hosts.all { Ipv4Subnet.contains(active.localIp, active.localPrefix, it) }
    if (!directSubnet) {
        publish(state.copy(progress = 78, message = "ROUTED VLAN — RESOLVING HOSTS"))
        return publishLayer3Results(
            range,
            responsive,
            "Unavailable (routed)",
            "Layer 3 route",
            "${responsive.size} ROUTED HOSTS — MAC REQUIRES SAME VLAN"
        )
    }
    publish(state.copy(progress = 78, message = "READING IP / MAC NEIGHBOR TABLE"))
    val arp = readArpTable(range)
    if (arp == null) {
        return publish(state.copy(scanning = false, progress = 100, macAccessAvailable = false,
            message = "MAC ACCESS BLOCKED: ${NativeArp.lastError.ifBlank { "NEIGHBOR TABLE UNAVAILABLE" }}"))
    }

    val previous = history.load()
    val names = resolveNames(arp.keys.filter { responsive.containsKey(it) })
    val found = arp.filterKeys { it in range.hosts }.map { (ip, mac) ->
        val latency = responsive[ip]
        val old = previous[ip]?.takeIf { it.mac.equals(mac, ignoreCase = true) }
        val resolvedName = names[ip] ?: "Unknown host"
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

    private fun publishLayer3Results(
        range: NetworkRange,
        responsive: Map<String, Long>,
        macLabel: String,
        vendorLabel: String,
        resultMessage: String
    ) {
        val previous = history.load()
        val now = System.currentTimeMillis()
        val names = resolveNames(responsive.keys)
        val onlineByIp = responsive.mapValues { (ip, latency) ->
            val old = previous[ip]
            val resolvedName = names[ip] ?: "Unknown host"
            LanDevice(
                ip = ip,
                mac = macLabel,
                vendor = vendorLabel,
                name = resolvedName.takeUnless { it == "Unknown host" } ?: old?.name ?: "Unknown host",
                online = true,
                latencyMs = latency,
                lastSeen = now
            )
        }
        val allAddresses = range.hosts.map { ip ->
            onlineByIp[ip] ?: LanDevice(
                ip = ip,
                mac = macLabel,
                vendor = vendorLabel,
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
            resultMessage,
            true
        ))
    }

    fun close() {
        closed = true
        cancelled = true
        listOf(coordinator, workers, portCoordinator, portWorkers, nameWorkers, vendorWorker).forEach { it.shutdownNow() }
        main.removeCallbacksAndMessages(null)
    }

    fun probe(ip: String): Long? {
        if (closed || Thread.currentThread().isInterrupted) return null
        val started = System.nanoTime()
        stimulateNeighbor(ip)
        val reachable = runCatching { InetAddress.getByName(ip).isReachable(350) }.getOrDefault(false)
        if (!reachable && intArrayOf(80, 443, 22, 445, 9100, 53).none {
                !closed && !Thread.currentThread().isInterrupted && tcpOpen(ip, it, 180)
            }) return null
        return (System.nanoTime() - started) / 1_000_000
    }

    fun scanPorts(ip: String, callback: (List<Int>) -> Unit) {
        if (closed) return
        portCoordinator.execute {
            val ports = intArrayOf(20,21,22,23,25,53,67,68,80,81,110,123,135,137,138,139,143,161,389,443,445,
                515,548,554,587,631,993,995,1433,1883,2049,3306,3389,5000,5353,5432,5900,8000,8080,8443,9100)
            val open = ConcurrentHashMap.newKeySet<Int>()
            try {
                runBatch(portWorkers, ports.map { port -> Callable {
                    if (!closed && tcpOpen(ip, port, 350)) open += port
                } }, 5)
                val result = open.sorted()
                main.post { if (!closed) callback(result) }
              } catch (_: InterruptedException) {
                  Thread.currentThread().interrupt()
              }
        }
    }

    private fun <T> runBatch(pool: ExecutorService, tasks: List<Callable<T>>, seconds: Long) {
        pool.invokeAll(tasks, seconds, TimeUnit.SECONDS).forEach { future ->
            if (!future.isCancelled) future.get()
        }
    }

    private fun resolveNames(ips: Collection<String>): Map<String, String> {
        val names = ConcurrentHashMap<String, String>()
        runBatch(nameWorkers, ips.map { ip -> Callable {
            if (!closed && !cancelled) names[ip] = resolveName(ip)
        } }, 6)
        return names.toMap()
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
                if (fields.size >= 6 && fields[5] == range.interfaceName && fields[2] != "0x0" && fields[3].matches(Regex("(?i)([0-9a-f]{2}:){5}[0-9a-f]{2}")) && fields[3] != "00:00:00:00:00:00")
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
        if (closed || cancelled) return
        state = value
        main.post { if (!closed) onState(value) }
    }

    private fun parseRange(cidr: String): NetworkRange? = runCatching {
        val parts = cidr.trim().split('/')
        require(parts.size == 2)
        val prefix = parts[1].toInt()
        // Keep mobile scans bounded. Larger-than-/24 ranges are intentionally rejected.
        require(prefix in 24..30)
        val active = currentRange() ?: return@runCatching null
        NetworkRange(active.localIp, prefix, Ipv4Subnet.hosts(parts[0], prefix),
            Ipv4Subnet.address(Ipv4Subnet.network(parts[0], prefix)), active.interfaceName, active.localPrefix)
    }.getOrNull()

    private fun isPrivateIpv4(address: Inet4Address): Boolean {
        val bytes = address.address.map { it.toInt() and 0xff }
        return bytes[0] == 10 ||
            (bytes[0] == 172 && bytes[1] in 16..31) ||
            (bytes[0] == 192 && bytes[1] == 168)
    }

    private fun ipValue(ip: String): Long = ip.split('.').fold(0L) { total, octet -> total * 256 + octet.toLong() }

    private data class Candidate(val priority: Int, val interfaceName: String, val ip: String, val prefix: Int)
}
