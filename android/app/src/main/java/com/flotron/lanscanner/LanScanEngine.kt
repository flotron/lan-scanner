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
import java.util.concurrent.CancellationException
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
    private val scanLock = Any()
    @Volatile private var activeScan: ScanSession? = null
    @Volatile private var generation = 0L
    @Volatile private var closed = false
    private val vendors = VendorDatabase(appContext)
    private val history = DeviceHistory(appContext)
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
        val session = synchronized(scanLock) {
            if (closed || activeScan != null) return
            ScanSession(++generation).also { activeScan = it }
        }
        coordinator.execute {
            var failure: String? = null
            try {
                performScan(cidrOverride, session)
            } catch (_: CancellationException) {
                // The final state below re-enables controls after work has been cancelled.
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
            } catch (_: Exception) {
                failure = "SCAN FAILED — CHECK NETWORK AND RETRY"
            } finally {
                synchronized(scanLock) {
                    if (activeScan === session) {
                        activeScan = null
                        val stopped = session.cancelled.get()
                        val message = if (stopped) "SCAN STOPPED — SELECT RANGE OR SCAN AGAIN" else failure ?: state.message
                        publishState(state.copy(scanning = false, message = message,
                            progress = if (stopped || failure != null) state.progress.coerceAtMost(99) else state.progress), session.generation)
                    }
                }
            }
        }
    }

    fun cancel() {
        synchronized(scanLock) {
            val session = activeScan ?: return
            session.cancelled.set(true)
            publishState(state.copy(scanning = true, message = "STOPPING SCAN…"), session.generation)
        }
    }

    private fun performScan(cidrOverride: String?, session: ScanSession) {
        session.check()
        val range = if (cidrOverride.isNullOrBlank()) currentRange() else parseRange(cidrOverride)
        if (range == null) {
            publishScan(session, state.copy(scanning = false, progress = 0,
                message = if (currentRange() == null) "CONNECT TO WI-FI OR ETHERNET" else "INVALID RANGE — USE IPv4 /20 TO /30"))
            return
        }
        publishScan(session, ScanState(range.cidr, true, 0, message = "DISCOVERING ${range.hosts.size} ADDRESSES"))
        val responsive = ConcurrentHashMap<String, Long>()
        // Batches bound memory and provide progress on /23 and larger ranges.
        // Each batch has its own deadline instead of timing out the whole range.
        var completed = 0
        for (batch in range.hosts.chunked(48)) {
            session.run(workers, batch.map { ip -> Callable {
                val latency = probe(ip)
                session.check()
                if (latency != null) responsive[ip] = latency
            } }, 8_000)
            completed += batch.size
            val partial = responsive.entries.sortedBy { Ipv4Subnet.value(it.key) }.map { (ip, latency) ->
                LanDevice(ip, "Pending", "Pending", "Resolving…", latencyMs = latency)
            }
            publishScan(session, state.copy(progress = completed * 75 / range.hosts.size, devices = partial,
                message = "PROBED $completed / ${range.hosts.size} — ${responsive.size} ONLINE"))
        }
        session.check()
        val active = currentRange()
        if (active == null || active.localIp != range.localIp || active.interfaceName != range.interfaceName) {
            publishScan(session, state.copy(message = "NETWORK CHANGED — SCAN AGAIN"))
            return
        }
        val localHosts = range.hosts.filter { Ipv4Subnet.contains(active.localIp, active.localPrefix, it) }
        publishScan(session, state.copy(progress = 80, message = "READING NEIGHBORS / RESOLVING NAMES"))
        val arp = if (BuildConfig.MAC_DISCOVERY_ENABLED && localHosts.isNotEmpty())
            readArpTable(range.copy(hosts = localHosts)) else emptyMap()
        session.check()
        val names = resolveNames(responsive.keys, session)
        session.check()
        val previous = history.load()
        val localSet = localHosts.toHashSet()
        val allAddresses = range.hosts.map { ip ->
            val latency = responsive[ip]
            val mac = arp?.get(ip)
            val old = previous[ip]?.takeIf { mac == null || it.mac.equals(mac, ignoreCase = true) }
            val macLabel = when {
                !BuildConfig.MAC_DISCOVERY_ENABLED -> "Unavailable"
                ip !in localSet -> "Unavailable (routed)"
                mac != null -> mac
                arp == null -> "Unavailable (access)"
                latency == null -> old?.mac ?: "Not recorded"
                else -> "Not recorded"
            }
            LanDevice(ip, macLabel,
                if (mac != null) vendors.find(mac).takeUnless { it == "Unknown" } ?: old?.vendor ?: "Unknown"
                else if (ip !in localSet) "Layer 3 route" else if (latency == null) old?.vendor ?: "Unknown" else "Unknown",
                names[ip]?.takeUnless { it == "Unknown host" } ?: old?.name ?: if (latency != null) "Unknown host" else "No client recorded",
                online = latency != null, latencyMs = latency,
                lastSeen = if (latency != null) System.currentTimeMillis() else old?.lastSeen ?: 0L)
        }
        synchronized(scanLock) {
            session.check()
            val merged = previous.toMutableMap()
            // Store verified identities; remote scans cannot replace a verified MAC.
            allAddresses.filter { arp?.containsKey(it.ip) == true }.forEach { merged[it.ip] = it }
            history.save(merged.values)
            val diagnostic = when {
                !BuildConfig.MAC_DISCOVERY_ENABLED -> "MAC DISABLED"
                arp == null -> "LOCAL MAC UNAVAILABLE"
                localHosts.size < range.hosts.size -> "ROUTED MAC UNAVAILABLE"
                else -> "${arp.size} VERIFIED MACS"
            }
            publishScan(session, ScanState(range.cidr, false, 100, allAddresses,
                "${responsive.size} ONLINE — $diagnostic", true))
        }
    }

    fun close() {
        closed = true
        activeScan?.cancelled?.set(true)
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

    private fun resolveNames(ips: Collection<String>, session: ScanSession): Map<String, String> {
        val names = ConcurrentHashMap<String, String>()
        session.run(nameWorkers, ips.map { ip -> Callable {
            session.check()
            val name = resolveName(ip)
            session.check()
            names[ip] = name
        } }, 6_000, allowPartial = true)
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

    private fun publishScan(session: ScanSession, value: ScanState) {
        synchronized(scanLock) {
            session.check()
            if (activeScan === session) publishState(value, session.generation)
        }
    }

    private fun publishState(value: ScanState, scanGeneration: Long) {
        if (closed) return
        state = value
        main.post { if (!closed && generation == scanGeneration) onState(value) }
    }

    private fun parseRange(cidr: String): NetworkRange? = runCatching {
        val parts = cidr.trim().split('/')
        require(parts.size == 2)
        val prefix = parts[1].toInt()
        // Match desktop limits; /23 includes 510 usable addresses.
        require(prefix in 20..30)
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

    private data class Candidate(val priority: Int, val interfaceName: String, val ip: String, val prefix: Int)
}
