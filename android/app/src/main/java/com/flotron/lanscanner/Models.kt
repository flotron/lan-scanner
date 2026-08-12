package com.flotron.lanscanner

data class LanDevice(
    val ip: String,
    val mac: String,
    val vendor: String,
    val name: String,
    val online: Boolean = true,
    val latencyMs: Long? = null,
    val lastSeen: Long = System.currentTimeMillis(),
    val openPorts: List<Int> = emptyList()
)

data class ScanState(
    val subnet: String = "Not connected",
    val scanning: Boolean = false,
    val progress: Int = 0,
    val devices: List<LanDevice> = emptyList(),
    val message: String = "READY",
    val macAccessAvailable: Boolean = true
)

data class NetworkRange(
    val localIp: String,
    val prefix: Int,
    val hosts: List<String>,
    val networkAddress: String,
    val interfaceName: String
) {
    val cidr: String get() = "$networkAddress/$prefix"
}
