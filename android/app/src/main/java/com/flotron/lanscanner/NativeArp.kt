package com.flotron.lanscanner

object NativeArp {
    val available: Boolean = runCatching {
        System.loadLibrary("lanscanner_arp")
        true
    }.getOrDefault(false)

    fun lookup(ip: String, interfaceName: String): String? {
        if (!available) return null
        return runCatching { lookupNative(ip, interfaceName) }.getOrNull()
    }

    private external fun lookupNative(ip: String, interfaceName: String): String?
}
