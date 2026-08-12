package com.flotron.lanscanner

object NativeArp {
    @Volatile var lastError: String = ""
        private set
    val available: Boolean = runCatching {
        System.loadLibrary("lanscanner_arp")
        true
    }.getOrDefault(false)

    fun lookup(ip: String, interfaceName: String): String? {
        if (!available) return null
        return runCatching { lookupNative(ip, interfaceName) }.getOrNull()
    }

    fun dump(interfaceName: String): Map<String, String>? {
        if (!available) { lastError = "NATIVE LIBRARY NOT AVAILABLE"; return null }
        return runCatching {
            val raw = dumpNative(interfaceName)
            if (raw.startsWith("!")) {
                lastError = raw.drop(1)
                return@runCatching null
            }
            lastError = ""
            raw.lineSequence().mapNotNull { line ->
                val separator = line.indexOf('=')
                if (separator > 0) line.substring(0, separator) to line.substring(separator + 1) else null
            }.toMap()
        }.getOrElse { lastError = it.javaClass.simpleName; null }
    }

    private external fun lookupNative(ip: String, interfaceName: String): String?
    private external fun dumpNative(interfaceName: String): String
}
