package com.flotron.lanscanner

/** Numeric IPv4 operations; never performs DNS lookups. */
internal object Ipv4Subnet {
    fun value(ip: String): Long {
        val parts = ip.split('.')
        require(parts.size == 4 && parts.all { part ->
            part.isNotEmpty() && part.all { it in '0'..'9' } && part.toIntOrNull() in 0..255
        })
        return parts.fold(0L) { total, part -> (total shl 8) or part.toLong() }
    }

    fun address(value: Long): String = (3 downTo 0).joinToString(".") {
        ((value ushr (it * 8)) and 255).toString()
    }

    fun network(ip: String, prefix: Int): Long {
        require(prefix in 0..32)
        val mask = if (prefix == 0) 0L else (0xffffffffL shl (32 - prefix)) and 0xffffffffL
        return value(ip) and mask
    }

    fun contains(localIp: String, prefix: Int, ip: String): Boolean =
        network(localIp, prefix) == network(ip, prefix)

    fun hosts(ip: String, prefix: Int): List<String> {
        require(prefix in 20..30)
        val start = network(ip, prefix)
        return (start + 1 until start + (1L shl (32 - prefix)) - 1).map(::address)
    }
}
