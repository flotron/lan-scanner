package com.flotron.lanscanner

/** Identity and input rules shared by persistence and the UI. Never use an IP as an alias key. */
object UserLabels {
    fun macKey(value: String): String? {
        val key = value.trim().uppercase(java.util.Locale.ROOT).replace('-', ':')
        if (!Regex("([0-9A-F]{2}:){5}[0-9A-F]{2}").matches(key)) return null
        if (key == "00:00:00:00:00:00" || key.take(2).toInt(16) and 1 != 0) return null
        return key
    }

    fun label(value: String): String = value.trim().also {
        require(it.isNotEmpty() && it.length <= 64 && it.none { char -> char.code < 32 }) {
            "Use a name of 1–64 characters."
        }
    }

    fun addresses(values: List<String>): List<String> {
        require(values.size in 1..16) { "Select between 1 and 16 IP addresses." }
        return values.map { ip ->
            val parts = ip.split('.')
            require(parts.size == 4 && parts.all { it.isNotEmpty() && it.all(Char::isDigit) && (it.toIntOrNull()?.let { number -> number in 0..255 } == true) }) { "Invalid IPv4 address." }
            val numbers = parts.map(String::toInt)
            require(numbers[0] !in 224..239 && numbers.any { it != 0 } && numbers.any { it != 255 }) { "Use individual device addresses." }
            numbers.joinToString(".")
        }.distinct()
    }
}
