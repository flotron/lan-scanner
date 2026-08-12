package com.flotron.lanscanner

import android.content.Context
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.ConcurrentHashMap

class VendorDatabase(private val context: Context) {
    private val vendors = ConcurrentHashMap<String, String>()
    private val preferences = context.getSharedPreferences("vendor_db", Context.MODE_PRIVATE)

    init {
        val cached = preferences.getString("vendors", null)
        if (cached != null) loadJson(cached) else loadFallback()
    }

    fun find(mac: String): String = vendors[mac.replace(":", "").uppercase().take(6)] ?: "Unknown"

    private fun loadFallback() {
        mapOf(
            "001A11" to "Google", "001B63" to "Apple", "001C42" to "Parallels",
            "001E58" to "D-Link", "001F29" to "Hewlett Packard", "0024E8" to "Dell",
            "0418D6" to "Ubiquiti", "18E829" to "Ubiquiti", "24A43C" to "Ubiquiti",
            "60E327" to "TP-Link", "B09575" to "TP-Link", "FC3497" to "ASUSTek",
            "3C5A37" to "Samsung", "F4F5D8" to "Google", "DC2C6E" to "Routerboard"
        ).forEach { (key, value) -> vendors[key] = value }
    }

    private fun loadJson(raw: String) {
        runCatching {
            val json = JSONObject(raw)
            json.keys().forEach { key -> vendors[key] = json.getString(key) }
        }.onFailure { loadFallback() }
    }

    /** Downloads IEEE's public OUI CSV and retains only the assignment/company map locally. */
    fun refresh() {
        val now = System.currentTimeMillis()
        val lastAttempt = preferences.getLong("last_attempt", 0L)
        val lastSuccess = preferences.getLong("last_success", 0L)
        val interval = if (lastSuccess > 0L) 30L * 24 * 60 * 60 * 1_000 else 24L * 60 * 60 * 1_000
        if (now - lastAttempt < interval) return
        preferences.edit().putLong("last_attempt", now).apply()
        runCatching {
            val connection = URL("https://standards-oui.ieee.org/oui/oui.csv").openConnection() as HttpURLConnection
            connection.connectTimeout = 8_000
            connection.readTimeout = 15_000
            connection.setRequestProperty("User-Agent", "LAN-Scanner-Android")
            val updated = JSONObject()
            connection.inputStream.bufferedReader().useLines { lines ->
                lines.drop(1).forEach { line ->
                    val fields = parseCsv(line)
                    if (fields.size >= 3) {
                        val prefix = fields[1].replace("-", "").uppercase()
                        if (prefix.length >= 6) updated.put(prefix.take(6), fields[2])
                    }
                }
            }
            if (updated.length() > 1_000) {
                preferences.edit()
                    .putString("vendors", updated.toString())
                    .putLong("last_success", System.currentTimeMillis())
                    .apply()
                vendors.clear()
                loadJson(updated.toString())
            }
        }
    }

    private fun parseCsv(line: String): List<String> {
        val result = mutableListOf<String>()
        val value = StringBuilder()
        var quoted = false
        line.forEach { char ->
            when {
                char == '"' -> quoted = !quoted
                char == ',' && !quoted -> { result += value.toString(); value.clear() }
                else -> value.append(char)
            }
        }
        result += value.toString()
        return result
    }
}
