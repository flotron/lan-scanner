package com.flotron.lanscanner

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

class DeviceHistory(context: Context) {
    private val preferences = context.getSharedPreferences("device_history", Context.MODE_PRIVATE)

    fun load(): Map<String, LanDevice> {
        val result = mutableMapOf<String, LanDevice>()
        val array = runCatching { JSONArray(preferences.getString("devices", "[]")) }.getOrNull() ?: return result
        for (index in 0 until array.length()) {
            val item = array.optJSONObject(index) ?: continue
            val ip = item.optString("ip")
            val mac = item.optString("mac")
            if (ip.isNotBlank() && mac.isNotBlank()) result[ip] = LanDevice(
                ip, mac, item.optString("vendor", "Unknown"), item.optString("name"), false,
                lastSeen = item.optLong("lastSeen", 0)
            )
        }
        return result
    }

    fun save(devices: Collection<LanDevice>) {
        val array = JSONArray()
        devices.forEach { device -> array.put(JSONObject().apply {
            put("ip", device.ip); put("mac", device.mac); put("vendor", device.vendor)
            put("name", device.name); put("lastSeen", device.lastSeen)
        }) }
        preferences.edit().putString("devices", array.toString()).apply()
    }
}
