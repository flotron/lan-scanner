package com.flotron.lanscanner

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

class WatchPreferences(context: Context) {
    private val preferences = context.getSharedPreferences("watch_preferences", Context.MODE_PRIVATE)
    private fun objectValue(key: String) = runCatching { JSONObject(preferences.getString(key, "{}") ?: "{}") }.getOrDefault(JSONObject())
    private val aliases = objectValue("aliases")

    fun customName(mac: String): String = UserLabels.macKey(mac)?.let { aliases.optString(it) }.orEmpty()
    fun name(device: LanDevice): String = customName(device.mac).ifBlank { device.name }

    fun saveName(mac: String, name: String) {
        val key = requireNotNull(UserLabels.macKey(mac)) { "A recorded device MAC is required." }
        if (name.isBlank()) aliases.remove(key) else aliases.put(key, UserLabels.label(name))
        preferences.edit().putString("aliases", aliases.toString()).apply()
    }

    private fun addresses(array: JSONArray?): List<String> = runCatching {
        requireNotNull(array)
        UserLabels.addresses((0 until array.length()).map { array.getString(it) })
    }.getOrDefault(emptyList())

    fun selection(): List<String> = addresses(runCatching { JSONArray(preferences.getString("selection", "[]")) }.getOrNull())
    fun saveSelection(ips: Collection<String>) {
        preferences.edit().putString("selection", JSONArray(ips.toList()).toString()).apply()
    }

    fun groups(): Map<String, List<String>> {
        val data = objectValue("groups")
        return data.keys().asSequence().associateWith { addresses(data.optJSONArray(it)) }.filterValues { it.isNotEmpty() }.toSortedMap()
    }

    fun saveGroup(name: String, ips: List<String>) {
        val key = UserLabels.label(name)
        val validated = UserLabels.addresses(ips)
        val data = objectValue("groups")
        require(data.has(key) || data.length() < 32) { "Up to 32 groups can be saved. Delete one first." }
        data.put(key, JSONArray(validated))
        preferences.edit().putString("groups", data.toString()).apply()
    }

    fun deleteGroup(name: String) {
        val data = objectValue("groups"); data.remove(name)
        preferences.edit().putString("groups", data.toString()).apply()
    }
}
