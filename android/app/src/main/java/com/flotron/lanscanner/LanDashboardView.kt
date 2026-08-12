package com.flotron.lanscanner

import android.app.AlertDialog
import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RectF
import android.graphics.Typeface
import android.os.Handler
import android.os.Looper
import android.view.MotionEvent
import android.view.View
import android.widget.EditText
import kotlin.math.abs
import kotlin.math.max

class LanDashboardView(context: Context) : View(context) {
    private val green = Color.rgb(0, 255, 120)
    private val pale = Color.rgb(218, 255, 230)
    private val dim = Color.rgb(103, 157, 121)
    private val red = Color.rgb(255, 76, 91)
    private val panel = Color.rgb(3, 22, 12)
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply { typeface = Typeface.MONOSPACE }
    private val engine = LanScanEngine(context) { updateState(it) }
    private val handler = Handler(Looper.getMainLooper())
    private var state = ScanState()
    private var scrollYValue = 0f
    private var downY = 0f
    private var lastY = 0f
    private var contentHeight = 1200f
    private val rowRects = mutableListOf<Pair<RectF, LanDevice>>()
    private val watchRects = mutableListOf<Pair<RectF, LanDevice>>()
    private val watched = linkedSetOf<String>()
    private val watchInFlight = mutableSetOf<String>()
    private val watchResults = mutableMapOf<String, Pair<Boolean, Long?>>()
    private val watchHistory = mutableMapOf<String, MutableList<Boolean>>()
    private var scanRect = RectF()
    private var rangeRect = RectF()
    private var filterRect = RectF()
    private var sortRect = RectF()
    private var customRange: String? = null
    private var onlineOnly = false
    private var sortMode = 0
    private var selected: LanDevice? = null
    private var detailPorts: List<Int>? = null
    private var detailRect = RectF()
    private var lastScanStarted = 0L
    private val density = resources.displayMetrics.density

    init {
        setBackgroundColor(Color.rgb(2, 8, 5))
        isFocusable = true
        startWatchLoop()
        startAutoScan()
    }

    private fun updateState(value: ScanState) {
        state = value
        if (!value.scanning && value.progress == 100) lastScanStarted = System.currentTimeMillis()
        invalidate()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        drawBackdrop(canvas)
        canvas.save()
        canvas.translate(0f, -scrollYValue)
        val pad = 18f * density
        var y = 26f * density
        y = drawHeader(canvas, pad, y)
        y = drawControls(canvas, pad, y + 22f * density)
        if (state.scanning) y = drawProgress(canvas, pad, y + 12f * density)
        if (watched.isNotEmpty()) y = drawWatchPanel(canvas, pad, y + 12f * density)
        y = drawStats(canvas, pad, y + 14f * density)
        y = drawDevices(canvas, pad, y + 14f * density)
        contentHeight = y + 40f * density
        selected?.let { drawDetails(canvas, it) }
        canvas.restore()
    }

    private fun drawBackdrop(canvas: Canvas) {
        paint.strokeWidth = 1f
        paint.color = Color.argb(18, 0, 255, 120)
        var y = 0f
        while (y < height) { canvas.drawLine(0f, y, width.toFloat(), y, paint); y += 4f }
        paint.textSize = 11f * density
        paint.color = Color.argb(15, 0, 255, 120)
        val glyphs = "01アイウエオカキクケコ"
        for (column in 0 until max(1, width / 70)) {
            val x = (column * 71 + 33).toFloat()
            val yy = ((column * 113 + System.currentTimeMillis() / 90) % max(1, height)).toFloat()
            canvas.drawText(glyphs[column % glyphs.length].toString(), x, yy, paint)
        }
    }

    private fun drawHeader(canvas: Canvas, x: Float, y: Float): Float {
        text(canvas, "NETWORK RECONNAISSANCE CONSOLE", x, y, 9f, dim, spacing = 2f)
        text(canvas, "LAN", x, y + 43f * density, 31f, pale, bold = true)
        text(canvas, "SCANNER", x + 72f * density, y + 43f * density, 31f, green, bold = true)
        text(canvas, "● LIVE", width - 83f * density, y + 12f * density, 8f, green)
        line(canvas, x, y + 64f * density, width - x, y + 64f * density)
        return y + 64f * density
    }

    private fun drawControls(canvas: Canvas, x: Float, y: Float): Float {
        val h = 104f * density
        panel(canvas, RectF(x, y, width - x, y + h))
        text(canvas, "NETWORK INTERFACE", x + 14f * density, y + 22f * density, 8f, dim, spacing = 1.3f)
        text(canvas, "SCAN RANGE", x + 14f * density, y + 61f * density, 8f, dim, spacing = 1.3f)
        val range = engine.currentRange()
        rangeRect = RectF(x + 120f * density, y + 39f * density, width - x - 12f * density, y + 68f * density)
        text(canvas, range?.let { "${it.interfaceName} — ${it.localIp}" } ?: "NO WI-FI / ETHERNET", x + 130f * density, y + 22f * density, 9f, pale)
        text(canvas, customRange ?: range?.cidr ?: "—", x + 130f * density, y + 61f * density, 10f, pale)
        scanRect = RectF(x + 14f * density, y + 72f * density, width - x - 14f * density, y + 98f * density)
        button(canvas, scanRect, if (state.scanning) "SCANNING ${state.progress}%" else "▶ INITIATE SCAN")
        return y + h
    }

    private fun drawProgress(canvas: Canvas, x: Float, y: Float): Float {
        text(canvas, state.message, x, y + 10f * density, 8f, dim)
        val track = RectF(x, y + 18f * density, width - x, y + 21f * density)
        paint.color = Color.rgb(14, 42, 25); canvas.drawRect(track, paint)
        paint.color = green; canvas.drawRect(track.left, track.top, track.left + track.width() * state.progress / 100f, track.bottom, paint)
        return y + 28f * density
    }

    private fun drawWatchPanel(canvas: Canvas, x: Float, y: Float): Float {
        val targets = state.devices.filter { it.ip in watched }
        val h = (48 + targets.size * 61).toFloat() * density
        panel(canvas, RectF(x, y, width - x, y + h), strong = true)
        text(canvas, "IMMEDIATE WATCH", x + 14f * density, y + 19f * density, 8f, green, bold = true)
        text(canvas, "SECOND-BY-SECOND PING", x + 14f * density, y + 35f * density, 10f, pale, bold = true)
        var rowY = y + 48f * density
        targets.forEach { device ->
            val result = watchResults[device.ip]
            val online = result?.first
            text(canvas, if (online == false) "DOWN" else if (online == true) "ONLINE" else "CHECKING", x + 14f * density, rowY + 16f * density, 8f, if (online == false) red else green, bold = true)
            text(canvas, device.ip, x + 84f * density, rowY + 16f * density, 9f, pale)
            val latency = result?.second?.let { "${it}ms" } ?: "—"
            text(canvas, latency, width - x - 48f * density, rowY + 16f * density, 8f, dim)
            val history = watchHistory[device.ip].orEmpty()
            val slots = max(8, ((width - 2 * x - 28f * density) / (13f * density)).toInt())
            for (slot in 0 until slots) {
                val left = x + 14f * density + slot * 13f * density
                val box = RectF(left, rowY + 27f * density, left + 9f * density, rowY + 39f * density)
                paint.color = when (history.getOrNull(slot)) { true -> green; false -> red; null -> Color.rgb(18, 49, 29) }
                canvas.drawRect(box, paint)
            }
            line(canvas, x + 12f * density, rowY + 50f * density, width - x - 12f * density, rowY + 50f * density, alpha = 25)
            rowY += 61f * density
        }
        return y + h
    }

    private fun drawStats(canvas: Canvas, x: Float, y: Float): Float {
        val gap = 8f * density
        val cardW = (width - 2 * x - gap) / 2
        val online = state.devices.count { it.online }
        stat(canvas, RectF(x, y, x + cardW, y + 67f * density), online.toString(), "HOSTS ONLINE")
        stat(canvas, RectF(x + cardW + gap, y, width - x, y + 67f * density), state.devices.size.toString(), "VERIFIED MACS")
        stat(canvas, RectF(x, y + 75f * density, x + cardW, y + 142f * density), "${state.progress}%", "SCAN PROGRESS")
        stat(canvas, RectF(x + cardW + gap, y + 75f * density, width - x, y + 142f * density), if (lastScanStarted == 0L) "NEVER" else "DONE", "LAST SCAN")
        return y + 142f * density
    }

    private fun drawDevices(canvas: Canvas, x: Float, y: Float): Float {
        rowRects.clear(); watchRects.clear()
        panel(canvas, RectF(x, y, width - x, y + 85f * density))
        text(canvas, "DISCOVERED HOSTS", x + 14f * density, y + 23f * density, 12f, green, bold = true)
        text(canvas, state.message, x + 14f * density, y + 41f * density, 7f, dim)
        filterRect = RectF(x + 12f * density, y + 52f * density, x + 142f * density, y + 78f * density)
        sortRect = RectF(x + 150f * density, y + 52f * density, width - x - 12f * density, y + 78f * density)
        button(canvas, filterRect, if (onlineOnly) "ONLINE ONLY" else "ALL CLIENTS")
        val sortNames = arrayOf("IP", "STATUS", "NAME", "MAC", "VENDOR")
        button(canvas, sortRect, "SORT: ${sortNames[sortMode]}")
        var rowY = y + 93f * density
        if (!state.macAccessAvailable) {
            panel(canvas, RectF(x, rowY, width - x, rowY + 110f * density), strong = true)
            text(canvas, "MAC ACCESS REQUIRED", x + 14f * density, rowY + 30f * density, 12f, red, bold = true)
            text(canvas, "THIS ANDROID BUILD BLOCKED /proc/net/arp", x + 14f * density, rowY + 55f * density, 8f, pale)
            text(canvas, "NO INCOMPLETE RESULTS ARE SHOWN", x + 14f * density, rowY + 78f * density, 8f, dim)
            return rowY + 110f * density
        }
        if (state.devices.isEmpty()) {
            text(canvas, if (state.scanning) "SCANNING..." else "TAP INITIATE SCAN", x + 14f * density, rowY + 25f * density, 10f, dim)
            return rowY + 60f * density
        }
        val visible = state.devices
            .filter { !onlineOnly || it.online }
            .let { devices -> when (sortMode) {
                1 -> devices.sortedWith(compareByDescending<LanDevice> { it.online }.thenBy { ipNumeric(it.ip) })
                2 -> devices.sortedBy { it.name.lowercase() }
                3 -> devices.sortedBy { it.mac }
                4 -> devices.sortedBy { it.vendor.lowercase() }
                else -> devices.sortedBy { ipNumeric(it.ip) }
            } }
        visible.forEach { device ->
            val rect = RectF(x, rowY, width - x, rowY + 105f * density)
            panel(canvas, rect, alpha = if (device.online) 230 else 105)
            val watch = RectF(x + 12f * density, rowY + 14f * density, x + 37f * density, rowY + 39f * density)
            paint.style = Paint.Style.STROKE; paint.strokeWidth = 1.5f * density; paint.color = if (device.ip in watched) green else dim
            canvas.drawRect(watch, paint); paint.style = Paint.Style.FILL
            if (device.ip in watched) text(canvas, "✓", watch.left + 5f * density, watch.bottom - 6f * density, 11f, green, bold = true)
            watchRects += watch to device
            text(canvas, if (device.online) "● ONLINE" else "● OFFLINE", x + 48f * density, rowY + 29f * density, 8f, if (device.online) green else dim, bold = true)
            text(canvas, device.ip, x + 13f * density, rowY + 59f * density, 13f, pale, bold = true)
            text(canvas, device.mac, x + 13f * density, rowY + 78f * density, 9f, dim)
            text(canvas, device.name, x + 170f * density, rowY + 58f * density, 9f, pale)
            text(canvas, device.vendor.take(25), x + 170f * density, rowY + 78f * density, 8f, dim)
            text(canvas, "›", width - x - 17f * density, rowY + 65f * density, 20f, green)
            rowRects += rect to device
            rowY += 113f * density
        }
        return rowY
    }

    private fun drawDetails(canvas: Canvas, device: LanDevice) {
        val top = scrollYValue + 40f * density
        detailRect = RectF(12f * density, top, width - 12f * density, top + 440f * density)
        paint.color = Color.argb(245, 2, 12, 7); canvas.drawRect(detailRect, paint)
        paint.style = Paint.Style.STROKE; paint.strokeWidth = 1.5f * density; paint.color = green; canvas.drawRect(detailRect, paint); paint.style = Paint.Style.FILL
        text(canvas, "NODE INSPECTION", detailRect.left + 18f * density, top + 27f * density, 8f, green)
        text(canvas, "×", detailRect.right - 34f * density, top + 32f * density, 22f, green)
        text(canvas, device.ip, detailRect.left + 18f * density, top + 63f * density, 20f, pale, bold = true)
        line(canvas, detailRect.left + 18f * density, top + 78f * density, detailRect.right - 18f * density, top + 78f * density)
        detailLine(canvas, "STATUS", if (device.online) "ONLINE" else "OFFLINE", top + 112f * density)
        detailLine(canvas, "MAC", device.mac, top + 150f * density)
        detailLine(canvas, "MANUFACTURER", device.vendor, top + 188f * density)
        detailLine(canvas, "HOST", device.name, top + 226f * density)
        detailLine(canvas, "LATENCY", device.latencyMs?.let { "${it} ms" } ?: "NO REPLY", top + 264f * density)
        text(canvas, "OPEN TCP PORTS", detailRect.left + 18f * density, top + 304f * density, 8f, dim)
        val ports = detailPorts
        text(canvas, when { ports == null -> "SCANNING..."; ports.isEmpty() -> "NONE FOUND"; else -> ports.joinToString("  ") }, detailRect.left + 18f * density, top + 334f * density, 11f, if (ports == null) green else pale)
        button(canvas, RectF(detailRect.left + 18f * density, top + 370f * density, detailRect.right - 18f * density, top + 414f * density), "CLOSE")
    }

    private fun detailLine(canvas: Canvas, label: String, value: String, y: Float) {
        text(canvas, label, detailRect.left + 18f * density, y, 8f, dim)
        text(canvas, value, detailRect.left + 120f * density, y, 10f, pale)
    }

    override fun onTouchEvent(event: MotionEvent): Boolean {
        when (event.actionMasked) {
            MotionEvent.ACTION_DOWN -> { downY = event.y; lastY = event.y; return true }
            MotionEvent.ACTION_MOVE -> {
                val delta = lastY - event.y; lastY = event.y
                scrollYValue = (scrollYValue + delta).coerceIn(0f, max(0f, contentHeight - height))
                invalidate(); return true
            }
            MotionEvent.ACTION_UP -> {
                if (abs(event.y - downY) > 14f * density) return true
                val x = event.x; val y = event.y + scrollYValue
                if (selected != null) { selected = null; detailPorts = null; invalidate(); return true }
                if (rangeRect.contains(x, y)) { showRangeDialog(); return true }
                if (scanRect.contains(x, y)) { engine.scan(customRange); return true }
                if (filterRect.contains(x, y)) { onlineOnly = !onlineOnly; invalidate(); return true }
                if (sortRect.contains(x, y)) { sortMode = (sortMode + 1) % 5; invalidate(); return true }
                watchRects.firstOrNull { it.first.contains(x, y) }?.let { (_, device) ->
                    if (device.ip in watched) {
                        watched.remove(device.ip); watchHistory.remove(device.ip)
                    } else if (watched.size < 16) watched.add(device.ip)
                    invalidate(); return true
                }
                rowRects.firstOrNull { it.first.contains(x, y) }?.let { (_, device) ->
                    selected = device; detailPorts = null; engine.scanPorts(device.ip) { detailPorts = it; invalidate() }; invalidate(); return true
                }
            }
        }
        return true
    }

    private fun startWatchLoop() {
        handler.post(object : Runnable {
            override fun run() {
                state.devices.filter { it.ip in watched }.forEach { device ->
                    if (!watchInFlight.add(device.ip)) return@forEach
                    Thread { val latency = engine.probe(device.ip); handler.post {
                        watchInFlight.remove(device.ip)
                        watchResults[device.ip] = (latency != null) to latency
                        val history = watchHistory.getOrPut(device.ip) { mutableListOf() }
                        val slots = max(8, ((width - 64f * density) / (13f * density)).toInt())
                        if (history.size >= slots) history.clear()
                        history += latency != null
                        invalidate()
                    } }.start()
                }
                handler.postDelayed(this, 1000)
            }
        })
    }

    private fun startAutoScan() {
        handler.postDelayed(object : Runnable {
            override fun run() {
                if (!state.scanning) engine.scan(customRange)
                handler.postDelayed(this, 15_000)
            }
        }, 750)
    }

    private fun showRangeDialog() {
        val input = EditText(context).apply {
            setText(customRange ?: engine.currentRange()?.cidr.orEmpty())
            setTextColor(pale); setHintTextColor(dim); setBackgroundColor(Color.rgb(3, 22, 12))
            typeface = Typeface.MONOSPACE; setPadding(20, 12, 20, 12)
        }
        AlertDialog.Builder(context)
            .setTitle("SCAN RANGE (/24 TO /30)")
            .setView(input)
            .setPositiveButton("APPLY") { _, _ ->
                val value = input.text.toString().trim()
                customRange = value.ifBlank { null }
                engine.scan(customRange)
                invalidate()
            }
            .setNegativeButton("DEFAULT") { _, _ -> customRange = null; engine.scan(); invalidate() }
            .show()
    }

    private fun ipNumeric(ip: String): Long = runCatching {
        ip.split('.').fold(0L) { total, value -> total * 256 + value.toLong() }
    }.getOrDefault(Long.MAX_VALUE)

    private fun stat(canvas: Canvas, rect: RectF, value: String, label: String) {
        panel(canvas, rect)
        paint.color = green; canvas.drawRect(rect.left, rect.top, rect.left + 2f * density, rect.bottom, paint)
        text(canvas, value, rect.left + 14f * density, rect.top + 32f * density, 19f, green, bold = true)
        text(canvas, label, rect.left + 14f * density, rect.top + 53f * density, 7f, dim, spacing = 1f)
    }

    private fun panel(canvas: Canvas, rect: RectF, strong: Boolean = false, alpha: Int = 220) {
        paint.color = Color.argb(alpha, Color.red(panel), Color.green(panel), Color.blue(panel)); canvas.drawRect(rect, paint)
        paint.style = Paint.Style.STROKE; paint.strokeWidth = if (strong) 1.5f * density else 1f
        paint.color = Color.argb(if (strong) 125 else 65, 0, 255, 120); canvas.drawRect(rect, paint); paint.style = Paint.Style.FILL
    }

    private fun button(canvas: Canvas, rect: RectF, label: String) {
        paint.color = Color.argb(18, 0, 255, 120); canvas.drawRect(rect, paint)
        paint.style = Paint.Style.STROKE; paint.strokeWidth = 1f * density; paint.color = green; canvas.drawRect(rect, paint); paint.style = Paint.Style.FILL
        paint.textSize = 10f * density; paint.typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD); paint.letterSpacing = .08f
        val width = paint.measureText(label); paint.color = green
        canvas.drawText(label, rect.centerX() - width / 2, rect.centerY() + 4f * density, paint); paint.letterSpacing = 0f
    }

    private fun text(canvas: Canvas, value: String, x: Float, y: Float, size: Float, color: Int, bold: Boolean = false, spacing: Float = 0f) {
        paint.textSize = size * density; paint.color = color; paint.typeface = Typeface.create(Typeface.MONOSPACE, if (bold) Typeface.BOLD else Typeface.NORMAL)
        paint.letterSpacing = spacing / 10f
        canvas.drawText(value, x, y, paint); paint.letterSpacing = 0f
    }

    private fun line(canvas: Canvas, x1: Float, y1: Float, x2: Float, y2: Float, alpha: Int = 65) {
        paint.color = Color.argb(alpha, 0, 255, 120); paint.strokeWidth = 1f; canvas.drawLine(x1, y1, x2, y2, paint)
    }
}
