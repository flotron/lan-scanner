package com.flotron.lanscanner

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.Window
import android.view.WindowManager

class MainActivity : Activity() {
    private lateinit var dashboard: LanDashboardView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestWindowFeature(Window.FEATURE_NO_TITLE)
        window.setStatusBarColor(0xff020805.toInt())
        window.setNavigationBarColor(0xff020805.toInt())
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        dashboard = LanDashboardView(this)
        setContentView(dashboard)
        if (BuildConfig.MAC_DISCOVERY_ENABLED && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M &&
            checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.ACCESS_COARSE_LOCATION
            ), LOCATION_PERMISSION_REQUEST)
        } else {
            dashboard.beginDiscovery(true)
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == LOCATION_PERMISSION_REQUEST) {
            dashboard.beginDiscovery(grantResults.any { it == PackageManager.PERMISSION_GRANTED })
        }
    }

    companion object {
        private const val LOCATION_PERMISSION_REQUEST = 1201
    }
}
