plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val lanScannerKeystorePath = System.getenv("LANSCANNER_KEYSTORE_PATH")

android {
    namespace = "com.flotron.lanscanner"
    compileSdk = 31

    defaultConfig {
        applicationId = "com.flotron.lanscanner"
        minSdk = 29
        targetSdk = 31
        versionCode = 10
        versionName = "0.2.3"
        externalNativeBuild {
            cmake { cppFlags += "-std=c++17" }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    externalNativeBuild {
        cmake { path = file("src/main/cpp/CMakeLists.txt") }
    }

    buildFeatures { buildConfig = true }
    lint {
        // This sideload-only build intentionally targets API 31 to retain local ARP/MAC access.
        disable += "ExpiredTargetSdkVersion"
    }
    signingConfigs {
        if (!lanScannerKeystorePath.isNullOrBlank()) {
            create("stableRelease") {
                storeFile = file(lanScannerKeystorePath)
                storePassword = "lan-scanner-release"
                keyAlias = "lan-scanner"
                keyPassword = "lan-scanner-release"
            }
        }
    }
    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfigs.findByName("stableRelease")?.let { signingConfig = it }
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
}

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-stdlib:2.0.21")
}
