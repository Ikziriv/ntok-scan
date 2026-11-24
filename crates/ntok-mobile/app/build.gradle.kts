plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.ntokscan.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.ntokscan.app"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"

        // URL of a running ntok-web instance. Override in local.properties
        // (ntok.baseUrl=http://192.168.x.x:3000) or with -Pntok.baseUrl=…
        // 10.0.2.2 is host loopback as seen from the Android emulator.
        buildConfigField(
            "String",
            "NTOK_BASE_URL",
            "\"${findProperty("ntok.baseUrl") ?: "http://10.0.2.2:3000"}\"",
        )
    }
    buildFeatures { buildConfig = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    jvmToolchain(17)
}
