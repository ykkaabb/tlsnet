plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "work.ykk.tlsnet"
    compileSdk = 35

    defaultConfig {
        applicationId = "work.ykk.tlsnet"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }

    val releaseStore = System.getenv("TLSNET_SIGNING_STORE_FILE")
    if (!releaseStore.isNullOrBlank()) {
        signingConfigs.create("tlsnetRelease") {
            storeFile = file(releaseStore)
            storePassword = System.getenv("TLSNET_SIGNING_STORE_PASSWORD")
            keyAlias = System.getenv("TLSNET_SIGNING_KEY_ALIAS")
            keyPassword = System.getenv("TLSNET_SIGNING_KEY_PASSWORD")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            signingConfig = signingConfigs.findByName("tlsnetRelease")
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
    }
}

dependencies {
    implementation(files("libs/tlsnet.aar"))
}
