import java.io.ByteArrayOutputStream

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// versionCode 用 git 提交数自动递增（Actions 里 checkout 必须 fetch-depth: 0）
fun gitVersionCode(): Int {
    return try {
        val proc = ProcessBuilder("git", "rev-list", "--count", "HEAD")
            .redirectErrorStream(true)
            .start()
        val out = ByteArrayOutputStream()
        proc.inputStream.copyTo(out)
        proc.waitFor()
        if (proc.exitValue() == 0) out.toString().trim().toInt() else 1
    } catch (e: Exception) { 1 }
}

android {
    namespace = "com.youyoudezhuzhu.uutransparentproxy"
    compileSdk = 34
    ndkVersion = "26.1.10909125"

    defaultConfig {
        applicationId = "com.youyoudezhuzhu.uutransparentproxy"
        minSdk = 26
        targetSdk = 34
        versionCode = gitVersionCode()
        versionName = "1.0.0"

        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a")
        }

        externalNativeBuild {
            cmake {
                cFlags += "-std=gnu11 -Wall -O2"
            }
        }
    }

    buildTypes {
        getByName("debug") {
            isMinifyEnabled = false
            // 云编译产物为未签名 Debug APK（需求原文），可直装
        }
        getByName("release") {
            isMinifyEnabled = false
            // 同样不签名，交由用户/云环境自行处理
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/jni/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        viewBinding = true
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.activity:activity-ktx:1.9.1")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.4")
    implementation("androidx.recyclerview:recyclerview:1.3.2")
}
