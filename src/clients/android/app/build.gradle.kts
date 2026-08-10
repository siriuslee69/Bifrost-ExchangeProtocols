import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
  id("com.android.application")
  id("org.jetbrains.kotlin.android")
}

val bifrostAndroidAbis = listOf("arm64-v8a", "x86_64")

android {
  namespace = "com.siriuslee.bifrost.android"
  compileSdk = 36

  defaultConfig {
    applicationId = "com.siriuslee.bifrost.android"
    minSdk = 26
    targetSdk = 36
    versionCode = 1
    versionName = "0.1.0"
    testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

    ndk {
      abiFilters += bifrostAndroidAbis
    }

  }

  buildTypes {
    debug {
      isDebuggable = true
    }
    release {
      isMinifyEnabled = false
      proguardFiles(
        getDefaultProguardFile("proguard-android-optimize.txt"),
        "proguard-rules.pro",
      )
    }
  }

  buildFeatures {
    buildConfig = true
  }

  compileOptions {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
  }

  kotlin {
    compilerOptions {
      jvmTarget.set(JvmTarget.JVM_17)
    }
  }

}

dependencies {
  testImplementation("junit:junit:4.13.2")
  androidTestImplementation("androidx.test:runner:1.6.2")
  androidTestImplementation("androidx.test.ext:junit:1.2.1")
}
