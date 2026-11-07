plugins { id("com.android.application"); id("org.jetbrains.kotlin.android"); id("org.jetbrains.kotlin.plugin.compose") }
android { namespace = "com.glasschat.owner"; compileSdk = 35
    defaultConfig { applicationId = "com.glasschat.owner"; minSdk = 26; targetSdk = 35; versionCode = 1; versionName = "0.1.0"; ndk { abiFilters += setOf("arm64-v8a") } }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        isCoreLibraryDesugaringEnabled = true
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { compose = true }
    // Keep this constrained private preview to 64-bit ARM devices; exclude other Signal runtimes at packaging time.
    // Signal documents its testing JNI library as client-testing-only; the app does not call its APIs.
    packaging { jniLibs { excludes += setOf("**/libsignal_jni_testing.so", "**/x86/**", "**/x86_64/**", "**/armeabi-v7a/**") } }
}
dependencies {
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.4")
    implementation(project(":core-ui"))
    implementation(project(":core-data"))
    implementation(project(":core-crypto"))
    implementation(project(":core-network"))
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.core:core-ktx:1.15.0")
}
