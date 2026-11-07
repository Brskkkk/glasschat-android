plugins { id("com.android.library"); id("org.jetbrains.kotlin.android") }

android {
    namespace = "com.glasschat.crypto"
    compileSdk = 35
    defaultConfig { minSdk = 26 }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    // Official Signal Android artifact; see docs/CRYPTO_AND_LICENSE.md before distributing.
    implementation("org.signal:libsignal-android:0.106.2")
}
