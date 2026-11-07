pluginManagement { repositories { google(); mavenCentral(); gradlePluginPortal() } }
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // Signal's official Maven repository. Do not mirror proprietary/private artifacts here.
        maven { url = uri("https://build-artifacts.signal.org/libraries/maven") }
    }
}
rootProject.name = "GlassChat"
include(":app-owner", ":app-client", ":core-ui", ":core-data", ":core-crypto")
