# GlassChat Android — foundation preview

This repository is an early, explicitly incomplete Android foundation based on the supplied GlassChat specification. It builds two independently installable APK targets and a shared custom Compose UI module.

## What is implemented in this source

- `app-owner` and `app-client` Android application modules with distinct package IDs (`com.glasschat.owner`, `com.glasschat.client`).
- Shared Compose UI foundation using translucent surfaces, gradient lighting and rounded glass-like panels (not a complete Liquid Glass theme system).
- Owner-only foreground-service lifecycle preview, notification channel, Start/Pause/Stop notification actions, and a persistent status notification that explicitly says the backend is not configured.
- Android 13+ notification permission request before starting the service.
- Manifest special-use foreground-service declaration, scoped to this local demo.

## Not implemented; do not treat as ready for messaging or server use

There is no account/authentication service, invitation system, user/device registry, API server, relay, gateway/VPS, database, local encrypted persistence, cryptographic protocol, E2EE, key management, contact flow, conversation UI, attachment transfer, FCM, true service health monitoring, restart/boot recovery, audit log, Owner administration, privacy settings, theme editor, production signing, or release build. The Owner service shell does not listen for requests or host GlassChat. No message is sent or encrypted. It intentionally reports this limitation in the UI and notification.

The foreground-service implementation is a lifecycle demonstration, not evidence that an ordinary phone can host the always-available service in the specification. Android and Play distribution restrictions for `specialUse` services require device/API and policy review before a real deployment. Auto-start, `START_STICKY`, and force-stop recovery are not implemented.

## Build

Requires JDK 17, Android SDK platform 35 and Android Gradle Plugin dependencies.

```sh
./gradlew :app-owner:assembleDebug :app-client:assembleDebug
```

Debug APKs are for development only and are not production signed. Build verification has not passed in this environment: required AndroidX artifacts were absent from the offline cache, and the online Gradle process was terminated before compilation completed.

## Security

This repository contains no backend secrets or signing keys. Keep private keys, tokens, service credentials, production signing material and `.env` files out of Git. `.gitignore` excludes common local secret and keystore files; review every source change before publishing.
