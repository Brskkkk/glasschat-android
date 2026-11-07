# Build, install and first-run setup

This guide describes the GlassChat Owner and GlassChat Client preview source and debug APKs. It does not imply a live backend or production readiness.

## App editions

- GlassChat Owner (`app-owner`, application ID `com.glasschat.owner`) includes the same shared messaging UI as Client plus owner-only server-account/device controls and a local Owner service status shell.
- GlassChat Client (`app-client`, application ID `com.glasschat.client`) is the regular client and does not expose Owner-only administration controls.
- Both currently target Android 35 and require Android 8.0/API 26 or newer. The APKs have different application IDs, so both can be installed on one device.

## Install the supplied debug preview

The private GitHub prerelease [`v0.1.0-preview.1`](https://github.com/Brskkkk/glasschat-android/releases/tag/v0.1.0-preview.1) contains `glasschat-owner-debug.apk` and `app-client-debug.apk`. Download them only while signed into an account authorized to view the private repository. Both are arm64-v8a-only; they will not install on x86/x86_64 or 32-bit ARM devices. On the Android device, open each APK and allow installation from that source if Android asks. Android may show an unknown-source warning because these are debug-signed builds. The Owner and Client APKs can coexist.

Both APKs were successfully assembled and their package IDs and v2 signatures checked. The Client build logged D8 warnings while rewriting Kotlin metadata, although Gradle completed successfully. After publishing this preview, the source toolchain was upgraded to AGP 8.10.1 / Gradle 8.11.1, which meets Kotlin 2.2’s documented D8/R8 requirement. That source change has not been rebuilt, so the published APK still has the warning; treat it as a preview and do not assume runtime stability. Each APK is approximately 194 MB. SHA-256: Owner `ef82d0b032543b8c371ab63a29ea461016d6991d2e781b1b6f41934c9ce82bc2`; Client `c92423626b39a4ed5f09d5a90f1b83e1ae8812e5ac32cf5dcbc82ccfb44e4ad3`. These are debug builds signed with Gradle's debug key. They are not production release-signed. Do not use them as a secure production service, and do not expect a future release-key build to update them seamlessly.

## Build from source

Requirements: JDK 17, Android SDK platform/build tools for API 35, and network access for Gradle/Maven dependencies. Source uses Android Gradle Plugin 8.10.1, Gradle 8.11.1 and Kotlin 2.2.20; this combination was set after the preview build to meet Kotlin 2.2’s documented R8 requirement, and still needs a fresh build verification. From the repository root:

```sh
./gradlew --no-daemon :app-owner:assembleDebug :app-client:assembleDebug
```

For this preview, both app modules are configured for `arm64-v8a` only to keep the packaged Signal native runtime within available build storage. Outputs:

```text
app-owner/build/outputs/apk/debug/app-owner-debug.apk
app-client/build/outputs/apk/debug/app-client-debug.apk
```

To run the repository's unit-test tasks (there may be no test source sets yet):

```sh
./gradlew --no-daemon test
```

The Owner and Client debug APKs were assembled separately and verified as package `com.glasschat.owner` / `com.glasschat.client`, version `0.1.0`, with the Android debug certificate. No unit/integration tests, emulator/device launch, live server, security review or cryptographic interoperability checks were run. The Client packaging emitted D8 Kotlin metadata rewrite warnings. Do not treat a successful build as verification of the server or cryptographic interoperability. Current delivery is debug APKs only; production signing and reproducible release signing are not configured.

## Live Supabase setup required

The apps do not bundle a Supabase project, database password, service-role key, production endpoint, or live Owner account. To attempt live setup:

1. Create a Supabase project under your own account and retain its HTTPS Project URL and public anon/publishable key. Never give the app or anyone the service-role key or database password.
2. Review the SQL and RLS/security-definer procedures with a qualified reviewer. Apply `supabase/migrations/0001_glasschat_auth_metadata.sql` through `0010_atomic_group_fanout.sql` in numeric order using the project's SQL Editor. Stop if any migration errors; never assume a partial sequence succeeded.
3. Configure Supabase Auth policy. Depending on the project's settings, sign-up may require email verification.
4. A trusted project operator must provision the first Owner account/role. The migrations intentionally do not grant Owner to the first person who signs up, and there is no service-role credential in the app.
5. In each app, use the secure account/device setup section to enter the HTTPS Project URL and public anon key, then sign up/sign in. The Owner account can create one-time invitations after it has been provisioned; the Client redeems one.
6. Users exchange their account UUIDs out of band, mutually approve contacts, compare the full Signal identity fingerprint through a trusted separate channel, and enter the expected fingerprint before establishing a session. Do not skip this verification.
7. Only after those steps can the source attempt the authenticated encrypted relay. No live Supabase project or deployment was created or tested for this preview.

The included SQL is source-only and has not been applied to a live project. Migration review in this task is not a complete security audit. A Supabase relay does not make an Owner phone publicly reachable or turn it into a backend server.

## Owner service behavior

The Owner UI includes Start, Pause, Resume, Stop and optional boot-start controls. Starting asks for notification permission on Android 13+ and shows a persistent notification. This service is explicitly a lifecycle-only shell: it does not listen on an API port, host an account registry, maintain a relay connection, or provide public reachability. Its notification states that the backend is not configured. Android/OEM policies can defer boot startup; force-stop requires manually reopening the app. Do not interpret the “active” shell state as an operational server.

## What to verify yourself

After installing, basic screen launch is not a security check. Do not use real sensitive conversations until the project and migrations have been reviewed, deployed and provisioned, and the exact build is tested on devices. Validate registration, invitations, mutual consent, fingerprint verification, direct/group sessions, duplicate and partial delivery handling, acknowledgements and retention, device removal, service/process lifecycle, and actual device-to-device interoperability. The preview has not completed these validations.

## Important limitations

- WorkManager polls/retries best effort; Android can defer it. FCM/push and live WebSockets are not implemented.
- Direct-message fan-out is per device and can have partial relay acceptance; server-managed group batch acceptance is atomic for each new batch when migration 0010 is deployed. Pairwise Signal copies are used, not Sender-Key groups.
- The one-file inline attachment cap is 512 KiB; no blob streaming, image/video viewer or voice messages.
- Some conversation controls/themes are local-only and do not sync. The Owner's separate local registry is a prototype, not the authoritative network account registry.
- Local at-rest protection encrypts selected record payloads using AES-GCM and Android Keystore; routing/index metadata is visible. This is not SQLCipher/full-database encryption.
- No phone-level, full integration, interoperability, security audit or load test has established stability. Signal's libsignal Android library is AGPL-3.0-only and its maintainers say third-party use is unsupported; see [crypto/licensing notes](CRYPTO_AND_LICENSE.md).
