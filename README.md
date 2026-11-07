# GlassChat Android — work in progress

This is the private source repository for the requested GlassChat Owner and Client apps. Both app entry points now include source wiring for Supabase Auth, invitations/device setup, verified Signal sessions, ciphertext-only relay messaging, and a best-effort WorkManager sync path. It is not yet a validated or production-ready messenger: the Supabase project is not configured, migrations are not deployed, and builds/tests/packaging remain paused as Jr requested.

## Present in source (not build-verified)

- Separate `app-owner` and `app-client` modules/package IDs, sharing a Compose screen. The network-backed flow requires a deployed and reviewed Supabase project, initial Owner provisioning, and bilateral account/device setup.
- Eight local theme presets, a validated custom accent color, and a local profile preview (display name, handle, about); these settings remain on-device and are not published.
- A shared local-first conversation/contact/message UI with local search, drafts, edits/deletion, reactions, bookmarks, pin/archive/mute flags and private nicknames. The local controls are not synchronized; the verified Signal/Supabase send/receive path is a separate opt-in path and remains untested. The local theme picker includes eight presets plus a custom accent editor, not the full requested effect system or performance adaptation.
- `SealedLocalStore`: payload JSON is AES-GCM encrypted with an Android Keystore key before writing to SQLite. Record kind, opaque ID, conversation ID and timestamp columns remain visible but are authenticated as AES-GCM associated data. A transactional source migration from the prior record format is present but unverified. This is local at-rest protection, not SQLCipher/full-database encryption and not E2EE.
- Signal/libsignal identity, prekey and session state is sealed locally. The pipeline wraps ciphertext in a versioned envelope and atomically pairs ratchet advancement with its encrypted local outbox or received local message. The coordinator submits ciphertext to authenticated Supabase RPCs using idempotent delivery IDs and acknowledges inbound copies only after local persistence. These source paths have not been built or interoperably tested.
- Supabase source integration for Auth, invitation redemption/Owner invitation creation, device registration, contact consent, public Signal prekeys, and authenticated per-device ciphertext relay. Migrations are un-deployed source and require security review; the initial Owner must be provisioned by a trusted operator. The separate phone-local registry remains a local prototype, not a remote administration system.
- Owner foreground-service lifecycle/notification shell with Start/Pause/Resume/Stop actions, an opt-in boot-start setting that honors explicit Stop, and a persisted last-start timestamp. It does not listen for requests or host the relay. Both apps now schedule network-constrained encrypted polling/retry through WorkManager after peer verification; users can opt in to generic local notifications on newly saved messages (no sender/text preview). Android may defer polling; this is not FCM or real-time push.

## Still required by the supplied specification

The included source has not been compiled or security-audited. Live Supabase configuration/deployment and interoperability remain unverified; Owner phone hosting/public reachability, FCM/push, attachments, full group management and many requested product features remain unfinished. A basic local group-text path now fans out pairwise Signal ciphertext to the verified devices linked to a shared UUID, but it has no authoritative roster or group Sender-Key protocol. Do not consider the application complete from source inspection alone.

The complete feature checklist and deployment limitations are in [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md).

## Build and release

No new APK is available. A previous local Gradle attempt failed during `:app-owner:mergeDebugGlobalSynthetics` because required AndroidX/Guava artifacts were unavailable offline; an earlier online Gradle attempt ended before compilation. Per Jr's instruction, do not build, test, package APKs, or trigger CI until the requested feature implementation is complete and stable.

## Security

No service credentials, backend tokens, production signing keys or other secrets belong in this repository. No production signing configuration or backend credentials have been supplied. The currently implemented local store and queue do not make the app ready for real private communication.
