# GlassChat Android — work in progress

This is the existing private repository for the requested GlassChat Owner and Client apps. It is not a usable messenger or a completed server. The source has not been built or tested in this implementation pass; builds, tests, packaging and CI remain intentionally deferred until the full requested feature implementation is in place, as Jr requested.

## Present in source (not build-verified)

- Separate `app-owner` and `app-client` modules/package IDs, sharing a Compose screen.
- A local-only conversation/contact/message UI: create local conversation/contact records, save message text locally, and search the local messages. The UI explicitly says messages are not sent. It now exposes local-copy edit/delete, one local reaction, local bookmarks, and local conversation flags; these actions do not affect another device. Drafts now autosave locally per selected conversation, and pin/archive/mute controls change local flags only; these are not synchronized or backed by remote messaging. Local contacts can be given private per-device nicknames or removed locally; this does not change account names and is not synced. A local theme picker now offers the eight requested color preset names and stores the selected preset encrypted on this device; there is not yet a full custom live editor or performance-adaptive effect system.
- `SealedLocalStore`: payload JSON is AES-GCM encrypted with an Android Keystore key before writing to SQLite. Record kind, opaque ID, conversation ID and timestamp columns remain visible but are authenticated as AES-GCM associated data. A transactional source migration from the prior record format is present but unverified. This is local at-rest protection, not SQLCipher/full-database encryption and not E2EE.
- `queueCiphertext`, `pendingCiphertextFor`, `acknowledgeCiphertext` and `expireCiphertext`: storage operations for per-recipient-device ciphertext copies, idempotent enqueue, no deletion on retrieval, acknowledgement matched to its recipient device, and a seven-day maximum expiry. These are not wired to an API, identity/authentication, a real relay, or a client durable-ack flow.
- Local-only account-registry primitives in `SealedLocalStore`: random one-time invitation codes with digest-only persistence and expiry/revocation, transactional local UUID account creation, account status changes, per-device public-key/FCM-token records and local device revocation. Owner UI can create/copy/revoke local invitations and suspend/restore local accounts. Successful local registry changes now generate encrypted local audit entries in the same SQLite transaction. These are phone-local controls only: there is no complete remote registration UI or authenticated server, and no remote permission is enforced. The local audit trail is not server-authenticated or tamper-resistant.
- Owner foreground-service lifecycle/notification shell with Start/Pause/Resume/Stop actions. It reports the account service and relay unavailable. It does not listen for network requests or host a server.

## Still required by the supplied specification

The real Owner/Client identity and authentication system, registration/invitations, account/device/key registries, secure contact requests, a maintained Signal-compatible E2EE session implementation, authenticated network APIs, functioning Owner server, public reachability, ciphertext-only network relay and durable recipient acknowledgements, encrypted attachments, FCM, groups and normal messaging features, Owner administration, true health/recovery behavior, complete Liquid Glass theme editor and effect system, migrations, and usable release builds are not implemented. No feature should be considered complete based only on the current source.

The complete feature checklist and deployment limitations are in [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md).

## Build and release

No APK is available. A previous local Gradle attempt failed during `:app-owner:mergeDebugGlobalSynthetics` because required AndroidX/Guava artifacts were unavailable offline; an earlier online Gradle attempt ended before compilation. Per Jr's instruction, do not build, test, package APKs, or trigger CI until the requested feature implementation is complete and stable.

## Security

No service credentials, backend tokens, production signing keys or other secrets belong in this repository. No production signing configuration or backend credentials have been supplied. The currently implemented local store and queue do not make the app ready for real private communication.
