# GlassChat Android preview

GlassChat has two separate Android application modules: GlassChat Owner (`com.glasschat.owner`) and GlassChat Client (`com.glasschat.client`). They share the Compose interface and secure-runtime source, but Owner includes additional owner-gated server controls and a local service-lifecycle panel. This is an implementation preview, not a completed or production-ready messenger.

## Current preview contents

- Supabase Auth/account/device setup source; owner-created invitations; mutual contact consent; out-of-band Signal fingerprint verification; Signal libsignal sessions; a ciphertext-only relay and local encrypted message storage.
- Per-verified-device direct-message encryption, local outbox/inbox, retry/polling, per-device stored/expired status, one-time prekey replenishment and signed EC/Kyber key rotation source.
- Server-managed text groups with expiring invites, roster/membership controls, member removal and revocation, and atomic server acceptance of pairwise-encrypted copies for all verified devices.
- One inline file per message, up to 512 KiB; it travels inside the Signal-encrypted message and the recipient chooses where to save it.
- Local conversation/contact settings and theme/profile previews. Owner also has server-side account/device controls and a metadata-only admin audit view (when migrations are deployed), plus a local Owner service shell.

All listed network and cryptographic paths are source implementations. This preview build is the first compile/package pass; successful compilation does not mean Supabase is deployed, migrations are reviewed or applied, interoperability is proven, or live messaging works. The Owner foreground service does not host the account service or relay. There is no FCM: WorkManager polling is best effort and Android may defer it. Group encryption is pairwise fan-out, not Signal Sender-Key. The server-managed groups are distinct from local UUID-only groups. Large/streamed files, image/video/voice workflows, push, account recovery/backup, and several specification features are unfinished.

See:
- [Build, install and first-run setup](docs/BUILD_AND_INSTALL.md)
- [Current implementation and remaining-work checklist](IMPLEMENTATION_STATUS.md)
- [Supabase configuration, migrations and relay behavior](docs/SUPABASE_AND_RELAY.md)
- [Crypto implementation and licensing notes](docs/CRYPTO_AND_LICENSE.md)

## Private source and preview release

Repository: <https://github.com/Brskkkk/glasschat-android>. It is intended to remain private; the release is a prerelease attached to that private repository and is not a public distribution. APKs in this preview use the Android debug signing configuration, not a production release key. Install only if you understand that the implementation is incomplete and unvalidated on devices.

## Security and live service caveats

Never put a Supabase service-role key, database password, signing private key or other secret in the app, repository, issue, release, or chat. The Android client should use only the Supabase Project URL and public anon key together with the signed-in user's access token. A trusted operator must review and apply migrations `0001` through `0010` in numeric order, configure Supabase Auth and provision the first Owner. The current task has not done this and has no dashboard access. The migrations are source requiring independent review, not a verified live schema or security audit.

The app has not been phone-tested or independently audited. Debug APKs are not appropriate for production or broad distribution. Refer to the implementation checklist for exactly what has and has not been checked.
