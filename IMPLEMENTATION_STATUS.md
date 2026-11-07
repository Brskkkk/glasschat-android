# GlassChat implementation status

This is a source inspection report, not a release. The project has not been built or tested in this work, per Jr's instruction not to build/package until the requested implementation is complete and stable. Earlier repository history records a Gradle dependency-resolution failure; no APK or CI run is available as evidence.

| Area | Current state |
|---|---|
| Independent Owner and Client packages | Gradle modules and distinct application IDs are present in source; not build-verified. |
| Local conversation/contact/message UI | Local creation, message save/search, local-only message edit/delete, a local reaction, local bookmarks, autosaved conversation drafts, pin/archive/mute controls, private local contact nicknames and local removal exist in source. No remote contact lookup or transmission. |
| Local data protection | Payload JSON uses AES-GCM with an Android Keystore key. The current source binds ciphertext to record identity and routing metadata as associated data, and includes a v1-to-v2 in-place migration intended to preserve existing encrypted rows; neither behavior has been build- or migration-tested. SQLite routing/index metadata remains visible. This is not SQLCipher/full-database encryption and not E2EE. No recovery/backup UI. |
| Ciphertext delivery storage primitives | Per-recipient-device queue storage, no-delete-on-fetch, device-matched ack and max seven-day expiry methods exist in source. No HTTP/API integration, caller authentication, real client-side durable commit, notification, or actual relay service. |
| Local account registry | Digest-only one-time invitation records, transactional local UUID account creation, account status changes, and per-device public-key/FCM-token records and revocation exist as local storage primitives. The Owner screen exposes local invitation creation/revocation and local account listing/suspend/restore. The invite can be copied on request; only its digest is stored locally. Registry mutations now create encrypted local audit entries in the same SQLite transaction, and the Owner screen shows recent events. This log is not server-authenticated or tamper-resistant. None of this reaches another device; no Client redemption/registration flow, authenticated remote server or server-side permission enforcement exists. |
| Owner foreground service | Start/Pause/Resume/Stop lifecycle and notification shell exist. It does not host an API, account registry or relay; its status intentionally says those are unavailable. Boot/autostart/network monitoring, proper restart recovery and real service health are absent. |
| End-to-end encryption | Not implemented. No reviewed Signal-compatible library is integrated; local AES-GCM protects records at rest only. Library/license choice remains pending; no library has been selected or integrated. |
| Authentication, network APIs and relay | Not implemented. No authenticated account service, HTTPS/WebSocket API, reachable public endpoint or temporary relay is wired up. |
| FCM | Not integrated. No Firebase project configuration or real token delivery path. |
| Themes and profile presentation | A source-only local picker has the eight named presets, a validated custom accent color, and a local profile preview with display name/handle/about. Settings are encrypted at rest in the local record store. Profile data is not published or tied to authenticated identity; there is no complete live editor, animation/refraction tuning or performance adaptation. Not build-verified. |
| Remaining requested messenger/Owner features | Groups, real contact requests, message transport/delivery receipts, attachments, voice/media pipeline, full notifications, custom Theme Studio editing, owner administration UI, backup/recovery and broad security/reliability coverage remain incomplete. |
| Build, tests and APKs | Not run or produced in this work. User requested no packaging until full implementation and stability checks. |
| Repository | WIP source changes are being kept in the existing private `glasschat-android` repository; consult its `main` history for the latest commit. |

## Reachability constraint

A ciphertext-only relay is distinct from a tunnel that makes an Owner phone reachable. The phone's carrier may block inbound connections behind CGNAT, and Android does not guarantee background process uptime. A no-cost gateway/tunnel or direct routable carrier path is not yet configured; do not describe the phone as publicly reachable. No paid hosting has been selected or authorized.
