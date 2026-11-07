# GlassChat implementation and deployment status

Status reflects source inspected during the current implementation pass. The code has not been built or tested in this pass. The feature list below is a scope checklist, not a claim of completion.

## Owner and Client requirements

| Area | Current state |
|---|---|
| Independent Owner and Client packages | Gradle modules and distinct application IDs are present in source; not build-verified. |
| Local conversation/contact/message UI | Local creation, message save/search, local-only message edit/delete, a local reaction, local bookmarks, autosaved conversation drafts, and pin/archive/mute controls exist in source. These are local-device changes only and do not sync. No remote contact lookup or transmission. |
| Local data protection | Payload JSON is AES-GCM encrypted at rest under a Keystore key. SQLite routing/index metadata is visible. Not SQLCipher and not E2EE. No recovery/backup/migration UI. |
| Ciphertext delivery storage primitives | Per-recipient-device queue storage, no-delete-on-fetch, device-matched ack and max seven-day expiry methods exist in source. No HTTP/API integration, caller authentication, real client-side durable commit, notification, or actual relay service. |
| Owner foreground service | Start/Pause/Resume/Stop lifecycle and notification shell exist. It does not host an API, account registry or relay; its status intentionally says those are unavailable. Boot/autostart/network monitoring, proper restart recovery and real service health are absent. |
| E2EE | Not implemented. No custom encryption is presented as E2EE. Integrate a maintained protocol library, with device identity, prekeys, sessions, ratchet and key rotation, before any message can be described as private end-to-end. |
| Identity/auth/invitations/accounts/devices | Local-only primitives exist for one-time invitation digest storage/redemption into UUID client accounts, status changes, device public-key/FCM-token records and local device revocation. These are not exposed as a complete registration UI, do not authenticate a caller, do not publish remotely, and do not enforce remote access. No production authentication/session/recovery flow or owner bootstrap is implemented. |
| Contact requests, groups, media, attachments, remote reactions/edits, read/delivery receipts, profile, notifications and theme Studio | Not implemented beyond local conversation/message save/search/edit/bookmark controls. Local drafts and pin/archive/mute flags are not synchronized. |
| Admin dashboard, roles, owner badge, account/device actions, nickname events, audit log, backups, server settings | Not implemented. |
| FCM | Not configured or implemented. No Firebase project config or service credentials supplied. |
| Android build/release | No APK, no signing key. Build and tests intentionally deferred by Jr until full feature implementation is complete. Previous Gradle attempts did not complete successfully. |

## Reachability: Owner phone with no paid hosting

The separate ciphertext relay in the supplied design is not a reachability tunnel. A tunnel routes a network connection to a local listener; it does not implement authenticated accounts, ciphertext queueing, recipient-device acknowledgements, expiry, or message security.

Direct public connections to an Owner phone require a publicly routable address and permitted inbound traffic. A public IPv4 behind the carrier's CGNAT cannot accept ordinary unsolicited inbound connections; a router port-forward only helps when the internet connection really has a reachable address. A carrier-provided globally routed IPv6 could allow direct inbound routing where both networks support it and firewall rules permit it, but the address may be dynamic and endpoint discovery plus TLS/authentication still need implementation. The app has no way to assume which service the owner's carrier provides.

Two no-cost tunnel directions were checked against their current provider docs:

- Tailscale Funnel is listed as available on all Tailscale plans, but requires Funnel enabled in a tailnet, MagicDNS/HTTPS certificates and its CLI. Tailscale's CLI documentation explicitly says there is no CLI support for Android/iOS. Therefore it is not a supported, in-app Owner-phone deployment path as presently designed. It is also a provider-operated public TCP proxy, separate from GlassChat's encrypted message relay.
- Cloudflare Tunnel requires running the `cloudflared` daemon on the origin and mapping a public hostname. The project has no Android integration, Cloudflare account/hostname configuration, or tunnel credentials. It is an external reachability proxy, not the GlassChat message relay. Do not describe an ephemeral quick tunnel as durable production hosting.

Sources:
- https://tailscale.com/docs/features/tailscale-funnel
- https://tailscale.com/docs/reference/tailscale-cli
- https://developers.cloudflare.com/tunnel/

No route has been provisioned or tested. No paid service has been selected or configured. Do not promise always-on public availability: carrier ingress, Android background execution, force-stop, battery management, dynamic addressing and service outages remain relevant even if a route is later obtained.

## External dependencies / missing setup

- Owner-phone inbound connectivity: actual carrier/network capabilities and available IPv4/IPv6/port forwarding have not been established.
- Any tunnel provider route would require a compatible service client and owner-controlled provider setup; Tailscale Funnel is not officially CLI-supported on Android.
- FCM needs an owner-supplied Firebase project/app registration and credentials. Do not create or commit secrets.
- Authentication and a Signal-compatible protocol implementation need deliberate library/version integration and verification; no bespoke cryptographic substitute is acceptable.
- No domain, public IP, tunnel credentials, FCM credentials, production signing keys or server identity data have been supplied.

## Deferred validation

Do not build/test/package or trigger CI until all requested implementation work is complete, per Jr's explicit instruction. The earlier failure remains the only actual build evidence: offline AndroidX/Guava dependencies blocked `:app-owner:mergeDebugGlobalSynthetics`; no APK was produced. The online attempt ended before compilation completed. No tests have run on the current source changes.
