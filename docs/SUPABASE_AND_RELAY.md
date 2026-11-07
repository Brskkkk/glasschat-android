# Supabase identity metadata and encrypted relay boundary

## What is in source

`supabase/migrations/0001_glasschat_auth_metadata.sql` is schema/RLS groundwork for a Supabase project. It links a random permanent GlassChat UUID to `auth.users`, stores account/device metadata and public Signal identity/signed-prekey material, and keeps a digest rather than the one-time invite code. Invitation creation is owner-role-gated; redemption binds the currently authenticated Supabase Auth user and consumes the invite in a transaction. A trusted operator still has to bootstrap the first Owner account. These SQL routines have not been applied to a Supabase project or reviewed/exercised against a live instance.

There is deliberately no GlassChat message table, conversation archive, plaintext content, or relay queue in Supabase. Supabase Auth/Postgres provide authentication and metadata only; they are not the E2EE protocol. Private device keys and session state belong on the device. The SQL migration stores public key material only. Direct reads of other people's prekeys are not exposed; the contact-authorized prekey retrieval path still needs server/API implementation.

No Supabase project URL, public client key, or credentials were supplied, so neither Auth nor database calls are wired into either APK. Production/service-role secrets must never be placed in Android source. A future client can use only the project's public anon key and an authenticated session; privileged operations belong behind server-side authorization. No paid hosting or deployment has been selected.

## Relay contract (not yet running)

The Owner-side queue already stores one opaque encrypted delivery copy per recipient device, leaves it queued on fetch, acknowledges only the matching recipient device, and enforces a seven-day maximum expiry. That is local persistence logic, not a network relay. `SignalMessagePipeline` now encrypts text through an established pinned Signal session before storing a versioned ciphertext envelope and includes a receive helper that checks authenticated device mappings, rejects expired copies, decrypts and stores locally. This helper is not wired to the app or network; it is not yet connected to an authenticated API or a recipient's durable-store acknowledgment. Its session ratchet update and local message write are not one transaction, so the transport must not acknowledge until durable message storage succeeds and must handle replay/retry safely.

The network API still needs implementation with these boundaries:

- Derive sender account/device only from a verified Supabase Auth token plus an active device binding; never trust sender IDs from the request body.
- Authorize recipient and device using active account/device state and an accepted contact relationship.
- Accept only a bounded opaque Signal envelope for the selected recipient device. Do not decode, log, preview, or persist plaintext.
- Keep queued ciphertext in temporary relay storage, separate from Supabase's account database. Delete a device copy only after that device reports successful local durable storage; FCM acceptance is not delivery acknowledgment.
- Use HTTPS and authenticated WebSockets where appropriate; no server credentials in APKs. Keep FCM payloads generic and non-content-bearing.
- Retain undelivered envelopes for at most seven days, then expire them and expose a delivery failure state.

The Owner foreground service remains a lifecycle/notification shell; it does not host these endpoints or provide network recovery yet. A free, reachable phone route/tunnel is not configured. Carrier NAT, power management and Android process/force-stop limits can prevent public reachability and continuous service; do not advertise the Owner phone as an always-on public server. No paid relay or VPS has been chosen.
