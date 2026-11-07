# Supabase identity metadata and encrypted relay boundary

## What is in source

`supabase/migrations/0001_glasschat_auth_metadata.sql` is schema/RLS groundwork for a Supabase project. It links a random permanent GlassChat UUID to `auth.users`, stores account/device metadata and public Signal identity/signed-prekey material, and keeps a digest rather than the one-time invite code. Invitation creation is owner-role-gated; redemption binds the currently authenticated Supabase Auth user and consumes the invite in a transaction. A trusted operator still has to bootstrap the first Owner account. These SQL routines have not been applied to a Supabase project or exercised against a live instance.

`0002_signal_one_time_prekeys.sql` and `0003_contact_keys_and_ciphertext_relay.sql` add source-only groundwork for owner-published public one-time prekeys, bilateral contact consent, contact-gated Signal bundle retrieval with atomic one-time-key consumption, and authenticated ciphertext submit/fetch/ack/expiry RPCs. Relay rows contain only bounded opaque Signal ciphertext, its SHA-256 idempotency digest, and device-routing metadata; the ack function clears the ciphertext payload after recipient acknowledgment. No plaintext conversation table/archive or private device key is stored in Supabase. The functions have not been applied or tested against a live Supabase instance; they are contracts, not a deployed service.

No Supabase project URL or public client key was supplied, so Auth and RPC calls are not wired into either APK and the migrations are not deployed. Production/service-role secrets must never be placed in Android source. A future client can use only the project's public anon key and an authenticated session; the RPCs derive the account from `auth.uid()` and validate active device/contact bindings. No paid hosting or deployment has been selected.

## Relay contract (not yet running)

The local ciphertext queue still stores one opaque encrypted delivery copy per recipient device, leaves it queued on fetch, acknowledges only the matching recipient device, and enforces a seven-day maximum expiry; it is not a network relay. `SignalMessagePipeline` encrypts only through an established pinned Signal session, queues a bounded ciphertext envelope, and has a receive helper that validates caller-supplied authenticated device mappings, rejects expired copies, decrypts and stores locally. Both outbound ratchet advancement plus local queue insertion, and inbound ratchet advancement plus encrypted message insertion, now share one SQLite transaction. This source-only pipeline is still not wired to the app or to a network API. A recipient may acknowledge only after local durable storage returns successfully.

The network API still needs implementation with these boundaries:

- Derive sender account/device only from a verified Supabase Auth token plus an active device binding; never trust sender IDs from the request body.
- Authorize recipient and device using active account/device state and an accepted contact relationship.
- Accept only a bounded opaque Signal envelope for the selected recipient device. Do not decode, log, preview, or persist plaintext.
- Keep queued ciphertext in temporary relay storage, separate from Supabase's account database. Delete a device copy only after that device reports successful local durable storage; FCM acceptance is not delivery acknowledgment.
- Use HTTPS and authenticated WebSockets where appropriate; no server credentials in APKs. Keep FCM payloads generic and non-content-bearing.
- Retain undelivered envelopes for at most seven days, then expire them and expose a delivery failure state.

The Owner foreground service remains a lifecycle/notification shell; it does not host these endpoints or provide network recovery yet. A free, reachable phone route/tunnel is not configured. Carrier NAT, power management and Android process/force-stop limits can prevent public reachability and continuous service; do not advertise the Owner phone as an always-on public server. No paid relay or VPS has been chosen. The Supabase RPC migration provides a backend route only after an operator deploys and configures a project; no such configuration or deployment is present.
