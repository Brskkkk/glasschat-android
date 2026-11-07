# Supabase identity and encrypted relay

## Source wiring

Both Owner and Client app entry points use the shared `GlassChatSecureRuntime` in the Compose messenger. It accepts an HTTPS Supabase project URL and public anon key entered in the app; no project credentials are checked into source. The configuration, Supabase Auth session/refresh tokens, account/device metadata, peer mappings and Signal private state are stored through the local sealed store. A saved login is bound to its project URL and is not sent to a different configured project.

The UI source includes Supabase Auth sign-up/sign-in, current GlassChat account lookup, invitation redemption, device registration and public Signal prekey publication. Owner-only invitation creation requires an already provisioned active Owner account. The migration intentionally does not silently make the first registrant an Owner: a trusted project operator must provision the initial Owner. Signup may require email confirmation under Supabase policy.

The UI supports each side recording contact consent, loading the mutual-consent device directory, comparing the complete Signal identity fingerprint out of band, and explicitly entering that fingerprint before it fetches the peer bundle and establishes a pinned Signal session for a selected local conversation. A matching fingerprint is a human out-of-band check, not a claim that the contact has been independently authenticated by this app.

A selected conversation gets encrypted send/receive controls only when the runtime has a verified peer mapping for that conversation. Sending uses Signal and writes an encrypted envelope to the local outbox before trying authenticated relay RPC. A relay response must match the delivery ID before the local state is marked relay-accepted. A failure leaves the encrypted copy queued locally. Receive uses the locally stored peer mapping, decrypts and durably stores the message before sending its relay acknowledgment. The shared UI has no plaintext network fallback: with no verified session, it only saves locally and labels the message as not delivered.

Status distinction matters:

- `local_only`: saved on this device, not sent.
- `encrypted_queued_not_delivered`: Signal ciphertext is saved locally; relay acceptance is not confirmed.
- `relay_accepted_recipient_not_confirmed`: relay accepted ciphertext; recipient receipt is not confirmed.
- `received_encrypted_local`: decrypted message was saved on this device before relay acknowledgment.

Once a verified peer session is configured, the shared UI schedules a connected-network immediate sync and unique 15-minute periodic WorkManager sync in both APKs. It retries queued ciphertext and polls for inbound ciphertext, decrypting and persisting before acknowledgment. Android may defer or stop this work; it is not real-time push, FCM, or an always-on Owner relay, and it does not currently show incoming-message notifications. The Owner foreground service remains a local lifecycle shell, not the relay server.

## Migrations and deployment boundary

`supabase/migrations/0001_glasschat_auth_metadata.sql` defines account/device metadata and Owner-managed invitation functions. `0002_signal_one_time_prekeys.sql` adds public one-time-prekey publication. `0003_contact_keys_and_ciphertext_relay.sql` adds mutual-consent state, consent-gated Signal bundle retrieval with atomic one-time-prekey consumption, and per-device ciphertext submit/fetch/ack/expiry RPCs. `0004_contact_device_directory.sql` adds mutual-consent device discovery.

These migrations are source only. They have not been applied, audited against a deployed database, or exercised. Review the `SECURITY DEFINER` functions and policies before applying them to the owner's Supabase project. The authenticated Android client must use only the project's public anon key and user's access token; never put a service-role key in an APK.

Ciphertext relay is not a plaintext archive: it accepts bounded Signal envelope bytes plus delivery/device routing metadata, idempotently rejects a reused delivery ID with different content, and clears the payload after recipient acknowledgment. Submit limits expiry to seven days; fetch removes expired rows, and an explicit expiry RPC is available. No scheduled expiry job is configured. Relay acknowledgments indicate recipient durable storage only when the recipient's app performs the authenticated decrypt/store-then-ack path; server acceptance alone is not delivery confirmation.

## Remaining verification and configuration

No Supabase project URL or anon key was provided, the migrations are undeployed, and no live service has been contacted. Therefore these source paths do not yet constitute working live messaging. A trusted operator must review/apply migrations and provision the first Owner; then both apps need the public project URL/key and the account/device/contact setup described above. No app build, tests, CI or APK was run or produced in this work, in accordance with the instruction to keep those paused. End-to-end interoperability, live relay behavior and protocol security remain unverified.

A ciphertext relay does not make the Owner phone reachable behind carrier NAT or guarantee Android background uptime. No tunnel, public endpoint, paid hosting or continuous service arrangement is configured.
