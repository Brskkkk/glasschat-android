-- GlassChat account/metadata groundwork. No message bodies or relay ciphertext are stored here.
-- Apply with the Supabase SQL editor/migration runner after reviewing SECURITY DEFINER routines.
create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

create table if not exists public.gc_accounts (
    id uuid primary key default gen_random_uuid(),
    auth_user_id uuid not null unique references auth.users(id) on delete cascade,
    username text not null unique check (username ~ '^[a-z0-9_]{3,32}$'),
    display_name text not null check (char_length(display_name) between 1 and 80),
    role text not null default 'client' check (role in ('owner', 'client')),
    status text not null default 'active' check (status in ('active', 'suspended')),
    created_at timestamptz not null default now()
);

create table if not exists public.gc_devices (
    id uuid primary key default gen_random_uuid(),
    account_id uuid not null references public.gc_accounts(id) on delete cascade,
    signal_device_id smallint not null check (signal_device_id between 1 and 127),
    registration_id integer not null check (registration_id between 1 and 16380),
    public_identity_key bytea not null check (octet_length(public_identity_key) between 32 and 512),
    fcm_token text,
    status text not null default 'active' check (status in ('active', 'revoked')),
    created_at timestamptz not null default now(),
    last_authenticated_at timestamptz,
    unique (account_id, signal_device_id),
    unique (id, account_id)
);

-- Public protocol material only. Private identity/prekey material must stay on the device.
-- Clients can read/write only their own row through RLS; there is no cross-account read policy.
-- Cross-account reads stay blocked until a contact-authorized bundle endpoint performs active-contact/device checks.
create table if not exists public.gc_signal_public_prekeys (
    account_id uuid not null,
    device_id uuid not null,
    signed_prekey_id integer not null check (signed_prekey_id >= 0),
    signed_prekey_public bytea not null check (octet_length(signed_prekey_public) between 32 and 512),
    signed_prekey_signature bytea not null check (octet_length(signed_prekey_signature) between 32 and 1024),
    kyber_prekey_id integer,
    kyber_prekey_public bytea,
    kyber_prekey_signature bytea,
    updated_at timestamptz not null default now(),
    primary key (device_id),
    foreign key (device_id, account_id) references public.gc_devices(id, account_id) on delete cascade,
    check ((kyber_prekey_id is null and kyber_prekey_public is null and kyber_prekey_signature is null)
        or (kyber_prekey_id is not null and kyber_prekey_id >= 0
            and kyber_prekey_public is not null and octet_length(kyber_prekey_public) between 32 and 4096
            and kyber_prekey_signature is not null and octet_length(kyber_prekey_signature) between 32 and 4096))
);

create table if not exists public.gc_invitations (
    code_sha256 text primary key check (code_sha256 ~ '^[0-9a-f]{64}$'),
    created_by_account_id uuid not null references public.gc_accounts(id),
    created_at timestamptz not null default now(),
    expires_at timestamptz not null,
    revoked_at timestamptz,
    redeemed_at timestamptz,
    redeemed_account_id uuid references public.gc_accounts(id),
    check (expires_at > created_at),
    check (not (revoked_at is not null and redeemed_at is not null))
);

create index if not exists gc_devices_account_status_idx on public.gc_devices(account_id, status);
create index if not exists gc_invitation_expiry_idx on public.gc_invitations(expires_at);

alter table public.gc_accounts enable row level security;
alter table public.gc_devices enable row level security;
alter table public.gc_signal_public_prekeys enable row level security;
alter table public.gc_invitations enable row level security;

revoke all on public.gc_accounts, public.gc_devices, public.gc_signal_public_prekeys, public.gc_invitations from anon, authenticated;
grant select on public.gc_accounts to authenticated;
grant select, insert, update, delete on public.gc_devices to authenticated;
grant select, insert, update, delete on public.gc_signal_public_prekeys to authenticated;

create policy gc_accounts_select_self on public.gc_accounts
    for select to authenticated using (auth_user_id = (select auth.uid()));

create policy gc_devices_select_self on public.gc_devices
    for select to authenticated using (exists (
        select 1 from public.gc_accounts a where a.id = account_id and a.auth_user_id = (select auth.uid())
    ));
create policy gc_devices_insert_self on public.gc_devices
    for insert to authenticated with check (exists (
        select 1 from public.gc_accounts a where a.id = account_id and a.auth_user_id = (select auth.uid()) and a.status = 'active'
    ));
create policy gc_devices_update_self on public.gc_devices
    for update to authenticated using (exists (
        select 1 from public.gc_accounts a where a.id = account_id and a.auth_user_id = (select auth.uid())
    )) with check (exists (
        select 1 from public.gc_accounts a where a.id = account_id and a.auth_user_id = (select auth.uid())
    ));
create policy gc_devices_delete_self on public.gc_devices
    for delete to authenticated using (exists (
        select 1 from public.gc_accounts a where a.id = account_id and a.auth_user_id = (select auth.uid())
    ));

create policy gc_prekeys_write_self on public.gc_signal_public_prekeys
    for all to authenticated using (exists (
        select 1 from public.gc_accounts a where a.id = account_id and a.auth_user_id = (select auth.uid())
    )) with check (exists (
        select 1 from public.gc_accounts a where a.id = account_id and a.auth_user_id = (select auth.uid())
    ));

-- Invitation digest is calculated in Postgres; the one-time raw token is returned only to the
-- authenticated Owner caller and is never persisted. Service-role credentials are not needed
-- in either APK. An initial owner account must be provisioned by a trusted operator.
create or replace function public.gc_create_invitation(p_expires_at timestamptz)
returns text
language plpgsql
security definer
set search_path = public, extensions, pg_temp
as $$
declare
    v_account_id uuid;
    v_code text;
begin
    select id into v_account_id from public.gc_accounts
      where auth_user_id = auth.uid() and role = 'owner' and status = 'active';
    if v_account_id is null then raise exception 'owner authorization required' using errcode = '42501'; end if;
    if p_expires_at <= now() or p_expires_at > now() + interval '30 days' then
        raise exception 'invitation expiry must be within 30 days';
    end if;
    v_code := rtrim(translate(encode(gen_random_bytes(32), 'base64'), '+/', '-_'), '=');
    insert into public.gc_invitations(code_sha256, created_by_account_id, expires_at)
      values (encode(digest(convert_to(v_code, 'UTF8'), 'sha256'), 'hex'), v_account_id, p_expires_at);
    return v_code;
end;
$$;

create or replace function public.gc_redeem_invitation(
    p_code text,
    p_username text,
    p_display_name text
)
returns uuid
language plpgsql
security definer
set search_path = public, extensions, pg_temp
as $$
declare
    v_invitation public.gc_invitations%rowtype;
    v_account_id uuid;
    v_digest text;
begin
    if auth.uid() is null then raise exception 'authenticated session required' using errcode = '42501'; end if;
    if p_code !~ '^[A-Za-z0-9_-]{40,64}$' then raise exception 'invalid invitation code'; end if;
    if coalesce(p_username, '') !~ '^[a-z0-9_]{3,32}$'
       or char_length(trim(coalesce(p_display_name, ''))) not between 1 and 80 then
        raise exception 'invalid profile fields';
    end if;
    if exists (select 1 from public.gc_accounts where auth_user_id = auth.uid()) then
        raise exception 'authenticated user already has an account';
    end if;
    v_digest := encode(digest(convert_to(p_code, 'UTF8'), 'sha256'), 'hex');
    select * into v_invitation from public.gc_invitations
      where code_sha256 = v_digest and revoked_at is null and redeemed_at is null and expires_at > now()
      for update;
    if not found then raise exception 'invitation invalid, expired, revoked, or already used'; end if;
    insert into public.gc_accounts(auth_user_id, username, display_name, role, status)
      values (auth.uid(), p_username, trim(p_display_name), 'client', 'active')
      returning id into v_account_id;
    update public.gc_invitations set redeemed_at = now(), redeemed_account_id = v_account_id
      where code_sha256 = v_digest;
    return v_account_id;
end;
$$;

revoke all on function public.gc_create_invitation(timestamptz) from public, anon;
revoke all on function public.gc_redeem_invitation(text, text, text) from public, anon;
grant execute on function public.gc_create_invitation(timestamptz) to authenticated;
grant execute on function public.gc_redeem_invitation(text, text, text) to authenticated;

comment on table public.gc_accounts is 'GlassChat account metadata linked to Supabase Auth; never message bodies.';
comment on table public.gc_devices is 'Device metadata and public identity keys only; no private keys.';
comment on table public.gc_signal_public_prekeys is 'Signal public signed/Kyber prekey material; cross-account reads remain blocked pending a contact-checked bundle API.';
comment on table public.gc_invitations is 'Only SHA-256 digests of one-time invitation codes; no message payloads.';
