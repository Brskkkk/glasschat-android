-- Authenticated contact-authorized Signal bundle retrieval and temporary ciphertext relay.
-- Apply only after reviewing SECURITY DEFINER routines. No plaintext or private key is stored.

create table if not exists public.gc_contact_consents (
    account_id uuid not null references public.gc_accounts(id) on delete cascade,
    contact_account_id uuid not null references public.gc_accounts(id) on delete cascade,
    accepted boolean not null default false,
    updated_at timestamptz not null default now(),
    primary key (account_id, contact_account_id),
    check (account_id <> contact_account_id)
);

alter table public.gc_contact_consents enable row level security;
revoke all on public.gc_contact_consents from anon, authenticated;
grant select, insert, update, delete on public.gc_contact_consents to authenticated;
create policy gc_contact_consents_self on public.gc_contact_consents
    for all to authenticated using (
        exists (select 1 from public.gc_accounts a where a.id = account_id and a.auth_user_id = (select auth.uid()))
    ) with check (
        exists (select 1 from public.gc_accounts a where a.id = account_id and a.auth_user_id = (select auth.uid()))
    );

create table if not exists public.gc_ciphertext_deliveries (
    delivery_id uuid primary key,
    sender_device_id uuid not null references public.gc_devices(id) on delete cascade,
    recipient_device_id uuid not null references public.gc_devices(id) on delete cascade,
    ciphertext bytea check (ciphertext is null or octet_length(ciphertext) between 1 and 1048586),
    ciphertext_sha256 bytea not null check (octet_length(ciphertext_sha256) = 32),
    created_at timestamptz not null default now(),
    expires_at timestamptz not null,
    acknowledged_at timestamptz,
    check (expires_at > created_at),
    check ((acknowledged_at is null and ciphertext is not null) or (acknowledged_at is not null and ciphertext is null))
);
create index if not exists gc_ciphertext_pending_device_expiry_idx
    on public.gc_ciphertext_deliveries(recipient_device_id, expires_at)
    where acknowledged_at is null;
alter table public.gc_ciphertext_deliveries enable row level security;
revoke all on public.gc_ciphertext_deliveries from anon, authenticated;

-- Each user may only record their own side of a contact approval. Secure functions below
-- require both sides to have accepted before exposing keys or routing ciphertext.
create or replace function public.gc_submit_ciphertext(
    p_delivery_id uuid,
    p_sender_device_id uuid,
    p_recipient_device_id uuid,
    p_ciphertext bytea,
    p_expires_at timestamptz
)
returns uuid
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_sender_account uuid;
    v_recipient_account uuid;
    v_existing public.gc_ciphertext_deliveries%rowtype;
begin
    if auth.uid() is null then raise exception 'authenticated session required' using errcode = '42501'; end if;
    if p_ciphertext is null or octet_length(p_ciphertext) not between 1 and 1048586 then
        raise exception 'ciphertext size is invalid';
    end if;
    if p_expires_at <= now() or p_expires_at > now() + interval '7 days' then
        raise exception 'ciphertext expiry must be within seven days';
    end if;
    select d.account_id into v_sender_account
      from public.gc_devices d join public.gc_accounts a on a.id = d.account_id
      where d.id = p_sender_device_id and d.status = 'active' and a.status = 'active' and a.auth_user_id = auth.uid();
    if v_sender_account is null then raise exception 'active sender device required' using errcode = '42501'; end if;
    select d.account_id into v_recipient_account
      from public.gc_devices d join public.gc_accounts a on a.id = d.account_id
      where d.id = p_recipient_device_id and d.status = 'active' and a.status = 'active';
    if v_recipient_account is null or v_recipient_account = v_sender_account then raise exception 'active recipient device required'; end if;
    if not exists (
        select 1 from public.gc_contact_consents x join public.gc_contact_consents y
          on y.account_id = x.contact_account_id and y.contact_account_id = x.account_id
        where x.account_id = v_sender_account and x.contact_account_id = v_recipient_account
          and x.accepted and y.accepted
    ) then raise exception 'mutually accepted contact required' using errcode = '42501'; end if;

    insert into public.gc_ciphertext_deliveries(delivery_id, sender_device_id, recipient_device_id, ciphertext, ciphertext_sha256, expires_at)
      values (p_delivery_id, p_sender_device_id, p_recipient_device_id, p_ciphertext, extensions.digest(p_ciphertext, 'sha256'), p_expires_at)
      on conflict (delivery_id) do nothing;
    if found then return p_delivery_id; end if;
    select * into v_existing from public.gc_ciphertext_deliveries where delivery_id = p_delivery_id for update;
    if v_existing.sender_device_id = p_sender_device_id
       and v_existing.recipient_device_id = p_recipient_device_id
       and v_existing.ciphertext_sha256 = extensions.digest(p_ciphertext, 'sha256')
       and v_existing.expires_at = p_expires_at then return p_delivery_id; end if;
    raise exception 'delivery ID was already used for different content';
end;
$$;

create or replace function public.gc_fetch_ciphertext(p_recipient_device_id uuid, p_limit integer default 100)
returns table(delivery_id uuid, sender_device_id uuid, recipient_device_id uuid, ciphertext bytea, expires_at timestamptz)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_account_id uuid;
begin
    if auth.uid() is null then raise exception 'authenticated session required' using errcode = '42501'; end if;
    if p_limit not between 1 and 100 then raise exception 'fetch limit must be between 1 and 100'; end if;
    select d.account_id into v_account_id from public.gc_devices d join public.gc_accounts a on a.id = d.account_id
      where d.id = p_recipient_device_id and d.status = 'active' and a.status = 'active' and a.auth_user_id = auth.uid();
    if v_account_id is null then raise exception 'active recipient device required' using errcode = '42501'; end if;
    delete from public.gc_ciphertext_deliveries where gc_ciphertext_deliveries.expires_at <= now();
    return query select q.delivery_id, q.sender_device_id, q.recipient_device_id, q.ciphertext, q.expires_at
      from public.gc_ciphertext_deliveries q
      where q.recipient_device_id = p_recipient_device_id and q.acknowledged_at is null and q.expires_at > now()
      order by q.created_at, q.delivery_id limit p_limit;
end;
$$;

create or replace function public.gc_expire_ciphertext()
returns integer
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_deleted integer;
begin
    if auth.uid() is null then raise exception 'authenticated session required' using errcode = '42501'; end if;
    delete from public.gc_ciphertext_deliveries where expires_at <= now();
    get diagnostics v_deleted = row_count;
    return v_deleted;
end;
$$;

create or replace function public.gc_ack_ciphertext(p_delivery_id uuid, p_recipient_device_id uuid)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_account_id uuid;
    v_acknowledged boolean;
begin
    if auth.uid() is null then raise exception 'authenticated session required' using errcode = '42501'; end if;
    select d.account_id into v_account_id from public.gc_devices d join public.gc_accounts a on a.id = d.account_id
      where d.id = p_recipient_device_id and d.status = 'active' and a.status = 'active' and a.auth_user_id = auth.uid();
    if v_account_id is null then raise exception 'active recipient device required' using errcode = '42501'; end if;
    update public.gc_ciphertext_deliveries set ciphertext = null, acknowledged_at = coalesce(acknowledged_at, now())
      where delivery_id = p_delivery_id and recipient_device_id = p_recipient_device_id
      returning true into v_acknowledged;
    return coalesce(v_acknowledged, exists (
        select 1 from public.gc_ciphertext_deliveries q where q.delivery_id = p_delivery_id
          and q.recipient_device_id = p_recipient_device_id and q.acknowledged_at is not null
    ));
end;
$$;

-- Atomic, contact-gated one-time-prekey consumption. The caller's auth.uid() is derived
-- from Supabase Auth; one-time keys are removed in the same database transaction that returns them.
create or replace function public.gc_fetch_signal_prekey_bundle(p_peer_device_id uuid)
returns table(
    account_id uuid, device_id uuid, signal_device_id smallint, registration_id integer,
    identity_key bytea, signed_prekey_id integer, signed_prekey_public bytea,
    signed_prekey_signature bytea, kyber_prekey_id integer, kyber_prekey_public bytea,
    kyber_prekey_signature bytea, one_time_prekey_id integer, one_time_prekey_public bytea
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_requester_account uuid;
    v_peer_account uuid;
begin
    if auth.uid() is null then raise exception 'authenticated session required' using errcode = '42501'; end if;
    select a.id into v_requester_account from public.gc_accounts a where a.auth_user_id = auth.uid() and a.status = 'active';
    if v_requester_account is null then raise exception 'active GlassChat account required' using errcode = '42501'; end if;
    select d.account_id into v_peer_account from public.gc_devices d join public.gc_accounts a on a.id = d.account_id
      where d.id = p_peer_device_id and d.status = 'active' and a.status = 'active';
    if v_peer_account is null or v_peer_account = v_requester_account then raise exception 'active peer device required'; end if;
    if not exists (
        select 1 from public.gc_contact_consents x join public.gc_contact_consents y
          on y.account_id = x.contact_account_id and y.contact_account_id = x.account_id
        where x.account_id = v_requester_account and x.contact_account_id = v_peer_account
          and x.accepted and y.accepted
    ) then raise exception 'mutually accepted contact required' using errcode = '42501'; end if;

    return query
      with candidate as (
          select p.prekey_id, p.public_key from public.gc_signal_one_time_prekeys p
          where p.device_id = p_peer_device_id and p.account_id = v_peer_account
          order by p.prekey_id for update skip locked limit 1
      ), consumed as (
          delete from public.gc_signal_one_time_prekeys p using candidate c
          where p.device_id = p_peer_device_id and p.prekey_id = c.prekey_id
          returning p.prekey_id, p.public_key
      )
      select d.account_id, d.id, d.signal_device_id, d.registration_id, d.public_identity_key,
             s.signed_prekey_id, s.signed_prekey_public, s.signed_prekey_signature,
             s.kyber_prekey_id, s.kyber_prekey_public, s.kyber_prekey_signature,
             c.prekey_id, c.public_key
      from public.gc_devices d join public.gc_signal_public_prekeys s on s.device_id = d.id and s.account_id = d.account_id
      left join consumed c on true
      where d.id = p_peer_device_id and d.account_id = v_peer_account and d.status = 'active';
end;
$$;

revoke all on function public.gc_submit_ciphertext(uuid, uuid, uuid, bytea, timestamptz) from public, anon;
revoke all on function public.gc_fetch_ciphertext(uuid, integer) from public, anon;
revoke all on function public.gc_ack_ciphertext(uuid, uuid) from public, anon;
revoke all on function public.gc_expire_ciphertext() from public, anon;
revoke all on function public.gc_fetch_signal_prekey_bundle(uuid) from public, anon;
grant execute on function public.gc_submit_ciphertext(uuid, uuid, uuid, bytea, timestamptz) to authenticated;
grant execute on function public.gc_fetch_ciphertext(uuid, integer) to authenticated;
grant execute on function public.gc_ack_ciphertext(uuid, uuid) to authenticated;
grant execute on function public.gc_expire_ciphertext() to authenticated;
grant execute on function public.gc_fetch_signal_prekey_bundle(uuid) to authenticated;

comment on table public.gc_ciphertext_deliveries is 'Temporary per-device Signal ciphertext; payload cleared on authenticated durable-recipient acknowledgment or expiry.';
comment on function public.gc_fetch_signal_prekey_bundle(uuid) is 'Requires mutual contact consent; atomically returns and consumes at most one public one-time prekey. No private key material.';
