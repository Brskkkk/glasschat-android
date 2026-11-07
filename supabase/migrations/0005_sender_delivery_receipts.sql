-- Sender-visible, per-device durable-storage receipts for the temporary ciphertext relay.
-- This stores delivery metadata only (never message text or ciphertext). Apply only after
-- reviewing SECURITY DEFINER routines and the retention policy.

create table if not exists public.gc_delivery_receipts (
    delivery_id uuid primary key,
    sender_device_id uuid not null references public.gc_devices(id) on delete cascade,
    recipient_device_id uuid not null references public.gc_devices(id) on delete cascade,
    status text not null check (status in ('acknowledged', 'expired')),
    recorded_at timestamptz not null default now(),
    expires_at timestamptz not null
);
create index if not exists gc_delivery_receipts_sender_time_idx
    on public.gc_delivery_receipts(sender_device_id, recorded_at desc);
alter table public.gc_delivery_receipts enable row level security;
revoke all on public.gc_delivery_receipts from anon, authenticated;

-- A fetch or status refresh performs expiry cleanup, preserving a short metadata-only tombstone
-- so the sender can distinguish recipient storage from expiration. Tombstones are purged after
-- 30 days; no scheduler/pg_cron extension is required or assumed.
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

    insert into public.gc_delivery_receipts(delivery_id, sender_device_id, recipient_device_id, status, recorded_at, expires_at)
      select q.delivery_id, q.sender_device_id, q.recipient_device_id, 'expired', now(), q.expires_at
      from public.gc_ciphertext_deliveries q
      where q.acknowledged_at is null and q.expires_at <= now()
      on conflict (delivery_id) do update
        set status = 'expired', recorded_at = excluded.recorded_at, expires_at = excluded.expires_at
        where public.gc_delivery_receipts.status <> 'acknowledged';

    delete from public.gc_ciphertext_deliveries where expires_at <= now();
    get diagnostics v_deleted = row_count;
    delete from public.gc_delivery_receipts where recorded_at <= now() - interval '30 days';
    return v_deleted;
end;
$$;

-- Expire stale payloads before reading. The authenticated recipient can still retrieve only its
-- own active device's unacknowledged ciphertext.
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
    perform public.gc_expire_ciphertext();
    return query select q.delivery_id, q.sender_device_id, q.recipient_device_id, q.ciphertext, q.expires_at
      from public.gc_ciphertext_deliveries q
      where q.recipient_device_id = p_recipient_device_id and q.acknowledged_at is null and q.expires_at > now()
      order by q.created_at, q.delivery_id limit p_limit;
end;
$$;

-- Only the authenticated recipient device may acknowledge, after the client has durably saved the
-- decrypted message. Record per-device delivery confirmation for the authenticated sender.
create or replace function public.gc_ack_ciphertext(p_delivery_id uuid, p_recipient_device_id uuid)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_account_id uuid;
    v_sender_device_id uuid;
    v_expiry timestamptz;
begin
    if auth.uid() is null then raise exception 'authenticated session required' using errcode = '42501'; end if;
    select d.account_id into v_account_id from public.gc_devices d join public.gc_accounts a on a.id = d.account_id
      where d.id = p_recipient_device_id and d.status = 'active' and a.status = 'active' and a.auth_user_id = auth.uid();
    if v_account_id is null then raise exception 'active recipient device required' using errcode = '42501'; end if;
    perform public.gc_expire_ciphertext();

    select q.sender_device_id, q.expires_at into v_sender_device_id, v_expiry
      from public.gc_ciphertext_deliveries q
      where q.delivery_id = p_delivery_id and q.recipient_device_id = p_recipient_device_id
        and q.acknowledged_at is null and q.expires_at > now()
      for update;
    if found then
        update public.gc_ciphertext_deliveries q
          set ciphertext = null, acknowledged_at = coalesce(q.acknowledged_at, now())
          where q.delivery_id = p_delivery_id and q.recipient_device_id = p_recipient_device_id;
        insert into public.gc_delivery_receipts(delivery_id, sender_device_id, recipient_device_id, status, recorded_at, expires_at)
          values (p_delivery_id, v_sender_device_id, p_recipient_device_id, 'acknowledged', now(), v_expiry)
          on conflict (delivery_id) do update set status = 'acknowledged', recorded_at = excluded.recorded_at,
            expires_at = excluded.expires_at;
        return true;
    end if;
    return exists (
      select 1 from public.gc_delivery_receipts r where r.delivery_id = p_delivery_id
        and r.recipient_device_id = p_recipient_device_id and r.status = 'acknowledged'
    );
end;
$$;

-- The sender may ask about at most 100 IDs belonging to its authenticated active device.
-- Results contain metadata only and never reveal ciphertext or another sender's delivery state.
create or replace function public.gc_fetch_delivery_status(p_sender_device_id uuid, p_delivery_ids uuid[])
returns table(delivery_id uuid, recipient_device_id uuid, status text, recorded_at timestamptz)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_account_id uuid;
begin
    if auth.uid() is null then raise exception 'authenticated session required' using errcode = '42501'; end if;
    if p_delivery_ids is null or cardinality(p_delivery_ids) not between 1 and 100 then
      raise exception 'delivery status batch must contain 1 to 100 IDs';
    end if;
    select d.account_id into v_account_id from public.gc_devices d join public.gc_accounts a on a.id = d.account_id
      where d.id = p_sender_device_id and d.status = 'active' and a.status = 'active' and a.auth_user_id = auth.uid();
    if v_account_id is null then raise exception 'active sender device required' using errcode = '42501'; end if;
    perform public.gc_expire_ciphertext();

    return query
      select r.delivery_id, r.recipient_device_id, r.status, r.recorded_at
      from public.gc_delivery_receipts r
      where r.sender_device_id = p_sender_device_id and r.delivery_id = any(p_delivery_ids)
      union all
      select q.delivery_id, q.recipient_device_id, 'pending'::text, q.created_at
      from public.gc_ciphertext_deliveries q
      where q.sender_device_id = p_sender_device_id and q.delivery_id = any(p_delivery_ids)
        and q.acknowledged_at is null and q.expires_at > now()
      order by delivery_id;
end;
$$;

revoke all on function public.gc_fetch_delivery_status(uuid, uuid[]) from public, anon;
grant execute on function public.gc_fetch_delivery_status(uuid, uuid[]) to authenticated;
comment on table public.gc_delivery_receipts is 'Metadata-only per-device ciphertext delivery receipts retained for at most 30 days; no message payload.';
comment on function public.gc_fetch_delivery_status(uuid, uuid[]) is 'Returns only the authenticated sender device’s pending, durably acknowledged, or expired delivery metadata for supplied IDs.';
