-- Correct redemption retries: a previously redeemed invite must not report success after
-- its account's membership was later removed. Repeated redemption remains idempotent only while
-- that same membership is still active.
create or replace function public.gc_redeem_group_invite(p_code text)
returns table(group_id uuid, group_name text)
language plpgsql security definer set search_path = public, pg_temp
as $$
declare v_account uuid; v_group uuid; v_invite public.gc_group_invites%rowtype; v_name text;
begin
    if auth.uid() is null then raise exception 'authenticated session required' using errcode = '42501'; end if;
    select id into v_account from public.gc_accounts where auth_user_id = auth.uid() and status = 'active';
    if v_account is null then raise exception 'active GlassChat account required' using errcode = '42501'; end if;
    if p_code is null or p_code !~ '^[0-9a-fA-F]{48}$' then raise exception 'invalid group invitation'; end if;
    select i.group_id into v_group from public.gc_group_invites i
      where i.code_hash = extensions.digest(lower(p_code), 'sha256');
    if v_group is null then raise exception 'group invitation is invalid or expired'; end if;
    perform 1 from public.gc_groups where id = v_group for update;
    select * into v_invite from public.gc_group_invites i
      where i.code_hash = extensions.digest(lower(p_code), 'sha256') for update;
    if not found or v_invite.revoked_at is not null or v_invite.expires_at <= now() then
        raise exception 'group invitation is invalid or expired';
    end if;
    if v_invite.redeemed_by is not null then
        if v_invite.redeemed_by <> v_account or not exists (
            select 1 from public.gc_group_members m
             where m.group_id = v_invite.group_id and m.account_id = v_account
        ) then raise exception 'group invitation has already been used'; end if;
    else
        insert into public.gc_group_members(group_id, account_id, role)
        values (v_invite.group_id, v_account, 'member') on conflict (group_id, account_id) do nothing;
        update public.gc_group_invites set redeemed_by = v_account, redeemed_at = now() where id = v_invite.id;
    end if;
    select g.name into v_name from public.gc_groups g where g.id = v_invite.group_id;
    return query select v_invite.group_id, v_name;
end;
$$;
revoke all on function public.gc_redeem_group_invite(text) from public, anon;
grant execute on function public.gc_redeem_group_invite(text) to authenticated;

-- Atomic per-device ciphertext fan-out for a server-managed group.
-- This avoids exposing a partially accepted group message when one device submission fails.
-- Payloads remain independent pairwise Signal ciphertext; no plaintext/key material is stored.

create or replace function public.gc_submit_group_ciphertext_batch(
    p_group_id uuid,
    p_membership_version bigint,
    p_sender_device_id uuid,
    p_expires_at timestamptz,
    p_copies jsonb
)
returns uuid[]
language plpgsql
security definer
set search_path = public, extensions, pg_temp
as $$
declare
    v_sender_account uuid;
    v_current_version bigint;
    v_copy_count integer;
    v_existing_count integer;
    v_distinct_delivery_count integer;
    v_distinct_recipient_count integer;
    v_total_bytes bigint;
    v_ids uuid[];
begin
    if auth.uid() is null then raise exception 'authenticated session required' using errcode = '42501'; end if;
    if p_group_id is null or p_membership_version is null or p_membership_version < 1
       or p_sender_device_id is null or p_expires_at is null then
        raise exception 'group, membership version, sender device, and expiry are required';
    end if;
    if p_copies is null or jsonb_typeof(p_copies) <> 'array' then
        raise exception 'group ciphertext batch must be a JSON array';
    end if;
    if jsonb_array_length(p_copies) not between 1 and 127 then
        raise exception 'group ciphertext batch must contain 1 to 127 copies';
    end if;
    if p_expires_at <= now() or p_expires_at > now() + interval '7 days' then
        raise exception 'ciphertext expiry must be within seven days';
    end if;

    if exists (
        select 1 from jsonb_to_recordset(p_copies)
          as x(delivery_id uuid, recipient_device_id uuid, ciphertext_hex text)
        where x.delivery_id is null or x.recipient_device_id is null
           or x.ciphertext_hex is null or length(x.ciphertext_hex) < 2
           or length(x.ciphertext_hex) > 2097172 or mod(length(x.ciphertext_hex), 2) <> 0
           or x.ciphertext_hex !~ '^[0-9a-fA-F]+$'
    ) then raise exception 'group ciphertext batch contains malformed copy data'; end if;

    select count(*), count(distinct x.delivery_id), count(distinct x.recipient_device_id),
           coalesce(sum(length(x.ciphertext_hex)::bigint / 2), 0),
           array_agg(x.delivery_id order by x.delivery_id)
      into v_copy_count, v_distinct_delivery_count, v_distinct_recipient_count, v_total_bytes, v_ids
      from jsonb_to_recordset(p_copies)
        as x(delivery_id uuid, recipient_device_id uuid, ciphertext_hex text);
    if v_copy_count <> jsonb_array_length(p_copies)
       or v_distinct_delivery_count <> v_copy_count
       or v_distinct_recipient_count <> v_copy_count then
        raise exception 'group ciphertext batch contains duplicate identifiers';
    end if;
    if v_total_bytes > 8388608 then raise exception 'group ciphertext batch exceeds the 8 MiB limit'; end if;

    -- Serialize the complete batch against all membership changes. A transaction either stores
    -- every required device copy under this roster epoch or none of the new copies.
    select g.membership_version into v_current_version
      from public.gc_groups g where g.id = p_group_id for update;
    if not found then raise exception 'group does not exist'; end if;
    select d.account_id into v_sender_account
      from public.gc_devices d join public.gc_accounts a on a.id = d.account_id
      where d.id = p_sender_device_id and d.status = 'active' and a.status = 'active'
        and a.auth_user_id = auth.uid();
    if v_sender_account is null or not exists (
        select 1 from public.gc_group_members m
        where m.group_id = p_group_id and m.account_id = v_sender_account
    ) then raise exception 'active group sender membership required' using errcode = '42501'; end if;

    -- Exact retry is safe even if the roster changed after the original whole-batch commit.
    -- A mixed/changed ID set is rejected rather than silently widened or partially accepted.
    select count(*) into v_existing_count
      from jsonb_to_recordset(p_copies)
        as x(delivery_id uuid, recipient_device_id uuid, ciphertext_hex text)
      join public.gc_ciphertext_deliveries q on q.delivery_id = x.delivery_id;
    if v_existing_count > 0 then
        if exists (
            select 1 from jsonb_to_recordset(p_copies)
              as x(delivery_id uuid, recipient_device_id uuid, ciphertext_hex text)
            join public.gc_ciphertext_deliveries q on q.delivery_id = x.delivery_id
            where q.sender_device_id <> p_sender_device_id
               or q.recipient_device_id <> x.recipient_device_id
               or q.ciphertext_sha256 <> extensions.digest(decode(x.ciphertext_hex, 'hex'), 'sha256')
               or q.expires_at <> p_expires_at or q.group_id <> p_group_id
               or q.group_membership_version <> p_membership_version
        ) then raise exception 'delivery ID was already used for different content'; end if;
        if v_existing_count = v_copy_count then return v_ids; end if;
        if p_membership_version is null or p_membership_version <> v_current_version then
            raise exception 'group roster changed during an incomplete retry; refresh and prepare a new send';
        end if;
    elsif p_membership_version is null or p_membership_version <> v_current_version then
        raise exception 'group roster changed; refresh and prepare a new complete fan-out';
    end if;

    if exists (
        select 1 from public.gc_group_members m
        join public.gc_accounts a on a.id = m.account_id
        where m.group_id = p_group_id and a.status <> 'active'
    ) then raise exception 'group contains an inactive account; owner must resolve membership first'; end if;

    -- Require one ciphertext for every active device of every other active group member.
    -- Sender's own account devices are intentionally excluded; this matches the client fan-out.
    if exists (
        select 1 from public.gc_group_members m
        where m.group_id = p_group_id and m.account_id <> v_sender_account
          and not exists (
              select 1 from public.gc_devices d
              where d.account_id = m.account_id and d.status = 'active'
          )
    ) then raise exception 'every other group member must have an active device'; end if;

    if exists (
        with proposed as (
            select x.recipient_device_id
            from jsonb_to_recordset(p_copies)
              as x(delivery_id uuid, recipient_device_id uuid, ciphertext_hex text)
        ), expected as (
            select d.id as recipient_device_id
            from public.gc_group_members m
            join public.gc_accounts a on a.id = m.account_id and a.status = 'active'
            join public.gc_devices d on d.account_id = a.id and d.status = 'active'
            where m.group_id = p_group_id and m.account_id <> v_sender_account
        )
        select 1 from (
            (select recipient_device_id from expected except select recipient_device_id from proposed)
            union all
            (select recipient_device_id from proposed except select recipient_device_id from expected)
        ) differences
    ) then raise exception 'batch does not exactly cover the current active group devices'; end if;

    if exists (
        select 1
        from jsonb_to_recordset(p_copies)
          as x(delivery_id uuid, recipient_device_id uuid, ciphertext_hex text)
        join public.gc_devices d on d.id = x.recipient_device_id and d.status = 'active'
        where not exists (
            select 1 from public.gc_contact_consents own_consent
            join public.gc_contact_consents peer_consent
              on peer_consent.account_id = own_consent.contact_account_id
             and peer_consent.contact_account_id = own_consent.account_id
            where own_consent.account_id = v_sender_account
              and own_consent.contact_account_id = d.account_id
              and own_consent.accepted and peer_consent.accepted
        )
    ) then raise exception 'mutually accepted contact required for every group member' using errcode = '42501'; end if;

    insert into public.gc_ciphertext_deliveries(
        delivery_id, sender_device_id, recipient_device_id, ciphertext,
        ciphertext_sha256, expires_at, group_id, group_membership_version
    )
    select x.delivery_id, p_sender_device_id, x.recipient_device_id, decoded.ciphertext,
           extensions.digest(decoded.ciphertext, 'sha256'), p_expires_at, p_group_id, p_membership_version
    from jsonb_to_recordset(p_copies)
      as x(delivery_id uuid, recipient_device_id uuid, ciphertext_hex text)
    cross join lateral (select decode(x.ciphertext_hex, 'hex') as ciphertext) decoded
    where not exists (
        select 1 from public.gc_ciphertext_deliveries q where q.delivery_id = x.delivery_id
    );

    return v_ids;
end;
$$;

revoke all on function public.gc_submit_group_ciphertext_batch(uuid,bigint,uuid,timestamptz,jsonb) from public, anon;
grant execute on function public.gc_submit_group_ciphertext_batch(uuid,bigint,uuid,timestamptz,jsonb) to authenticated;
comment on function public.gc_submit_group_ciphertext_batch(uuid,bigint,uuid,timestamptz,jsonb) is
    'Atomically accepts an exact pairwise-ciphertext copy for every active device of every other active group member, under one locked membership version; exact retries are idempotent.';
