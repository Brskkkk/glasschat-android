-- Server-managed group membership and ciphertext authorization.
-- No plaintext content or private key material is stored here.

create table if not exists public.gc_groups (
    id uuid primary key default gen_random_uuid(),
    name text not null check (char_length(name) between 1 and 80),
    created_by uuid not null references public.gc_accounts(id) on delete cascade,
    created_at timestamptz not null default now()
);

create table if not exists public.gc_group_members (
    group_id uuid not null references public.gc_groups(id) on delete cascade,
    account_id uuid not null references public.gc_accounts(id) on delete cascade,
    role text not null check (role in ('owner', 'member')),
    joined_at timestamptz not null default now(),
    primary key (group_id, account_id)
);
create index if not exists gc_group_members_account_idx on public.gc_group_members(account_id, group_id);

alter table public.gc_ciphertext_deliveries
    add column if not exists group_id uuid references public.gc_groups(id) on delete cascade;

create table if not exists public.gc_group_invites (
    id uuid primary key default gen_random_uuid(),
    group_id uuid not null references public.gc_groups(id) on delete cascade,
    code_hash bytea not null unique check (octet_length(code_hash) = 32),
    created_by uuid not null references public.gc_accounts(id) on delete cascade,
    expires_at timestamptz not null,
    redeemed_by uuid references public.gc_accounts(id) on delete set null,
    redeemed_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz not null default now(),
    check ((redeemed_by is null) = (redeemed_at is null))
);
create index if not exists gc_group_invites_expiry_idx on public.gc_group_invites(expires_at);

alter table public.gc_groups enable row level security;
alter table public.gc_group_members enable row level security;
alter table public.gc_group_invites enable row level security;
revoke all on public.gc_groups, public.gc_group_members, public.gc_group_invites from public, anon, authenticated;

create or replace function public.gc_create_group(p_name text)
returns uuid
language plpgsql security definer set search_path = public, pg_temp
as $$
declare v_account uuid; v_group uuid;
begin
    if auth.uid() is null then raise exception 'authenticated session required' using errcode = '42501'; end if;
    select id into v_account from public.gc_accounts where auth_user_id = auth.uid() and status = 'active';
    if v_account is null then raise exception 'active GlassChat account required' using errcode = '42501'; end if;
    if p_name is null or char_length(btrim(p_name)) not between 1 and 80 then raise exception 'group name must be 1–80 characters'; end if;
    insert into public.gc_groups(name, created_by) values (btrim(p_name), v_account) returning id into v_group;
    insert into public.gc_group_members(group_id, account_id, role) values (v_group, v_account, 'owner');
    return v_group;
end;
$$;

create or replace function public.gc_create_group_invite(p_group_id uuid, p_expires_at timestamptz)
returns text
language plpgsql security definer set search_path = public, pg_temp
as $$
declare v_account uuid; v_code text;
begin
    if auth.uid() is null then raise exception 'authenticated session required' using errcode = '42501'; end if;
    select id into v_account from public.gc_accounts where auth_user_id = auth.uid() and status = 'active';
    if v_account is null then raise exception 'active GlassChat account required' using errcode = '42501'; end if;
    if not exists (select 1 from public.gc_group_members where group_id = p_group_id and account_id = v_account and role = 'owner') then
        raise exception 'group owner membership required' using errcode = '42501';
    end if;
    if p_expires_at <= now() or p_expires_at > now() + interval '7 days' then raise exception 'invite expiry must be within seven days'; end if;
    v_code := encode(extensions.gen_random_bytes(24), 'hex');
    insert into public.gc_group_invites(group_id, code_hash, created_by, expires_at)
      values (p_group_id, extensions.digest(v_code, 'sha256'), v_account, p_expires_at);
    return v_code;
end;
$$;

create or replace function public.gc_redeem_group_invite(p_code text)
returns table(group_id uuid, group_name text)
language plpgsql security definer set search_path = public, pg_temp
as $$
declare v_account uuid; v_invite public.gc_group_invites%rowtype; v_name text;
begin
    if auth.uid() is null then raise exception 'authenticated session required' using errcode = '42501'; end if;
    select id into v_account from public.gc_accounts where auth_user_id = auth.uid() and status = 'active';
    if v_account is null then raise exception 'active GlassChat account required' using errcode = '42501'; end if;
    if p_code is null or p_code !~ '^[0-9a-fA-F]{48}$' then raise exception 'invalid group invitation'; end if;
    select * into v_invite from public.gc_group_invites i
      where i.code_hash = extensions.digest(lower(p_code), 'sha256') for update;
    if not found or v_invite.revoked_at is not null or v_invite.expires_at <= now() then raise exception 'group invitation is invalid or expired'; end if;
    if v_invite.redeemed_by is not null and v_invite.redeemed_by <> v_account then raise exception 'group invitation has already been used'; end if;
    if v_invite.redeemed_by is null then
        insert into public.gc_group_members(group_id, account_id, role) values (v_invite.group_id, v_account, 'member')
          on conflict (group_id, account_id) do nothing;
        update public.gc_group_invites set redeemed_by = v_account, redeemed_at = now() where id = v_invite.id;
    end if;
    select g.name into v_name from public.gc_groups g where g.id = v_invite.group_id;
    return query select v_invite.group_id, v_name;
end;
$$;

create or replace function public.gc_list_my_groups()
returns table(group_id uuid, group_name text, role text, joined_at timestamptz)
language plpgsql security definer set search_path = public, pg_temp
as $$
declare v_account uuid;
begin
    if auth.uid() is null then raise exception 'authenticated session required' using errcode = '42501'; end if;
    select id into v_account from public.gc_accounts where auth_user_id = auth.uid() and status = 'active';
    if v_account is null then raise exception 'active GlassChat account required' using errcode = '42501'; end if;
    return query select g.id, g.name, m.role, m.joined_at from public.gc_group_members m
      join public.gc_groups g on g.id = m.group_id where m.account_id = v_account order by m.joined_at, g.id;
end;
$$;

create or replace function public.gc_list_group_members(p_group_id uuid)
returns table(account_id uuid, username text, display_name text, role text, joined_at timestamptz)
language plpgsql security definer set search_path = public, pg_temp
as $$
declare v_account uuid;
begin
    if auth.uid() is null then raise exception 'authenticated session required' using errcode = '42501'; end if;
    select id into v_account from public.gc_accounts where auth_user_id = auth.uid() and status = 'active';
    if v_account is null or not exists (select 1 from public.gc_group_members m where m.group_id = p_group_id and m.account_id = v_account) then
        raise exception 'active group membership required' using errcode = '42501';
    end if;
    return query select a.id, a.username, a.display_name, m.role, m.joined_at from public.gc_group_members m
      join public.gc_accounts a on a.id = m.account_id where m.group_id = p_group_id and a.status = 'active'
      order by (m.role = 'owner') desc, m.joined_at, a.id;
end;
$$;

create or replace function public.gc_submit_group_ciphertext(
    p_delivery_id uuid, p_group_id uuid, p_sender_device_id uuid,
    p_recipient_device_id uuid, p_ciphertext bytea, p_expires_at timestamptz
)
returns uuid
language plpgsql security definer set search_path = public, pg_temp
as $$
declare v_sender_account uuid; v_recipient_account uuid; v_existing public.gc_ciphertext_deliveries%rowtype;
begin
    if auth.uid() is null then raise exception 'authenticated session required' using errcode = '42501'; end if;
    if p_ciphertext is null or octet_length(p_ciphertext) not between 1 and 1048586 then raise exception 'ciphertext size is invalid'; end if;
    if p_expires_at <= now() or p_expires_at > now() + interval '7 days' then raise exception 'ciphertext expiry must be within seven days'; end if;
    select d.account_id into v_sender_account from public.gc_devices d join public.gc_accounts a on a.id=d.account_id
      where d.id=p_sender_device_id and d.status='active' and a.status='active' and a.auth_user_id=auth.uid();
    if v_sender_account is null or not exists(select 1 from public.gc_group_members where group_id=p_group_id and account_id=v_sender_account) then
      raise exception 'active group sender membership required' using errcode = '42501';
    end if;
    select d.account_id into v_recipient_account from public.gc_devices d join public.gc_accounts a on a.id=d.account_id
      where d.id=p_recipient_device_id and d.status='active' and a.status='active';
    if v_recipient_account is null or v_recipient_account=v_sender_account or
       not exists(select 1 from public.gc_group_members where group_id=p_group_id and account_id=v_recipient_account) then
      raise exception 'active group recipient membership required' using errcode = '42501';
    end if;
    if not exists (select 1 from public.gc_contact_consents x join public.gc_contact_consents y
      on y.account_id=x.contact_account_id and y.contact_account_id=x.account_id
      where x.account_id=v_sender_account and x.contact_account_id=v_recipient_account and x.accepted and y.accepted) then
      raise exception 'mutually accepted contact required' using errcode = '42501';
    end if;
    insert into public.gc_ciphertext_deliveries(delivery_id,sender_device_id,recipient_device_id,ciphertext,ciphertext_sha256,expires_at,group_id)
      values(p_delivery_id,p_sender_device_id,p_recipient_device_id,p_ciphertext,extensions.digest(p_ciphertext,'sha256'),p_expires_at,p_group_id)
      on conflict(delivery_id) do nothing;
    if found then return p_delivery_id; end if;
    select * into v_existing from public.gc_ciphertext_deliveries where delivery_id=p_delivery_id for update;
    if v_existing.sender_device_id=p_sender_device_id and v_existing.recipient_device_id=p_recipient_device_id
       and v_existing.ciphertext_sha256=extensions.digest(p_ciphertext,'sha256') and v_existing.expires_at=p_expires_at
       and v_existing.group_id=p_group_id then return p_delivery_id; end if;
    raise exception 'delivery ID was already used for different content';
end;
$$;

create or replace function public.gc_fetch_ciphertext_v2(p_recipient_device_id uuid, p_limit integer default 100)
returns table(delivery_id uuid,sender_device_id uuid,recipient_device_id uuid,ciphertext bytea,expires_at timestamptz,group_id uuid)
language plpgsql security definer set search_path = public, pg_temp
as $$
declare v_account uuid;
begin
    if auth.uid() is null then raise exception 'authenticated session required' using errcode = '42501'; end if;
    if p_limit is null or p_limit not between 1 and 100 then raise exception 'fetch limit must be between 1 and 100'; end if;
    select d.account_id into v_account from public.gc_devices d join public.gc_accounts a on a.id=d.account_id
      where d.id=p_recipient_device_id and d.status='active' and a.status='active' and a.auth_user_id=auth.uid();
    if v_account is null then raise exception 'active recipient device required' using errcode = '42501'; end if;
    delete from public.gc_ciphertext_deliveries q where q.expires_at<=now();
    return query select q.delivery_id,q.sender_device_id,q.recipient_device_id,q.ciphertext,q.expires_at,q.group_id
      from public.gc_ciphertext_deliveries q where q.recipient_device_id=p_recipient_device_id and q.acknowledged_at is null
      and q.expires_at>now() and (q.group_id is null or exists(select 1 from public.gc_group_members m where m.group_id=q.group_id and m.account_id=v_account))
      order by q.created_at,q.delivery_id limit p_limit;
end;
$$;

revoke all on function public.gc_create_group(text) from public, anon;
revoke all on function public.gc_create_group_invite(uuid,timestamptz) from public, anon;
revoke all on function public.gc_redeem_group_invite(text) from public, anon;
revoke all on function public.gc_list_my_groups() from public, anon;
revoke all on function public.gc_list_group_members(uuid) from public, anon;
revoke all on function public.gc_submit_group_ciphertext(uuid,uuid,uuid,uuid,bytea,timestamptz) from public, anon;
revoke all on function public.gc_fetch_ciphertext_v2(uuid,integer) from public, anon;
grant execute on function public.gc_create_group(text) to authenticated;
grant execute on function public.gc_create_group_invite(uuid,timestamptz) to authenticated;
grant execute on function public.gc_redeem_group_invite(text) to authenticated;
grant execute on function public.gc_list_my_groups() to authenticated;
grant execute on function public.gc_list_group_members(uuid) to authenticated;
grant execute on function public.gc_submit_group_ciphertext(uuid,uuid,uuid,uuid,bytea,timestamptz) to authenticated;
grant execute on function public.gc_fetch_ciphertext_v2(uuid,integer) to authenticated;

comment on table public.gc_groups is 'Server-authoritative GlassChat group names and membership metadata; no message content.';
comment on table public.gc_group_invites is 'Single-use, expiring group invitations; only a SHA-256 code digest is stored.';
comment on function public.gc_submit_group_ciphertext(uuid,uuid,uuid,uuid,bytea,timestamptz) is 'Accepts only opaque ciphertext and enforces active sender and recipient membership plus mutual contact consent.';
