-- Server-authoritative device revocation and limited Owner account controls.
-- Apply after 0001-0006; no message contents or private keys are exposed.

-- Clients may register their own device rows but cannot rewrite its status or public identity key.
revoke update, delete on public.gc_devices from authenticated;
drop policy if exists gc_devices_update_self on public.gc_devices;
drop policy if exists gc_devices_delete_self on public.gc_devices;

create table if not exists public.gc_owner_admin_audit (
    id bigint generated always as identity primary key,
    actor_account_id uuid references public.gc_accounts(id) on delete set null,
    event_type text not null check (event_type in ('client_suspended', 'client_restored', 'device_revoked')),
    target_account_id uuid references public.gc_accounts(id) on delete set null,
    target_device_id uuid references public.gc_devices(id) on delete set null,
    created_at timestamptz not null default now()
);
alter table public.gc_owner_admin_audit enable row level security;
revoke all on public.gc_owner_admin_audit from anon, authenticated;

create or replace function public.gc_owner_list_accounts()
returns table(account_id uuid, username text, display_name text, role text, status text)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_owner_id uuid;
begin
    select a.id into v_owner_id from public.gc_accounts a
      where a.auth_user_id = auth.uid() and a.role = 'owner' and a.status = 'active';
    if v_owner_id is null then raise exception 'active Owner authorization required' using errcode = '42501'; end if;
    return query select a.id, a.username, a.display_name, a.role, a.status
      from public.gc_accounts a order by a.created_at, a.id;
end;
$$;

create or replace function public.gc_owner_list_devices(p_account_id uuid)
returns table(device_id uuid, signal_device_id smallint, registration_id integer,
              status text, created_at timestamptz, last_authenticated_at timestamptz)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_owner_id uuid;
begin
    select a.id into v_owner_id from public.gc_accounts a
      where a.auth_user_id = auth.uid() and a.role = 'owner' and a.status = 'active';
    if v_owner_id is null then raise exception 'active Owner authorization required' using errcode = '42501'; end if;
    if not exists (select 1 from public.gc_accounts a where a.id = p_account_id) then
        raise exception 'GlassChat account not found';
    end if;
    return query select d.id, d.signal_device_id, d.registration_id, d.status, d.created_at, d.last_authenticated_at
      from public.gc_devices d where d.account_id = p_account_id order by d.created_at, d.id;
end;
$$;

create or replace function public.gc_owner_set_client_status(p_account_id uuid, p_status text)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_owner_id uuid;
    v_changed integer;
begin
    select a.id into v_owner_id from public.gc_accounts a
      where a.auth_user_id = auth.uid() and a.role = 'owner' and a.status = 'active';
    if v_owner_id is null then raise exception 'active Owner authorization required' using errcode = '42501'; end if;
    if p_status is null or p_status not in ('active', 'suspended') then raise exception 'status must be active or suspended'; end if;
    update public.gc_accounts set status = p_status
      where id = p_account_id and role = 'client' and status <> p_status;
    get diagnostics v_changed = row_count;
    if v_changed = 1 then
        insert into public.gc_owner_admin_audit(actor_account_id, event_type, target_account_id)
          values (v_owner_id, case when p_status = 'suspended' then 'client_suspended' else 'client_restored' end, p_account_id);
    end if;
    return v_changed = 1;
end;
$$;

create or replace function public.gc_revoke_device(p_device_id uuid)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_actor_id uuid;
    v_actor_role text;
    v_target_account_id uuid;
    v_changed integer;
begin
    select a.id, a.role into v_actor_id, v_actor_role from public.gc_accounts a
      where a.auth_user_id = auth.uid() and a.status = 'active';
    if v_actor_id is null then raise exception 'active GlassChat account required' using errcode = '42501'; end if;
    select d.account_id into v_target_account_id from public.gc_devices d where d.id = p_device_id;
    if v_target_account_id is null then return false; end if;
    if v_target_account_id <> v_actor_id and v_actor_role <> 'owner' then
        raise exception 'device belongs to another account' using errcode = '42501';
    end if;
    update public.gc_devices set status = 'revoked'
      where id = p_device_id and status = 'active';
    get diagnostics v_changed = row_count;
    if v_changed = 1 then
        delete from public.gc_signal_one_time_prekeys p where p.device_id = p_device_id;
        delete from public.gc_signal_public_prekeys p where p.device_id = p_device_id;
        insert into public.gc_owner_admin_audit(actor_account_id, event_type, target_account_id, target_device_id)
          values (v_actor_id, 'device_revoked', v_target_account_id, p_device_id);
    end if;
    return v_changed = 1;
end;
$$;

create or replace function public.gc_owner_list_admin_audit(p_limit integer default 100)
returns table(event_id bigint, actor_account_id uuid, event_type text,
              target_account_id uuid, target_device_id uuid, created_at timestamptz)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_owner_id uuid;
begin
    select a.id into v_owner_id from public.gc_accounts a
      where a.auth_user_id = auth.uid() and a.role = 'owner' and a.status = 'active';
    if v_owner_id is null then raise exception 'active Owner authorization required' using errcode = '42501'; end if;
    if p_limit is null or p_limit not between 1 and 200 then raise exception 'audit limit must be 1-200'; end if;
    return query select l.id, l.actor_account_id, l.event_type, l.target_account_id, l.target_device_id, l.created_at
      from public.gc_owner_admin_audit l order by l.created_at desc, l.id desc limit p_limit;
end;
$$;

revoke all on function public.gc_owner_list_accounts() from public, anon;
revoke all on function public.gc_owner_list_devices(uuid) from public, anon;
revoke all on function public.gc_owner_set_client_status(uuid, text) from public, anon;
revoke all on function public.gc_revoke_device(uuid) from public, anon;
revoke all on function public.gc_owner_list_admin_audit(integer) from public, anon;
grant execute on function public.gc_owner_list_accounts() to authenticated;
grant execute on function public.gc_owner_list_devices(uuid) to authenticated;
grant execute on function public.gc_owner_set_client_status(uuid, text) to authenticated;
grant execute on function public.gc_revoke_device(uuid) to authenticated;
grant execute on function public.gc_owner_list_admin_audit(integer) to authenticated;

comment on function public.gc_owner_list_accounts() is 'Lists non-secret account metadata for the active Owner only.';
comment on function public.gc_owner_list_devices(uuid) is 'Lists device metadata without public identity/prekey material or tokens for the active Owner only.';
comment on function public.gc_owner_set_client_status(uuid, text) is 'Allows the active Owner to suspend or restore client accounts only; Owner accounts cannot be changed here.';
comment on function public.gc_revoke_device(uuid) is 'Revokes an own device or, for an active Owner, any device; removes its published prekeys and writes a metadata-only audit record.';
comment on table public.gc_owner_admin_audit is 'Metadata-only log of server-authorized Owner account/device changes; no message contents.';
comment on function public.gc_owner_list_admin_audit(integer) is 'Lists metadata-only Owner administrative audit events for the active Owner.';
