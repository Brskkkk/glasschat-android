-- Group management and membership-version guarded ciphertext submission.
-- This adds no plaintext or private-key storage. Membership edits serialize with sends by
-- locking the group row; each pairwise copy carries the roster version it was prepared for.

alter table public.gc_groups
    add column if not exists membership_version bigint not null default 1;

-- A member may fetch only queued copies created at or after their current membership epoch.
-- This prevents a removed account that later rejoins from receiving old queued group content.
alter table public.gc_group_members
    add column if not exists joined_membership_version bigint;
update public.gc_group_members m
   set joined_membership_version = g.membership_version
  from public.gc_groups g
 where g.id = m.group_id and m.joined_membership_version is null;
alter table public.gc_group_members alter column joined_membership_version set not null;

alter table public.gc_ciphertext_deliveries
    add column if not exists group_membership_version bigint;
update public.gc_ciphertext_deliveries q
   set group_membership_version = g.membership_version
  from public.gc_groups g
 where q.group_id = g.id and q.group_membership_version is null;
do $$
begin
    if not exists (
        select 1 from pg_constraint
         where conname = 'gc_ciphertext_group_version_pair_check'
           and conrelid = 'public.gc_ciphertext_deliveries'::regclass
    ) then
        alter table public.gc_ciphertext_deliveries
            add constraint gc_ciphertext_group_version_pair_check
            check ((group_id is null) = (group_membership_version is null));
    end if;
end;
$$;

-- Prepare the joining epoch while holding the same group-row lock used by guarded submits.
-- The AFTER insert/delete trigger advances the version only if the membership row actually changes.
create or replace function public.gc_prepare_group_member_epoch()
returns trigger
language plpgsql security definer set search_path = public, pg_temp
as $$
declare v_joined_version bigint;
begin
    select g.membership_version + 1 into v_joined_version
      from public.gc_groups g where g.id = new.group_id for update;
    if not found then raise exception 'group does not exist'; end if;
    new.joined_membership_version := v_joined_version;
    return new;
end;
$$;
revoke all on function public.gc_prepare_group_member_epoch() from public, anon, authenticated;
drop trigger if exists gc_group_member_epoch on public.gc_group_members;
create trigger gc_group_member_epoch
    before insert on public.gc_group_members
    for each row execute function public.gc_prepare_group_member_epoch();

create or replace function public.gc_bump_group_membership_version()
returns trigger
language plpgsql security definer set search_path = public, pg_temp
as $$
begin
    if tg_op = 'INSERT' then
        update public.gc_groups set membership_version = membership_version + 1 where id = new.group_id;
        return new;
    end if;
    update public.gc_groups set membership_version = membership_version + 1 where id = old.group_id;
    return old;
end;
$$;
revoke all on function public.gc_bump_group_membership_version() from public, anon, authenticated;
drop trigger if exists gc_group_membership_version on public.gc_group_members;
create trigger gc_group_membership_version
    after insert or delete on public.gc_group_members
    for each row execute function public.gc_bump_group_membership_version();

-- Include the snapshot version in the same statement as the visible roster.
drop function if exists public.gc_list_group_members(uuid);
create function public.gc_list_group_members(p_group_id uuid)
returns table(account_id uuid, username text, display_name text, role text, joined_at timestamptz, membership_version bigint)
language plpgsql security definer set search_path = public, pg_temp
as $$
declare v_account uuid;
begin
    if auth.uid() is null then raise exception 'authenticated session required' using errcode = '42501'; end if;
    select id into v_account from public.gc_accounts where auth_user_id = auth.uid() and status = 'active';
    if v_account is null or not exists (select 1 from public.gc_group_members m where m.group_id = p_group_id and m.account_id = v_account) then
        raise exception 'active group membership required' using errcode = '42501';
    end if;
    return query select a.id, a.username, a.display_name, m.role, m.joined_at, g.membership_version
      from public.gc_group_members m
      join public.gc_accounts a on a.id = m.account_id
      join public.gc_groups g on g.id = m.group_id
      where m.group_id = p_group_id and a.status = 'active'
      order by (m.role = 'owner') desc, m.joined_at, a.id;
end;
$$;

-- Owner-only member removal. The group lock is the serialization point also used by guarded sends.
create or replace function public.gc_remove_group_member(p_group_id uuid, p_target_account_id uuid)
returns boolean
language plpgsql security definer set search_path = public, pg_temp
as $$
declare v_actor uuid; v_role text;
begin
    if auth.uid() is null then raise exception 'authenticated session required' using errcode = '42501'; end if;
    select id into v_actor from public.gc_accounts where auth_user_id = auth.uid() and status = 'active';
    if v_actor is null then raise exception 'active GlassChat account required' using errcode = '42501'; end if;
    perform 1 from public.gc_groups where id = p_group_id for update;
    if not found then raise exception 'group does not exist'; end if;
    if not exists (select 1 from public.gc_group_members where group_id = p_group_id and account_id = v_actor and role = 'owner') then
        raise exception 'group owner membership required' using errcode = '42501';
    end if;
    if p_target_account_id = v_actor then raise exception 'the group owner cannot remove their own membership'; end if;
    select role into v_role from public.gc_group_members where group_id = p_group_id and account_id = p_target_account_id for update;
    if not found then return false; end if;
    if v_role = 'owner' then raise exception 'group owner membership cannot be removed'; end if;
    delete from public.gc_group_members where group_id = p_group_id and account_id = p_target_account_id;
    return found;
end;
$$;

-- Owner-only invite listing exposes opaque IDs and lifecycle timestamps, never invite codes/digests.
create or replace function public.gc_list_group_invites(p_group_id uuid)
returns table(invite_id uuid, created_at timestamptz, expires_at timestamptz, redeemed_at timestamptz, revoked_at timestamptz)
language plpgsql security definer set search_path = public, pg_temp
as $$
declare v_actor uuid;
begin
    if auth.uid() is null then raise exception 'authenticated session required' using errcode = '42501'; end if;
    select id into v_actor from public.gc_accounts where auth_user_id = auth.uid() and status = 'active';
    if v_actor is null or not exists (select 1 from public.gc_group_members where group_id = p_group_id and account_id = v_actor and role = 'owner') then
        raise exception 'group owner membership required' using errcode = '42501';
    end if;
    return query select i.id, i.created_at, i.expires_at, i.redeemed_at, i.revoked_at
      from public.gc_group_invites i where i.group_id = p_group_id and i.redeemed_at is null
        and i.revoked_at is null and i.expires_at > now()
      order by i.created_at desc limit 50;
end;
$$;

create or replace function public.gc_revoke_group_invite(p_invite_id uuid)
returns boolean
language plpgsql security definer set search_path = public, pg_temp
as $$
declare v_actor uuid; v_group uuid; v_invite public.gc_group_invites%rowtype;
begin
    if auth.uid() is null then raise exception 'authenticated session required' using errcode = '42501'; end if;
    select id into v_actor from public.gc_accounts where auth_user_id = auth.uid() and status = 'active';
    if v_actor is null then raise exception 'active GlassChat account required' using errcode = '42501'; end if;
    select group_id into v_group from public.gc_group_invites where id = p_invite_id;
    if v_group is null then return false; end if;
    perform 1 from public.gc_groups where id = v_group for update;
    if not exists (select 1 from public.gc_group_members where group_id = v_group and account_id = v_actor and role = 'owner') then
        raise exception 'group owner membership required' using errcode = '42501';
    end if;
    select * into v_invite from public.gc_group_invites where id = p_invite_id and group_id = v_group for update;
    if not found or v_invite.redeemed_at is not null or v_invite.revoked_at is not null or v_invite.expires_at <= now() then
        return false;
    end if;
    update public.gc_group_invites set revoked_at = now() where id = p_invite_id;
    return true;
end;
$$;

-- Redemption locks the group before the invite, matching management/send lock ordering.
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

-- Version-guarded individual deliveries. The group row lock makes each accepted copy linearize
-- either before a membership edit or after its new version. A changed roster rejects all later
-- copies from that send attempt; already accepted copies remain explicitly partial, never hidden.
-- Delivery rows also retain the accepted roster epoch; later joiners cannot fetch older queued copies.
create or replace function public.gc_submit_group_ciphertext_v2(
    p_delivery_id uuid, p_group_id uuid, p_membership_version bigint, p_sender_device_id uuid,
    p_recipient_device_id uuid, p_ciphertext bytea, p_expires_at timestamptz
)
returns uuid
language plpgsql security definer set search_path = public, pg_temp
as $$
declare v_sender_account uuid; v_recipient_account uuid; v_current_version bigint; v_existing public.gc_ciphertext_deliveries%rowtype;
begin
    if auth.uid() is null then raise exception 'authenticated session required' using errcode = '42501'; end if;
    if p_ciphertext is null or octet_length(p_ciphertext) not between 1 and 1048586 then raise exception 'ciphertext size is invalid'; end if;
    if p_expires_at <= now() or p_expires_at > now() + interval '7 days' then raise exception 'ciphertext expiry must be within seven days'; end if;
    select membership_version into v_current_version from public.gc_groups where id = p_group_id for update;
    if not found then raise exception 'active group sender membership required' using errcode = '42501'; end if;
    select d.account_id into v_sender_account from public.gc_devices d join public.gc_accounts a on a.id=d.account_id
      where d.id=p_sender_device_id and d.status='active' and a.status='active' and a.auth_user_id=auth.uid();
    if v_sender_account is null or not exists(select 1 from public.gc_group_members where group_id=p_group_id and account_id=v_sender_account) then
      raise exception 'active group sender membership required' using errcode = '42501';
    end if;
    -- An exact retry of a copy already accepted under its original epoch remains idempotent even
    -- after a later roster edit. It cannot create another payload or reach a member outside the
    -- current membership epoch; fetch applies both current membership and joined-epoch checks.
    select * into v_existing from public.gc_ciphertext_deliveries where delivery_id=p_delivery_id for update;
    if found then
        if v_existing.sender_device_id=p_sender_device_id and v_existing.recipient_device_id=p_recipient_device_id
           and v_existing.ciphertext_sha256=extensions.digest(p_ciphertext,'sha256') and v_existing.expires_at=p_expires_at
           and v_existing.group_id=p_group_id and v_existing.group_membership_version=p_membership_version then
            return p_delivery_id;
        end if;
        raise exception 'delivery ID was already used for different content';
    end if;
    if p_membership_version is null or p_membership_version <> v_current_version then
        raise exception 'group roster changed; refresh and prepare a new complete fan-out';
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
    insert into public.gc_ciphertext_deliveries(delivery_id,sender_device_id,recipient_device_id,ciphertext,ciphertext_sha256,expires_at,group_id,group_membership_version)
      values(p_delivery_id,p_sender_device_id,p_recipient_device_id,p_ciphertext,extensions.digest(p_ciphertext,'sha256'),p_expires_at,p_group_id,p_membership_version);
    return p_delivery_id;
end;
$$;

-- Keep the existing fetch contract while preventing newly joined/rejoined accounts from
-- receiving any older group-epoch payload that is still waiting on the relay.
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
      and q.expires_at>now() and (q.group_id is null or exists(
          select 1 from public.gc_group_members m
           where m.group_id=q.group_id and m.account_id=v_account
             and m.joined_membership_version <= q.group_membership_version
      ))
      order by q.created_at,q.delivery_id limit p_limit;
end;
$$;

revoke all on function public.gc_list_group_members(uuid) from public, anon;
revoke all on function public.gc_redeem_group_invite(text) from public, anon;
revoke all on function public.gc_remove_group_member(uuid,uuid) from public, anon;
revoke all on function public.gc_list_group_invites(uuid) from public, anon;
revoke all on function public.gc_revoke_group_invite(uuid) from public, anon;
revoke all on function public.gc_submit_group_ciphertext(uuid,uuid,uuid,uuid,bytea,timestamptz) from public, anon, authenticated;
revoke all on function public.gc_submit_group_ciphertext_v2(uuid,uuid,bigint,uuid,uuid,bytea,timestamptz) from public, anon;
grant execute on function public.gc_list_group_members(uuid) to authenticated;
grant execute on function public.gc_redeem_group_invite(text) to authenticated;
grant execute on function public.gc_remove_group_member(uuid,uuid) to authenticated;
grant execute on function public.gc_list_group_invites(uuid) to authenticated;
grant execute on function public.gc_revoke_group_invite(uuid) to authenticated;
grant execute on function public.gc_submit_group_ciphertext_v2(uuid,uuid,bigint,uuid,uuid,bytea,timestamptz) to authenticated;

comment on function public.gc_submit_group_ciphertext_v2(uuid,uuid,bigint,uuid,uuid,bytea,timestamptz) is
    'Accepts opaque pairwise ciphertext only if the client-prepared membership version is still current; serializes each copy with membership changes and prevents later joiners from fetching older queued epochs.';
