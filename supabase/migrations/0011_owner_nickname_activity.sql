-- Owner nickname activity is a deliberately narrow disclosure path. Ordinary contact nicknames
-- stay local; only an authenticated client making an explicit UI choice can write to the single
-- active Owner account, and only that Owner can read the resulting event history.
create table if not exists public.gc_owner_nickname_events (
    id bigint generated always as identity primary key,
    assigning_account_id uuid not null references public.gc_accounts(id) on delete cascade,
    owner_account_id uuid not null references public.gc_accounts(id) on delete cascade,
    nickname text not null check (char_length(nickname) between 1 and 80),
    event_type text not null check (event_type in ('assigned', 'changed', 'removed')),
    created_at timestamptz not null default now(),
    check (assigning_account_id <> owner_account_id)
);
create index if not exists gc_owner_nickname_events_owner_recent_idx
    on public.gc_owner_nickname_events(owner_account_id, created_at desc, id desc);
alter table public.gc_owner_nickname_events enable row level security;
revoke all on public.gc_owner_nickname_events from public, anon, authenticated;

create or replace function public.gc_set_owner_nickname(p_owner_account_id uuid, p_nickname text)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_actor_id uuid;
    v_owner_id uuid;
    v_owner_count integer;
    v_previous text;
    v_previous_event text;
    v_next text;
    v_event text;
begin
    if auth.uid() is null then raise exception 'authenticated session required' using errcode = '42501'; end if;
    select a.id into v_actor_id from public.gc_accounts a
      where a.auth_user_id = auth.uid() and a.role = 'client' and a.status = 'active';
    if v_actor_id is null then raise exception 'active Client account required' using errcode = '42501'; end if;

    select count(*) into v_owner_count from public.gc_accounts a
      where a.role = 'owner' and a.status = 'active';
    if v_owner_count <> 1 then raise exception 'exactly one active official Owner is required' using errcode = '42501'; end if;
    select a.id into v_owner_id from public.gc_accounts a
      where a.role = 'owner' and a.status = 'active';
    if p_owner_account_id is distinct from v_owner_id then
        raise exception 'target is not the official Owner account' using errcode = '42501';
    end if;
    if p_nickname is not null and char_length(btrim(p_nickname)) not between 1 and 80 then
        raise exception 'nickname must be 1-80 characters, or blank to remove';
    end if;
    v_next := nullif(btrim(p_nickname), '');

    perform pg_advisory_xact_lock(hashtextextended(v_actor_id::text || ':' || v_owner_id::text, 0));
    select e.nickname, e.event_type into v_previous, v_previous_event
      from public.gc_owner_nickname_events e
      where e.assigning_account_id = v_actor_id and e.owner_account_id = v_owner_id
      order by e.created_at desc, e.id desc limit 1;
    if v_previous_event = 'removed' then v_previous := null; end if;

    if v_next is null then
        if v_previous is null then return false; end if;
        v_event := 'removed';
        v_next := v_previous;
    elsif v_previous is null then
        v_event := 'assigned';
    elsif v_previous = v_next then
        return false;
    else
        v_event := 'changed';
    end if;

    insert into public.gc_owner_nickname_events(assigning_account_id, owner_account_id, nickname, event_type)
      values (v_actor_id, v_owner_id, v_next, v_event);
    return true;
end;
$$;

create or replace function public.gc_owner_list_nickname_events(p_limit integer default 100)
returns table(event_id bigint, assigning_account_id uuid, assigning_username text,
              assigning_display_name text, nickname text, event_type text, created_at timestamptz)
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
    if p_limit is null or p_limit not between 1 and 200 then raise exception 'event limit must be 1-200'; end if;
    return query select e.id, e.assigning_account_id, a.username, a.display_name,
                        e.nickname, e.event_type, e.created_at
      from public.gc_owner_nickname_events e
      join public.gc_accounts a on a.id = e.assigning_account_id
      where e.owner_account_id = v_owner_id
      order by e.created_at desc, e.id desc limit p_limit;
end;
$$;

revoke all on function public.gc_set_owner_nickname(uuid, text) from public, anon;
revoke all on function public.gc_owner_list_nickname_events(integer) from public, anon;
grant execute on function public.gc_set_owner_nickname(uuid, text) to authenticated;
grant execute on function public.gc_owner_list_nickname_events(integer) to authenticated;
comment on table public.gc_owner_nickname_events is 'Explicitly shared nickname activity for the single active Owner only; other contact nicknames remain device-local.';
comment on function public.gc_set_owner_nickname(uuid, text) is 'Records an explicit Client-selected Owner nickname assignment/change/removal; validates the single active Owner on the server.';
comment on function public.gc_owner_list_nickname_events(integer) is 'Returns nickname activity for the authenticated active Owner only; no other contact nicknames are exposed.';
