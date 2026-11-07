-- Authenticated devices can inspect only the number of their own unconsumed one-time prekeys.
-- No key material or other device/account metadata is returned by this RPC.
create or replace function public.gc_count_own_one_time_prekeys(p_device_id uuid)
returns integer
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_account_id uuid;
    v_count integer;
begin
    if auth.uid() is null then raise exception 'authenticated session required' using errcode = '42501'; end if;
    select d.account_id into v_account_id
      from public.gc_devices d join public.gc_accounts a on a.id = d.account_id
      where d.id = p_device_id and d.status = 'active'
        and a.status = 'active' and a.auth_user_id = auth.uid();
    if v_account_id is null then raise exception 'active owned device required' using errcode = '42501'; end if;
    select count(*)::integer into v_count
      from public.gc_signal_one_time_prekeys p
      where p.device_id = p_device_id and p.account_id = v_account_id;
    return coalesce(v_count, 0);
end;
$$;
revoke all on function public.gc_count_own_one_time_prekeys(uuid) from public, anon;
grant execute on function public.gc_count_own_one_time_prekeys(uuid) to authenticated;
comment on function public.gc_count_own_one_time_prekeys(uuid) is
    'Returns only the unconsumed public one-time-prekey count for the authenticated caller’s active device.';
