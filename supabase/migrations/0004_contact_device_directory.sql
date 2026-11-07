-- Minimal public device lookup for mutually approved contacts. No message payload or
-- authentication secret is returned; identity keys remain public Signal verification material.
create or replace function public.gc_list_contact_devices(p_peer_account_id uuid)
returns table(account_id uuid, device_id uuid, signal_device_id smallint,
               registration_id integer, public_identity_key bytea)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_requester_account uuid;
begin
    if auth.uid() is null then raise exception 'authenticated session required' using errcode = '42501'; end if;
    select a.id into v_requester_account from public.gc_accounts a
      where a.auth_user_id = auth.uid() and a.status = 'active';
    if v_requester_account is null then raise exception 'active GlassChat account required' using errcode = '42501'; end if;
    if p_peer_account_id = v_requester_account or not exists (
        select 1 from public.gc_accounts a where a.id = p_peer_account_id and a.status = 'active'
    ) then raise exception 'active peer account required'; end if;
    if not exists (
        select 1 from public.gc_contact_consents x join public.gc_contact_consents y
          on y.account_id = x.contact_account_id and y.contact_account_id = x.account_id
        where x.account_id = v_requester_account and x.contact_account_id = p_peer_account_id
          and x.accepted and y.accepted
    ) then raise exception 'mutually accepted contact required' using errcode = '42501'; end if;
    return query select d.account_id, d.id, d.signal_device_id, d.registration_id, d.public_identity_key
      from public.gc_devices d where d.account_id = p_peer_account_id and d.status = 'active'
      order by d.created_at, d.id;
end;
$$;

revoke all on function public.gc_list_contact_devices(uuid) from public, anon;
grant execute on function public.gc_list_contact_devices(uuid) to authenticated;
comment on function public.gc_list_contact_devices(uuid) is
    'Returns only active device IDs and public Signal identity keys for mutually consented contacts.';
