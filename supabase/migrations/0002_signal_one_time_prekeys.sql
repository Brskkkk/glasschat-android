-- One-time Signal prekey public material only; private records stay on the device.
-- Clients may publish and inspect their own rows. They cannot read another account's
-- keys or consume/delete keys; a future authenticated, contact-checked bundle RPC must
-- atomically return and consume one row. This migration does not implement that RPC.

create table if not exists public.gc_signal_one_time_prekeys (
    account_id uuid not null,
    device_id uuid not null,
    prekey_id integer not null check (prekey_id between 1 and 2147483647),
    public_key bytea not null check (octet_length(public_key) between 32 and 512),
    created_at timestamptz not null default now(),
    primary key (device_id, prekey_id),
    foreign key (device_id, account_id)
        references public.gc_devices(id, account_id) on delete cascade
);

create index if not exists gc_signal_one_time_prekeys_account_device_idx
    on public.gc_signal_one_time_prekeys(account_id, device_id);

alter table public.gc_signal_one_time_prekeys enable row level security;
revoke all on public.gc_signal_one_time_prekeys from anon, authenticated;
grant select, insert on public.gc_signal_one_time_prekeys to authenticated;

create policy gc_one_time_prekeys_select_self on public.gc_signal_one_time_prekeys
    for select to authenticated using (exists (
        select 1 from public.gc_accounts a
        where a.id = account_id and a.auth_user_id = (select auth.uid())
    ));

create policy gc_one_time_prekeys_insert_self on public.gc_signal_one_time_prekeys
    for insert to authenticated with check (exists (
        select 1 from public.gc_accounts a
        join public.gc_devices d on d.account_id = a.id
        where a.id = account_id and d.id = device_id
          and a.auth_user_id = (select auth.uid())
          and a.status = 'active' and d.status = 'active'
    ));

comment on table public.gc_signal_one_time_prekeys is
    'Public Signal one-time prekeys. Authenticated clients can insert/read only their own rows; cross-account bundle retrieval and atomic consumption require a future contact-checked server RPC.';
