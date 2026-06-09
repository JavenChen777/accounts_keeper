alter table public.accounts enable row level security;

drop policy if exists "accounts_select_anon" on public.accounts;
drop policy if exists "accounts_insert_anon" on public.accounts;
drop policy if exists "accounts_update_anon" on public.accounts;
drop policy if exists "accounts_delete_anon" on public.accounts;

create policy "accounts_select_anon" on public.accounts
  for select to anon using (true);

create policy "accounts_insert_anon" on public.accounts
  for insert to anon with check (true);

create policy "accounts_update_anon" on public.accounts
  for update to anon using (true) with check (true);

create policy "accounts_delete_anon" on public.accounts
  for delete to anon using (true);
