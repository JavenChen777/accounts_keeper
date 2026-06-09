create extension if not exists pgcrypto;

create table if not exists public.accounts (
  id uuid primary key default gen_random_uuid(),
  product_name_url text not null,
  username text not null,
  password text not null,
  additional text,
  created_at timestamptz not null default now()
);

alter table public.accounts enable row level security;

-- For a personal encrypted client app using the publishable anon key.
-- The app encrypts account fields before upload, but anyone with this key and
-- these policies can still read/write ciphertext rows. Prefer real Supabase
-- auth policies if this project will be shared.
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
