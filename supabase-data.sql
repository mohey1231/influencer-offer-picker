-- Influencer offer picker: shared team data (campaigns, the influencer sheet, settings).
-- One row per document, like the page's old per-browser store: collection + id + JSON data.
-- Only signed-in users listed in app_users can read or write. Safe to re-run.

create table if not exists public.docs(
  collection text not null check (collection in ('campaigns','library','settings')),
  id text not null,
  data jsonb not null,
  updated_at timestamptz not null default now(),
  updated_by text,
  primary key (collection, id)
);
alter table public.docs enable row level security;

create or replace function public.is_member() returns boolean
language sql stable security definer set search_path = public as $$
  select exists(select 1 from public.app_users where email = lower(auth.jwt()->>'email'));
$$;

drop policy if exists "members read" on public.docs;
drop policy if exists "members insert" on public.docs;
drop policy if exists "members update" on public.docs;
drop policy if exists "members delete" on public.docs;
create policy "members read" on public.docs for select to authenticated using (public.is_member());
create policy "members insert" on public.docs for insert to authenticated with check (public.is_member());
create policy "members update" on public.docs for update to authenticated using (public.is_member()) with check (public.is_member());
create policy "members delete" on public.docs for delete to authenticated using (public.is_member());
grant select, insert, update, delete on public.docs to authenticated;

-- live updates: a campaign saved by one person shows up for everyone without refreshing
do $$ begin
  alter publication supabase_realtime add table public.docs;
exception when duplicate_object then null; end $$;
