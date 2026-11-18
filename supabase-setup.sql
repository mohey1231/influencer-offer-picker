-- Influencer offer picker: who may sign in.
-- Already run on Supabase project jdsgoerxwecqqoqxvmao. Safe to re-run on a fresh project.
create table if not exists public.app_users(
  email text primary key check (email = lower(email)),
  role text not null default 'member' check (role in ('admin','member')),
  added_at timestamptz not null default now(),
  added_by text
);
alter table public.app_users enable row level security;

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists(select 1 from public.app_users where email = lower(auth.jwt()->>'email') and role = 'admin');
$$;

drop policy if exists "read own or admin" on public.app_users;
drop policy if exists "admin insert" on public.app_users;
drop policy if exists "admin update" on public.app_users;
drop policy if exists "admin delete" on public.app_users;
create policy "read own or admin" on public.app_users for select to authenticated using (email = lower(auth.jwt()->>'email') or public.is_admin());
create policy "admin insert" on public.app_users for insert to authenticated with check (public.is_admin());
create policy "admin update" on public.app_users for update to authenticated using (public.is_admin()) with check (public.is_admin());
create policy "admin delete" on public.app_users for delete to authenticated using (public.is_admin() and email <> lower(auth.jwt()->>'email'));
grant select, insert, update, delete on public.app_users to authenticated;

-- only listed emails can create a login
create or replace function public.only_listed_signup() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if not exists(select 1 from public.app_users where email = lower(new.email)) then
    raise exception 'EMAIL_NOT_ALLOWED';
  end if;
  return new;
end $$;
drop trigger if exists only_listed_signup on auth.users;
create trigger only_listed_signup before insert on auth.users for each row execute function public.only_listed_signup();

-- removing someone from the list also removes their login
create or replace function public.drop_login_on_remove() returns trigger
language plpgsql security definer set search_path = public, auth as $$
begin
  delete from auth.users where lower(email) = old.email;
  return old;
end $$;
drop trigger if exists drop_login_on_remove on public.app_users;
create trigger drop_login_on_remove after delete on public.app_users for each row execute function public.drop_login_on_remove();

-- admin "reset": delete the login so the person can set a new password
create or replace function public.admin_reset_login(target text) returns void
language plpgsql security definer set search_path = public, auth as $$
begin
  if not public.is_admin() then raise exception 'NOT_ADMIN'; end if;
  delete from auth.users where lower(email) = lower(target);
end $$;
revoke execute on function public.admin_reset_login(text) from public, anon;
grant execute on function public.admin_reset_login(text) to authenticated;

insert into public.app_users(email, role, added_by) values ('rasans.rise@gmail.com', 'admin', 'setup')
on conflict (email) do nothing;
