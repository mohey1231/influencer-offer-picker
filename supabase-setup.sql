-- Influencer offer picker: username + password logins, created by an admin from inside the page.
-- Supabase Auth needs an email, so each username gets an internal address <username>@users.picker.local
-- (never mailed; "Confirm email" is off). Safe to re-run on a fresh project.

drop trigger if exists drop_login_on_remove on public.app_users;
drop function if exists public.admin_reset_login(text);
drop table if exists public.app_users cascade;

create table public.app_users(
  username text primary key check (username ~ '^[a-z0-9][a-z0-9._-]{2,29}$'),
  email text generated always as (username || '@users.picker.local') stored unique,
  role text not null default 'member' check (role in ('admin','member')),
  added_at timestamptz not null default now(),
  added_by text
);
alter table public.app_users enable row level security;

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists(select 1 from public.app_users where email = lower(auth.jwt()->>'email') and role = 'admin');
$$;

create policy "read own or admin" on public.app_users for select to authenticated using (email = lower(auth.jwt()->>'email') or public.is_admin());
create policy "admin insert" on public.app_users for insert to authenticated with check (public.is_admin());
create policy "admin update" on public.app_users for update to authenticated using (public.is_admin()) with check (public.is_admin());
create policy "admin delete" on public.app_users for delete to authenticated using (public.is_admin() and email <> lower(auth.jwt()->>'email'));
grant select, insert, update, delete on public.app_users to authenticated;

-- only listed usernames can get a login
create or replace function public.only_listed_signup() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if not exists(select 1 from public.app_users where email = lower(new.email)) then
    raise exception 'USER_NOT_ALLOWED';
  end if;
  return new;
end $$;
drop trigger if exists only_listed_signup on auth.users;
create trigger only_listed_signup before insert on auth.users for each row execute function public.only_listed_signup();

-- deleting a user from the list also deletes their login
create or replace function public.drop_login_on_remove() returns trigger
language plpgsql security definer set search_path = public, auth as $$
begin
  delete from auth.users where lower(email) = old.email;
  return old;
end $$;
create trigger drop_login_on_remove after delete on public.app_users for each row execute function public.drop_login_on_remove();

-- admin sets a new password for someone (same bcrypt hashing Supabase Auth uses)
create or replace function public.admin_set_password(target text, new_password text) returns void
language plpgsql security definer set search_path = public, auth, extensions as $$
begin
  if not public.is_admin() then raise exception 'NOT_ADMIN'; end if;
  if length(new_password) < 8 then raise exception 'PASSWORD_TOO_SHORT'; end if;
  update auth.users set encrypted_password = extensions.crypt(new_password, extensions.gen_salt('bf')), updated_at = now()
   where lower(email) = (select email from public.app_users where username = lower(target));
  if not found then raise exception 'NO_LOGIN'; end if;
end $$;
revoke execute on function public.admin_set_password(text, text) from public, anon;
grant execute on function public.admin_set_password(text, text) to authenticated;

-- true until the first admin has set a password (the login page shows a one-time setup form)
create or replace function public.needs_setup() returns boolean
language sql stable security definer set search_path = public, auth as $$
  select not exists(select 1 from auth.users u join public.app_users a on a.email = lower(u.email) where a.role = 'admin');
$$;
grant execute on function public.needs_setup() to anon, authenticated;

insert into public.app_users(username, role, added_by) values ('admin', 'admin', 'setup');
