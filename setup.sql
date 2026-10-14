-- =====================================================================
--  HOKIE POWER — database setup for Supabase
--  Paste this whole file into Supabase → SQL Editor → New query → Run.
--  Safe to run again: it only creates what is missing and refreshes the rules.
--
--  What it creates
--    profiles   one row per person: username, role (athlete/admin), status (pending/active/revoked)
--    user_data  one row per person: all of their training data (workouts, results, settings…)
--  Rules (Row Level Security)
--    • each person can only ever read and write THEIR OWN training data
--    • only people with status "active" can read or save data
--    • only an active admin can see the team list and approve / revoke / reset people
--    • the very first account created becomes the admin automatically
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- ---------- tables ----------
create table if not exists public.profiles (
  id         uuid primary key references auth.users(id) on delete cascade,
  username   text unique not null,
  role       text not null default 'athlete' check (role in ('athlete','admin')),
  status     text not null default 'pending' check (status in ('pending','active','revoked')),
  created_at timestamptz not null default now(),
  last_seen  timestamptz
);

create table if not exists public.user_data (
  user_id    uuid primary key references auth.users(id) on delete cascade,
  data       jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

alter table public.profiles  enable row level security;
alter table public.user_data enable row level security;

-- ---------- helper checks ----------
create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin' and status = 'active');
$$;

create or replace function public.is_active() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and status = 'active');
$$;

-- ---------- new sign-ups get a profile (first one = admin) ----------
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
declare is_first boolean;
begin
  select not exists (select 1 from public.profiles) into is_first;
  insert into public.profiles (id, username, role, status)
  values (
    new.id,
    lower(coalesce(new.raw_user_meta_data->>'username', split_part(new.email, '@', 1))),
    case when is_first then 'admin'  else 'athlete' end,
    case when is_first then 'active' else 'pending' end
  );
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ---------- row level security ----------
drop policy if exists "profiles: read own or admin" on public.profiles;
create policy "profiles: read own or admin" on public.profiles
  for select using (id = auth.uid() or public.is_admin());
-- (no insert/update/delete policies: profiles only change through the functions below)

drop policy if exists "data: read own"   on public.user_data;
drop policy if exists "data: insert own" on public.user_data;
drop policy if exists "data: update own" on public.user_data;
create policy "data: read own" on public.user_data
  for select using (user_id = auth.uid() and public.is_active());
create policy "data: insert own" on public.user_data
  for insert with check (user_id = auth.uid() and public.is_active());
create policy "data: update own" on public.user_data
  for update using (user_id = auth.uid() and public.is_active())
  with check (user_id = auth.uid() and public.is_active());

-- ---------- functions the app calls ----------
create or replace function public.touch_last_seen() returns void
language sql security definer set search_path = public as $$
  update public.profiles set last_seen = now() where id = auth.uid();
$$;

create or replace function public.admin_list_users()
returns table (id uuid, username text, role text, status text, created_at timestamptz, last_seen timestamptz, workouts int, data_updated timestamptz)
language plpgsql stable security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'Only an admin can do this'; end if;
  return query
    select p.id, p.username, p.role, p.status, p.created_at, p.last_seen,
           coalesce((select count(*)::int from jsonb_array_elements(coalesce(d.data->'sessions','[]'::jsonb)) s
                     where s->>'status' = 'completed'), 0),
           d.updated_at
    from public.profiles p left join public.user_data d on d.user_id = p.id
    order by case p.status when 'pending' then 0 when 'active' then 1 else 2 end, p.created_at;
end $$;

create or replace function public.admin_set_status(target uuid, new_status text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'Only an admin can do this'; end if;
  if target = auth.uid() then raise exception 'You cannot change your own access'; end if;
  if new_status not in ('pending','active','revoked') then raise exception 'Unknown status'; end if;
  update public.profiles set status = new_status where id = target;
end $$;

create or replace function public.admin_set_role(target uuid, new_role text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'Only an admin can do this'; end if;
  if target = auth.uid() then raise exception 'You cannot change your own role'; end if;
  if new_role not in ('athlete','admin') then raise exception 'Unknown role'; end if;
  update public.profiles set role = new_role where id = target;
end $$;

create or replace function public.admin_reset_password(target uuid, new_password text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public.is_admin() then raise exception 'Only an admin can do this'; end if;
  if length(new_password) < 8 then raise exception 'Password must be at least 8 characters'; end if;
  update auth.users set encrypted_password = extensions.crypt(new_password, extensions.gen_salt('bf')), updated_at = now()
  where id = target;
end $$;

create or replace function public.admin_delete_user(target uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'Only an admin can do this'; end if;
  if target = auth.uid() then raise exception 'You cannot delete yourself'; end if;
  delete from auth.users where id = target;   -- profile and training data go with it
end $$;

-- only signed-in people may call these (each one checks admin rights itself)
revoke all on function public.admin_list_users()                    from public, anon;
revoke all on function public.admin_set_status(uuid, text)          from public, anon;
revoke all on function public.admin_set_role(uuid, text)            from public, anon;
revoke all on function public.admin_reset_password(uuid, text)      from public, anon;
revoke all on function public.admin_delete_user(uuid)               from public, anon;
revoke all on function public.touch_last_seen()                     from public, anon;
grant execute on function public.admin_list_users()                 to authenticated;
grant execute on function public.admin_set_status(uuid, text)       to authenticated;
grant execute on function public.admin_set_role(uuid, text)         to authenticated;
grant execute on function public.admin_reset_password(uuid, text)   to authenticated;
grant execute on function public.admin_delete_user(uuid)            to authenticated;
grant execute on function public.touch_last_seen()                  to authenticated;

-- Done. You should see "Success. No rows returned".
