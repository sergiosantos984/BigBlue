-- =====================================================================
--  HOKIE POWER — phone alert when someone asks to join
--  1) Change the two values in the "settings" lines below (topic + your app address).
--  2) Paste this whole file into Supabase → SQL Editor → New query → Run.
--  Safe to run again (e.g. to change the topic).
--
--  How it works: when a new account is created (status "pending"), the database
--  sends a message to ntfy.sh on your private topic. The free ntfy app on your
--  phone shows it as a notification. Tapping it opens Team access in the app.
-- =====================================================================

create extension if not exists pg_net with schema extensions;

-- private settings (no one using the app can read this table)
create table if not exists public.app_settings (key text primary key, value text not null);
alter table public.app_settings enable row level security;

insert into public.app_settings (key, value) values
  ('ntfy_topic', 'hokie-power-727e2b15e9f0'),                 -- ← your private topic (same name you subscribe to in the ntfy app)
  ('app_url',    'https://sergiosantos984.github.io/Hokie-Power/')     -- ← your app's address
on conflict (key) do update set value = excluded.value;

-- sends one alert (never blocks a sign-up, even if ntfy is down)
create or replace function public.send_phone_alert(alert_title text, alert_message text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare topic text; app text;
begin
  select value into topic from public.app_settings where key = 'ntfy_topic';
  select value into app   from public.app_settings where key = 'app_url';
  if coalesce(topic, '') = '' then return; end if;
  perform net.http_post(
    url  := 'https://ntfy.sh',
    body := jsonb_build_object(
      'topic',    topic,
      'title',    alert_title,
      'message',  alert_message,
      'tags',     jsonb_build_array('muscle'),
      'priority', 4,
      'click',    coalesce(app, '') || '?go=admin'
    )
  );
exception when others then
  return;
end $$;

-- fires for every new pending account
create or replace function public.notify_new_signup() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if new.status = 'pending' then
    perform public.send_phone_alert('New athlete request', new.username || ' wants to join Hokie Power. Tap to approve.');
  end if;
  return new;
end $$;

drop trigger if exists on_profile_pending on public.profiles;
create trigger on_profile_pending
  after insert on public.profiles
  for each row execute function public.notify_new_signup();

-- "Send test alert" button in Team access
create or replace function public.admin_test_alert() returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'Only an admin can do this'; end if;
  perform public.send_phone_alert('Hokie Power test', 'Alerts are working. You will hear from me when someone asks to join.');
end $$;

revoke all on function public.send_phone_alert(text, text) from public, anon, authenticated;
revoke all on function public.admin_test_alert() from public, anon;
grant execute on function public.admin_test_alert() to authenticated;

-- Done. You should see "Success. No rows returned".
