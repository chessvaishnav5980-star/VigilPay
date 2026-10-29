-- VigilPay Supabase schema
-- Run this entire file once in Supabase Dashboard > SQL Editor.
-- It enables RLS, masks public identifiers, and keeps raw identifiers unreadable to browser roles.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text,
  role text not null default 'user' check (role in ('user','admin')),
  created_at timestamptz not null default now()
);

create table if not exists public.community_reports (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  identifier_type text not null check (identifier_type in ('phone','upi','website','wallet','account')),
  identifier text not null,
  identifier_hash bytea generated always as (digest(lower(regexp_replace(identifier, '\s', '', 'g')), 'sha256')) stored,
  identifier_display text not null,
  report_type text not null,
  description text not null check (char_length(description) between 12 and 800),
  incident_date date,
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  report_count integer not null default 1 check (report_count > 0),
  created_at timestamptz not null default now(),
  reviewed_at timestamptz
);

create table if not exists public.community_flags (
  id uuid primary key default gen_random_uuid(),
  report_id uuid not null references public.community_reports(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  reason text not null check (char_length(reason) between 3 and 300),
  created_at timestamptz not null default now(),
  unique(report_id,user_id)
);

create table if not exists public.incident_records (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  outcome text not null check (outcome in ('attempt','lost','recovered','prevented')),
  amount numeric(12,2) not null default 0 check (amount >= 0),
  scam_type text not null,
  happened_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);

create table if not exists public.safety_agreements (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  item_name text not null,
  amount numeric(12,2) check (amount >= 0),
  party_name text,
  plan text,
  share_token uuid not null default gen_random_uuid() unique,
  expires_at timestamptz not null default (now() + interval '14 days'),
  created_at timestamptz not null default now()
);

create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists(select 1 from public.profiles where id = auth.uid() and role = 'admin');
$$;

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id,display_name)
  values (new.id, coalesce(new.raw_user_meta_data->>'display_name', split_part(new.email,'@',1)))
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
for each row execute function public.handle_new_user();

-- Exact searches are performed against a one-way hash. The raw identifier is never returned.
create or replace function public.search_community_reports(search_query text default '')
returns table (
  id uuid,
  identifier_type text,
  identifier_display text,
  report_type text,
  description text,
  report_count integer,
  created_at timestamptz
)
language sql
stable
security definer
set search_path = public
as $$
  select r.id, r.identifier_type, r.identifier_display, r.report_type, r.description, r.report_count, r.created_at
  from public.community_reports r
  where r.status = 'approved'
    and (
      coalesce(trim(search_query),'') = ''
      or r.identifier_hash = digest(lower(regexp_replace(search_query, '\s', '', 'g')), 'sha256')
      or r.identifier_display ilike '%' || search_query || '%'
      or r.report_type ilike '%' || search_query || '%'
    )
  order by r.created_at desc
  limit 30;
$$;

alter table public.profiles enable row level security;
alter table public.community_reports enable row level security;
alter table public.community_flags enable row level security;
alter table public.incident_records enable row level security;
alter table public.safety_agreements enable row level security;

revoke all on public.profiles, public.community_reports, public.community_flags, public.incident_records, public.safety_agreements from anon, authenticated;
grant select on public.profiles to authenticated;
grant select (id,identifier_type,identifier_display,report_type,description,status,report_count,created_at,reviewed_at,user_id) on public.community_reports to authenticated;
grant insert (user_id,identifier_type,identifier,identifier_display,report_type,description,incident_date,status) on public.community_reports to authenticated;
grant update (status,reviewed_at,report_count) on public.community_reports to authenticated;
grant select,insert on public.community_flags to authenticated;
grant select,insert,update,delete on public.incident_records to authenticated;
grant select,insert,update,delete on public.safety_agreements to authenticated;
grant execute on function public.search_community_reports(text) to anon, authenticated;
grant execute on function public.is_admin() to authenticated;

drop policy if exists "Profiles are visible to owner and admins" on public.profiles;
create policy "Profiles are visible to owner and admins" on public.profiles for select to authenticated
using (id = auth.uid() or public.is_admin());

drop policy if exists "Users see own reports and admins see all" on public.community_reports;
create policy "Users see own reports and admins see all" on public.community_reports for select to authenticated
using (user_id = auth.uid() or public.is_admin());

drop policy if exists "Users submit pending reports" on public.community_reports;
create policy "Users submit pending reports" on public.community_reports for insert to authenticated
with check (user_id = auth.uid() and status = 'pending');

drop policy if exists "Admins moderate reports" on public.community_reports;
create policy "Admins moderate reports" on public.community_reports for update to authenticated
using (public.is_admin()) with check (public.is_admin());

drop policy if exists "Users submit report flags" on public.community_flags;
create policy "Users submit report flags" on public.community_flags for insert to authenticated
with check (user_id = auth.uid());

drop policy if exists "Users see own flags and admins see all" on public.community_flags;
create policy "Users see own flags and admins see all" on public.community_flags for select to authenticated
using (user_id = auth.uid() or public.is_admin());

drop policy if exists "Users own incident records" on public.incident_records;
create policy "Users own incident records" on public.incident_records for all to authenticated
using (user_id = auth.uid()) with check (user_id = auth.uid());

drop policy if exists "Users own agreements" on public.safety_agreements;
create policy "Users own agreements" on public.safety_agreements for all to authenticated
using (owner_id = auth.uid()) with check (owner_id = auth.uid());

create index if not exists community_reports_status_created_idx on public.community_reports(status,created_at desc);
create index if not exists community_reports_hash_idx on public.community_reports(identifier_hash);
create index if not exists incident_records_user_idx on public.incident_records(user_id,happened_at desc);

-- After signing up your admin account, promote it once from the SQL Editor:
-- update public.profiles set role = 'admin' where id = (select id from auth.users where email = 'you@example.com');
