-- VigilPay schema. Run in the Supabase SQL Editor. Stores outcomes only, never what users type.

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text,
  avatar_url text,
  created_at timestamptz not null default now()
);

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, display_name, avatar_url)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'full_name', new.raw_user_meta_data->>'name', split_part(new.email, '@', 1)),
    new.raw_user_meta_data->>'avatar_url'
  )
  on conflict (id) do nothing;
  return new;
end $$;

revoke execute on function public.handle_new_user() from public, anon, authenticated;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

create table if not exists public.checks (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users(id) on delete set null,
  scenario_id text,
  level text not null check (level in ('scam','caution','safe')),
  risk int not null check (risk between 0 and 100),
  ai_used boolean not null default false,
  created_at timestamptz not null default now()
);
create index if not exists checks_user_idx on public.checks (user_id, created_at desc);

create table if not exists public.quiz_results (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users(id) on delete set null,
  alias text not null default 'Guest',            -- first name or 'User 1', never a phone number
  phase text not null check (phase in ('before','after','practice')),
  score int not null,
  total int not null check (total > 0),
  created_at timestamptz not null default now(),
  check (score between 0 and total)
);

alter table public.profiles     enable row level security;
alter table public.checks       enable row level security;
alter table public.quiz_results enable row level security;

drop policy if exists "own profile read"   on public.profiles;
drop policy if exists "own profile update" on public.profiles;
drop policy if exists "own checks read"    on public.checks;
drop policy if exists "own quiz read"      on public.quiz_results;

create policy "own profile read"   on public.profiles     for select using ((select auth.uid()) = id);
create policy "own profile update" on public.profiles     for update using ((select auth.uid()) = id);
create policy "own checks read"    on public.checks       for select using ((select auth.uid()) = user_id);
create policy "own quiz read"      on public.quiz_results for select using ((select auth.uid()) = user_id);

create or replace function public.vigilpay_stats()
returns json language sql security definer set search_path = public as $$
  with b as (
    select alias, avg(score::float / total) as s from quiz_results where phase = 'before' group by alias
  ), a as (
    select alias, avg(score::float / total) as s from quiz_results where phase = 'after' group by alias
  ), pair as (
    select b.s as bs, a.s as as_ from b join a using (alias)
  )
  select json_build_object(
    'live', true,
    'total_checks', (select count(*) from checks),
    'scams',   (select count(*) from checks where level = 'scam'),
    'caution', (select count(*) from checks where level = 'caution'),
    'safe',    (select count(*) from checks where level = 'safe'),
    'top', coalesce((select json_agg(t) from (
        select scenario_id, count(*) as n from checks
        where scenario_id is not null group by scenario_id order by n desc limit 5) t), '[]'::json),
    'before_avg', (select round((avg(s) * 100)::numeric, 0) from b),
    'after_avg',  (select round((avg(s) * 100)::numeric, 0) from a),
    'testers',    (select count(*) from pair),
    'improved',   (select count(*) from pair where as_ > bs)
  );
$$;

create or replace function public.log_check(p_scenario text, p_level text, p_risk int, p_ai boolean)
returns void language plpgsql security definer set search_path = public as $$
begin
  if p_level not in ('scam','caution','safe') or p_risk < 0 or p_risk > 100 then
    raise exception 'invalid check';
  end if;
  insert into checks (user_id, scenario_id, level, risk, ai_used)
  values (auth.uid(), left(p_scenario, 40), p_level, p_risk, coalesce(p_ai, false));
end $$;

create or replace function public.save_quiz(p_alias text, p_phase text, p_score int, p_total int)
returns void language plpgsql security definer set search_path = public as $$
begin
  if p_phase not in ('before','after','practice') or p_total < 1 or p_total > 50 or p_score < 0 or p_score > p_total then
    raise exception 'invalid quiz result';
  end if;
  insert into quiz_results (user_id, alias, phase, score, total)
  values (auth.uid(), coalesce(nullif(left(regexp_replace(p_alias, '[^A-Za-z0-9 ]', '', 'g'), 24), ''), 'Guest'), p_phase, p_score, p_total);
end $$;

create or replace function public.my_history()
returns table (scenario_id text, level text, risk int, created_at timestamptz)
language sql security definer set search_path = public as $$
  select scenario_id, level, risk, created_at from checks
  where user_id = auth.uid() order by created_at desc limit 20;
$$;

revoke all on function public.log_check(text,text,int,boolean) from public, anon, authenticated;
revoke all on function public.save_quiz(text,text,int,int)     from public, anon, authenticated;
revoke all on function public.my_history()                     from public, anon, authenticated;
revoke all on function public.vigilpay_stats()                 from public, anon, authenticated;
grant execute on function public.log_check(text,text,int,boolean) to anon, authenticated;
grant execute on function public.save_quiz(text,text,int,int)     to anon, authenticated;
grant execute on function public.my_history()                     to authenticated;
grant execute on function public.vigilpay_stats()                 to anon, authenticated;
