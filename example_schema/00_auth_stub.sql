-- ============================================================================
--  00_auth_stub.sql
-- ============================================================================
--  TEST-ONLY STUB. This file exists so that the policy set in policies.sql,
--  which is written exactly the way Supabase writes it (auth.uid(),
--  auth.role(), the anon / authenticated / service_role roles), can be
--  installed and exercised against a plain PostgreSQL server.
--
--  On Supabase you DO NOT run this file. Supabase already provides:
--    * schema auth, table auth.users
--    * auth.uid(), auth.role(), auth.jwt(), auth.email()
--    * roles anon, authenticated, service_role (service_role has BYPASSRLS)
--    * default privileges that GRANT to anon/authenticated on new tables
--
--  Running this file against Supabase would either be a no-op (every object
--  below is created with IF NOT EXISTS / CREATE OR REPLACE) or, for the role
--  creation, fail harmlessly if you lack CREATEROLE. It is written to be
--  idempotent so that re-running the whole example is safe.
--
--  Everything here is a faithful reproduction of the *behaviour* the policies
--  depend on, not of Supabase's internals. Nothing in this file is security
--  relevant to your own application: it is scaffolding for the test pack.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Roles. These mirror Supabase's three PostgREST-facing roles.
--   anon         - unauthenticated request (no JWT, or a JWT with role=anon)
--   authenticated- a request carrying a user JWT
--   service_role - the server-side key. BYPASSRLS, so RLS never applies to it.
-- ---------------------------------------------------------------------------
do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then
    create role anon nologin noinherit;
    raise notice 'created role anon';
  end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then
    create role authenticated nologin noinherit;
    raise notice 'created role authenticated';
  end if;
  if not exists (select 1 from pg_roles where rolname = 'service_role') then
    begin
      create role service_role nologin noinherit bypassrls;
      raise notice 'created role service_role (BYPASSRLS)';
    exception when insufficient_privilege then
      create role service_role nologin noinherit;
      raise warning
        'created service_role WITHOUT bypassrls: you are not a superuser. '
        'The "admin sees everything" assertions will not behave as documented.';
    end;
  end if;
end
$$;

-- ---------------------------------------------------------------------------
-- schema auth
-- ---------------------------------------------------------------------------
create schema if not exists auth;

-- Minimal stand-in for Supabase's auth.users. Only the columns the example
-- schema and seed data touch. Supabase's real table has ~30 columns and is
-- not something you should ever recreate.
create table if not exists auth.users (
  id          uuid primary key,
  email       text unique,
  created_at  timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- auth.uid() / auth.role() / auth.jwt()
--
-- Supabase reads these out of the request's GUCs, which PostgREST sets from
-- the verified JWT before it runs your query. The definitions below are the
-- same shape Supabase uses, including the legacy single-claim GUC
-- (request.jwt.claim.sub) that older PostgREST versions set.
--
-- The test runner sets these GUCs per identity with:
--   select set_config('request.jwt.claims', '{"sub":"<uuid>","role":"authenticated"}', false);
-- which is exactly what PostgREST does. current_setting(..., true) returns
-- NULL instead of raising when the GUC is unset, which is why anon requests
-- get NULL rather than an error.
-- ---------------------------------------------------------------------------
create or replace function auth.uid()
returns uuid
language sql
stable
as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim.sub', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')
  )::uuid
$$;

create or replace function auth.role()
returns text
language sql
stable
as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim.role', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'role')
  )
$$;

create or replace function auth.jwt()
returns jsonb
language sql
stable
as $$
  select coalesce(nullif(current_setting('request.jwt.claims', true), '')::jsonb, '{}'::jsonb)
$$;

create or replace function auth.email()
returns text
language sql
stable
as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim.email', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'email')
  )
$$;

grant usage on schema auth to anon, authenticated, service_role;
grant execute on function auth.uid(), auth.role(), auth.jwt(), auth.email()
  to anon, authenticated, service_role;

-- ---------------------------------------------------------------------------
-- Supabase-like default privileges.
--
-- Supabase grants anon/authenticated table privileges in the public schema by
-- default; that is precisely why "I forgot to enable RLS" is the number one
-- leak. Reproducing it here means the test pack's negative control behaves
-- like the real thing rather than like a locked-down server.
-- ---------------------------------------------------------------------------
grant usage on schema public to anon, authenticated, service_role;

alter default privileges in schema public
  grant select, insert, update, delete on tables to anon, authenticated, service_role;
alter default privileges in schema public
  grant usage, select on sequences to anon, authenticated, service_role;
alter default privileges in schema public
  grant execute on functions to anon, authenticated, service_role;
