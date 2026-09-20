-- ============================================================================
--  schema.sql  --  tables for the multi-tenant example
-- ============================================================================
--  A realistic organisation / team model, the shape almost every SaaS starts
--  with:
--
--      organisations  -- the tenant boundary
--      memberships    -- which user belongs to which organisation, and as what
--      projects       -- owned by an organisation, created by a user
--      tasks          -- belong to a project, belong to an organisation,
--                        created by a user, optionally assigned to a user
--
--  Two independent facts are stored about every row, and they are easy to
--  confuse:
--
--    * WHICH TENANT the row belongs to          (org_id)
--    * WHO CREATED / OWNS the row               (created_by, assigned_to,
--                                                memberships.user_id)
--
--  Row Level Security has to get both right. A policy that only checks the
--  tenant lets one colleague forge rows attributed to another. A policy that
--  only checks the creator lets a user pull their own row into somebody
--  else's tenant. This schema gives you a column for each so the test suite
--  can tell the two failure modes apart.
--
--  The organisation id is denormalised onto tasks (alongside project_id) on
--  purpose: it is the single most common shape in real multi-tenant schemas,
--  because it lets a policy decide without a join. It also creates a real
--  integrity hazard -- tasks.org_id and projects.org_id can disagree -- which
--  the WITH CHECK clause in policies.sql closes.
--
--  Run order:
--      00_auth_stub.sql   (test-only scaffolding)
--      schema.sql         (this file)
--      policies.sql
--      seed.sql
-- ============================================================================

-- gen_random_uuid() is built into PostgreSQL 13+ (no pgcrypto extension
-- needed). Supabase runs 15+, so this is safe there.

-- ---------------------------------------------------------------------------
-- organisations -- the tenant
-- ---------------------------------------------------------------------------
create table if not exists public.organisations (
  id          uuid primary key default gen_random_uuid(),
  name        text        not null,
  slug        text        not null unique,
  created_at  timestamptz not null default now(),
  constraint organisations_name_not_blank check (length(btrim(name)) > 0)
);

comment on table public.organisations is
  'Tenant boundary. A user may reach this row only through a membership.';

-- ---------------------------------------------------------------------------
-- memberships -- the authorisation table
--
-- Every other policy in this pack ultimately resolves to a lookup in here.
-- Two consequences follow, and both matter:
--
--   1. memberships is the most security-critical table in the system. If its
--      own policies are wrong, every policy that depends on it is wrong too.
--
--   2. It is the hot path. (user_id, org_id) needs an index or every single
--      row a user reads pays for a sequential scan. See the index below and
--      docs/WRITING-POLICIES.md.
-- ---------------------------------------------------------------------------
create table if not exists public.memberships (
  id          uuid primary key default gen_random_uuid(),
  org_id      uuid        not null references public.organisations(id) on delete cascade,
  user_id     uuid        not null,
  role        text        not null default 'member',
  created_at  timestamptz not null default now(),
  constraint memberships_role_valid check (role in ('owner', 'admin', 'member')),
  constraint memberships_unique_user_per_org unique (org_id, user_id)
);

comment on table public.memberships is
  'Which user belongs to which organisation, and with what role.';

-- The index the policies read through. Lead with user_id: the overwhelmingly
-- common lookup is "the organisations of the current user".
create index if not exists memberships_user_id_org_id_idx
  on public.memberships (user_id, org_id);
-- Reverse direction, for "who is in this organisation" and for admin checks.
create index if not exists memberships_org_id_user_id_idx
  on public.memberships (org_id, user_id);

-- ---------------------------------------------------------------------------
-- projects
-- ---------------------------------------------------------------------------
create table if not exists public.projects (
  id          uuid primary key default gen_random_uuid(),
  org_id      uuid        not null references public.organisations(id) on delete cascade,
  name        text        not null,
  created_by  uuid        not null,
  created_at  timestamptz not null default now(),
  constraint projects_name_not_blank check (length(btrim(name)) > 0)
);

create index if not exists projects_org_id_idx on public.projects (org_id);

-- ---------------------------------------------------------------------------
-- tasks -- the child table
--
-- This is the table that exposes join leaks. A query that reads tasks without
-- going through projects is the most common way an application leaks rows:
-- the developer writes the project policy carefully, ships, and never
-- notices that tasks has no policy of its own.
-- ---------------------------------------------------------------------------
create table if not exists public.tasks (
  id          uuid primary key default gen_random_uuid(),
  org_id      uuid        not null references public.organisations(id) on delete cascade,
  project_id  uuid        not null references public.projects(id) on delete cascade,
  title       text        not null,
  created_by  uuid        not null,
  assigned_to uuid,
  created_at  timestamptz not null default now(),
  constraint tasks_title_not_blank check (length(btrim(title)) > 0)
);

create index if not exists tasks_org_id_idx     on public.tasks (org_id);
create index if not exists tasks_project_id_idx on public.tasks (project_id);
create index if not exists tasks_assigned_to_idx on public.tasks (assigned_to);

-- ---------------------------------------------------------------------------
-- A deliberately UNPROTECTED pair, used by the negative-control definitions.
--
-- These are not part of the example application. They exist so the pack can
-- demonstrate -- with output, on a real database -- that the test suite FAILS
-- when it is pointed at a table that is not actually protected:
--
--   demo_open_no_rls    RLS was never enabled. The single most common leak.
--   demo_open_using_true  RLS enabled, but with a permissive USING (true)
--                         policy left over from development.
--
-- If your own suite ever reports these as PASSING, the suite is broken, not
-- your database. See tests_definitions/03_negative_controls_*.json.
-- ---------------------------------------------------------------------------
create table if not exists public.demo_open_no_rls (
  id          uuid primary key default gen_random_uuid(),
  org_id      uuid        not null,
  title       text        not null,
  created_by  uuid        not null
);

create table if not exists public.demo_open_using_true (
  id          uuid primary key default gen_random_uuid(),
  org_id      uuid        not null,
  title       text        not null,
  created_by  uuid        not null
);
