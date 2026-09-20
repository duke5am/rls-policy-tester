-- ============================================================================
--  policies.sql  --  the CORRECT policy set for the example schema
-- ============================================================================
--  Every statement here is written the way you would write it in a real
--  Supabase migration. auth.uid() is used unmodified; nothing is adapted for
--  the local stub. If you run this file on Supabase, it installs unchanged.
--
--  Read this file top to bottom and the shape of a defensible policy set
--  emerges:
--
--    1. One helper layer (schema app) that answers "who is this user, in this
--       organisation?" Nothing else in the system re-implements that check.
--    2. RLS enabled on EVERY table. Not most tables. Every table.
--    3. One policy per (table, command). Never a "FOR ALL" policy that has to
--       be right about four different questions at once.
--    4. USING and WITH CHECK are different questions and are answered
--       separately. USING: which existing rows may this user touch?
--       WITH CHECK: what may the resulting row look like?
--    5. Both the tenant column (org_id) and the attribution columns
--       (created_by, user_id) are constrained.
-- ============================================================================


-- ###########################################################################
-- 1. AUTHORISATION HELPERS
-- ###########################################################################
-- These functions answer the only authorisation question the schema has. They
-- are SECURITY DEFINER so that looking up a membership does not itself have to
-- pass the memberships SELECT policy -- which would otherwise recurse.
--
-- Two hardening rules are applied to every function below, and both are load
-- bearing:
--
--   * `set search_path = ''` plus fully qualified names. A SECURITY DEFINER
--     function without a pinned search_path is a privilege escalation vector:
--     a caller who can create objects in a schema earlier on the search path
--     can shadow a function or operator the body relies on.
--
--   * EXECUTE is revoked from PUBLIC and granted explicitly. By default
--     PostgreSQL grants EXECUTE on new functions to PUBLIC.
--
-- SECURITY DEFINER means these functions run as their owner, and a table
-- owner is NOT subject to that table's RLS. That is exactly what we want for
-- a boolean membership lookup, and exactly what makes SECURITY DEFINER
-- dangerous when it returns ROWS instead of a boolean. See
-- docs/POLICY-PITFALLS.md, pitfall 5.
-- ###########################################################################

create schema if not exists app;

-- The helper schema is not part of the API surface. PostgREST only exposes
-- schemas you list in its config, and `app` is not one of them. Revoking
-- CREATE keeps callers from adding objects here.
revoke create on schema app from public;
grant usage on schema app to anon, authenticated, service_role;

-- Is p_user_id a member of p_org_id, in any role?
create or replace function app.is_org_member(p_org_id uuid, p_user_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
      from public.memberships m
     where m.org_id  = p_org_id
       and m.user_id = p_user_id
  )
$$;

-- Is p_user_id an owner or admin of p_org_id?
create or replace function app.is_org_admin(p_org_id uuid, p_user_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
      from public.memberships m
     where m.org_id  = p_org_id
       and m.user_id = p_user_id
       and m.role in ('owner', 'admin')
  )
$$;

-- Is p_user_id the owner of p_org_id?
create or replace function app.is_org_owner(p_org_id uuid, p_user_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
      from public.memberships m
     where m.org_id  = p_org_id
       and m.user_id = p_user_id
       and m.role = 'owner'
  )
$$;

-- Is p_project_id a project of p_org_id? Used by the tasks policies so that a
-- task cannot be attached to a project in a different tenant.
create or replace function app.project_belongs_to_org(p_project_id uuid, p_org_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
      from public.projects p
     where p.id     = p_project_id
       and p.org_id = p_org_id
  )
$$;

revoke all on function app.is_org_member(uuid, uuid)          from public;
revoke all on function app.is_org_admin(uuid, uuid)           from public;
revoke all on function app.is_org_owner(uuid, uuid)           from public;
revoke all on function app.project_belongs_to_org(uuid, uuid) from public;

grant execute on function app.is_org_member(uuid, uuid)          to anon, authenticated, service_role;
grant execute on function app.is_org_admin(uuid, uuid)           to anon, authenticated, service_role;
grant execute on function app.is_org_owner(uuid, uuid)           to anon, authenticated, service_role;
grant execute on function app.project_belongs_to_org(uuid, uuid) to anon, authenticated, service_role;


-- ###########################################################################
-- 2. ENABLE ROW LEVEL SECURITY ON EVERY TABLE
-- ###########################################################################
-- Note what this does NOT do: it does not grant anything. Enabling RLS with
-- zero policies is fail-closed: the table returns no rows to anyone except
-- its owner and superusers. The leak comes from the combination of RLS being
-- *off* and the anon/authenticated roles already holding table privileges,
-- which on Supabase they do by default.
alter table public.organisations  enable row level security;
alter table public.memberships    enable row level security;
alter table public.projects       enable row level security;
alter table public.tasks          enable row level security;

-- The negative-control tables stay exactly as schema.sql left them: one with
-- RLS off, one with a permissive policy. See section 7.


-- ###########################################################################
-- 3. organisations
-- ###########################################################################
-- A user reaches an organisation only through a membership. There is no
-- "public" organisation and no anon access at all, so no policy is created
-- for anon: RLS denies by default, which is what we want.
drop policy if exists organisations_select_member on public.organisations;
create policy organisations_select_member
  on public.organisations
  for select
  to authenticated
  using ( app.is_org_member(id, auth.uid()) );

-- NO INSERT POLICY ON organisations -- on purpose.
--
-- The obvious policy here is `with check (auth.uid() is not null)`: any signed
-- in user may create an organisation. It is not enough, because creating an
-- organisation that anybody can actually *use* requires a second insert -- the
-- owner's membership row -- and memberships only accepts inserts from an
-- existing admin of that organisation. A brand new organisation has none, so a
-- plain INSERT policy leaves you with an orphan organisation nobody can see.
--
-- The naive way out of that trap is to let users insert their own membership:
--
--     create policy memberships_insert_self on public.memberships
--       for insert to authenticated with check (user_id = auth.uid());
--
-- That is a privilege escalation. `user_id = auth.uid()` says "you may add
-- yourself" and says nothing about WHICH organisation -- so any authenticated
-- user can make themselves an owner of any organisation in the database.
-- Reproduced against a live server in docs/POLICY-PITFALLS.md, pitfall 9.
--
-- The correct answer is to make organisation creation a single atomic
-- operation owned by the server, and to keep the direct INSERT policies
-- closed. That is the function below. It is SECURITY DEFINER, which is what
-- lets it write the organisation and the owner membership in one transaction
-- without opening either table to the client -- and it checks auth.uid()
-- itself, which is the condition that makes SECURITY DEFINER safe here.

create or replace function public.create_organisation(p_name text, p_slug text)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user   uuid := auth.uid();
  v_org_id uuid;
begin
  if v_user is null then
    raise exception 'create_organisation: not authenticated'
      using errcode = '42501';
  end if;

  if p_name is null or length(btrim(p_name)) = 0 then
    raise exception 'create_organisation: name is required'
      using errcode = '22023';
  end if;

  insert into public.organisations (name, slug)
       values (btrim(p_name), btrim(p_slug))
    returning id into v_org_id;

  insert into public.memberships (org_id, user_id, role)
       values (v_org_id, v_user, 'owner');

  return v_org_id;
end
$$;

revoke all on function public.create_organisation(text, text) from public;
grant execute on function public.create_organisation(text, text)
  to anon, authenticated, service_role;

-- Only admins/owners may rename an organisation. USING picks the rows they
-- may touch; WITH CHECK confirms the row still belongs to an organisation
-- they administer after the update -- which stops an admin of org A from
-- rewriting a row so that it becomes org B's.
drop policy if exists organisations_update_admin on public.organisations;
create policy organisations_update_admin
  on public.organisations
  for update
  to authenticated
  using      ( app.is_org_admin(id, auth.uid()) )
  with check ( app.is_org_admin(id, auth.uid()) );

drop policy if exists organisations_delete_owner on public.organisations;
create policy organisations_delete_owner
  on public.organisations
  for delete
  to authenticated
  using ( app.is_org_owner(id, auth.uid()) );


-- ###########################################################################
-- 4. memberships
-- ###########################################################################
-- The authorisation table. Read access is deliberately narrow:
--   * you can always see your own membership rows, and
--   * admins of an organisation can see that organisation's roster.
-- Everything else is invisible.
drop policy if exists memberships_select_self_or_admin on public.memberships;
create policy memberships_select_self_or_admin
  on public.memberships
  for select
  to authenticated
  using (
        user_id = auth.uid()
     or app.is_org_admin(org_id, auth.uid())
  );

-- WHO MAY ADD A MEMBER.
--
-- Only an existing admin or owner of that organisation. Note what is NOT here:
-- `user_id = auth.uid()`. The self-service "accept my invitation" path is
-- deliberately not expressible as an RLS policy, because "user_id = <me>"
-- constrains who the row is about and says nothing about which organisation it
-- is in -- so it lets any authenticated user grant themselves ownership of any
-- organisation. Verified against a live server: docs/POLICY-PITFALLS.md,
-- pitfall 9.
--
-- If you need self-service invites, do it the way public.create_organisation()
-- does it: a SECURITY DEFINER RPC that takes an invitation token, validates it
-- server-side, and performs the insert itself. The token check is application
-- logic; the policy stays closed.
drop policy if exists memberships_insert_self_or_admin on public.memberships;
drop policy if exists memberships_insert_admin on public.memberships;
create policy memberships_insert_admin
  on public.memberships
  for insert
  to authenticated
  with check ( app.is_org_admin(org_id, auth.uid()) );

-- Role changes require admin rights on that organisation, both before and
-- after. Without the WITH CHECK half, an admin could promote themselves in an
-- organisation they do not administer by moving the row.
drop policy if exists memberships_update_admin on public.memberships;
create policy memberships_update_admin
  on public.memberships
  for update
  to authenticated
  using      ( app.is_org_admin(org_id, auth.uid()) )
  with check ( app.is_org_admin(org_id, auth.uid()) );

-- You may remove yourself (leave). Admins may remove anyone. Owners may not be
-- removed by an admin -- that rule is left to application logic rather than
-- encoded here, because expressing "the last owner cannot be removed" in RLS
-- requires a subquery over the same table.
drop policy if exists memberships_delete_self_or_admin on public.memberships;
create policy memberships_delete_self_or_admin
  on public.memberships
  for delete
  to authenticated
  using (
        user_id = auth.uid()
     or app.is_org_admin(org_id, auth.uid())
  );


-- ###########################################################################
-- 5. projects
-- ###########################################################################
drop policy if exists projects_select_member on public.projects;
create policy projects_select_member
  on public.projects
  for select
  to authenticated
  using ( app.is_org_member(org_id, auth.uid()) );

-- THE WITH CHECK LESSON.
--
-- `app.is_org_member(org_id, auth.uid())` alone answers "is this user allowed
-- to write into this tenant?". It does NOT answer "may this user claim to be
-- the author of this row?". Without `created_by = auth.uid()`, alice can
-- insert a project inside her own organisation attributed to carol -- or, in
-- a schema where created_by drives notifications or permissions, attributed
-- to anybody at all. The row passes every tenant check and is still a lie.
drop policy if exists projects_insert_member on public.projects;
create policy projects_insert_member
  on public.projects
  for insert
  to authenticated
  with check (
        app.is_org_member(org_id, auth.uid())
    and created_by = auth.uid()
  );

-- Members may edit projects in their organisation. The check half pins org_id
-- as well: a member of two organisations must not be able to move a project
-- out of one and into the other (which would drag every task with it in a
-- cascading update), and must not be able to reassign authorship.
drop policy if exists projects_update_member on public.projects;
create policy projects_update_member
  on public.projects
  for update
  to authenticated
  using      ( app.is_org_member(org_id, auth.uid()) )
  with check (
        app.is_org_member(org_id, auth.uid())
    and created_by = auth.uid()
  );

drop policy if exists projects_delete_admin on public.projects;
create policy projects_delete_admin
  on public.projects
  for delete
  to authenticated
  using ( app.is_org_admin(org_id, auth.uid()) );


-- ###########################################################################
-- 6. tasks  --  the child table
-- ###########################################################################
-- Every clause below is required, and each one closes a distinct hole:
--
--   app.is_org_member(org_id, auth.uid())        tenant isolation
--   created_by = auth.uid()                      attribution / spoofing
--   app.project_belongs_to_org(project_id, org_id)
--                                                cross-field integrity: a task
--                                                must not point at a project
--                                                in another tenant
--
-- Drop any one of them and the suite has a failing check that names it.
drop policy if exists tasks_select_member on public.tasks;
create policy tasks_select_member
  on public.tasks
  for select
  to authenticated
  using ( app.is_org_member(org_id, auth.uid()) );

drop policy if exists tasks_insert_member on public.tasks;
create policy tasks_insert_member
  on public.tasks
  for insert
  to authenticated
  with check (
        app.is_org_member(org_id, auth.uid())
    and created_by = auth.uid()
    and app.project_belongs_to_org(project_id, org_id)
  );

drop policy if exists tasks_update_member on public.tasks;
create policy tasks_update_member
  on public.tasks
  for update
  to authenticated
  using      ( app.is_org_member(org_id, auth.uid()) )
  with check (
        app.is_org_member(org_id, auth.uid())
    and created_by = auth.uid()
    and app.project_belongs_to_org(project_id, org_id)
  );

drop policy if exists tasks_delete_admin on public.tasks;
create policy tasks_delete_admin
  on public.tasks
  for delete
  to authenticated
  using ( app.is_org_admin(org_id, auth.uid()) );


-- ###########################################################################
-- 7. the negative-control tables -- INTENTIONALLY BROKEN
-- ###########################################################################
-- These two tables exist so the pack can prove, on a real server, that the
-- suite fails when it is pointed at a table that is not protected. If you
-- point `rls_test_runner.py` at your own database, delete this section, or
-- simply never reference these tables -- the suite only tests the tables a
-- definition file names.

-- Leak 1: RLS was never enabled. Handled in schema.sql by simply not enabling
--          it. The default privileges from 00_auth_stub.sql mean anon and
--          authenticated already hold SELECT, so every row is readable.
comment on table public.demo_open_no_rls is
  'NEGATIVE CONTROL: RLS is deliberately NOT enabled. Every deny check against this table must FAIL.';

-- Leak 2: RLS enabled, but a permissive policy left over from development.
alter table public.demo_open_using_true enable row level security;

drop policy if exists demo_open_using_true_permissive on public.demo_open_using_true;
create policy demo_open_using_true_permissive
  on public.demo_open_using_true
  for all
  to authenticated
  using (true)
  with check (true);

comment on table public.demo_open_using_true is
  'NEGATIVE CONTROL: RLS enabled but the only policy is USING (true). Every deny check against this table must FAIL.';


-- ###########################################################################
-- 8. ON `FORCE ROW LEVEL SECURITY` -- read this before you add it
-- ###########################################################################
--
-- By default a table's OWNER bypasses that table's RLS. `FORCE ROW LEVEL
-- SECURITY` removes that exemption -- but only for the owner, and only when the
-- owner is not a superuser. Both halves were measured on the live PostgreSQL
-- 17.11 server this pack was built against, and both matter:
--
--   * Superuser owner (the Supabase case). `postgres` owns the tables and is a
--     superuser, and a superuser bypasses RLS unconditionally. FORCE changes
--     nothing at all. Measured: `alter table memberships force row level
--     security` on the shipped schema, then queried as the authenticated
--     alice -- 1 organisation, 3 tasks, 2 memberships, exactly as before.
--
--   * Non-superuser owner. FORCE takes effect, and it takes effect on the
--     owner's own queries. If your SECURITY DEFINER helpers are owned by that
--     same role, they become subject to the policies of the tables they read.
--     Measured on a schema with a non-superuser owner: after FORCE on the
--     membership table, every policy that called the membership helper started
--     returning FALSE. No error was raised. The application simply showed
--     every user an empty database.
--
-- That second case is the one to be careful about, and the danger is silence
-- rather than a crash. It is not the same failure as the recursion error,
-- which has a different cause entirely -- a policy that reads its own table:
--
--     -- WRONG: the policy on memberships reads memberships
--     create policy memberships_select on public.memberships
--       for select to authenticated
--       using (exists (select 1 from public.memberships m
--                       where m.org_id = memberships.org_id
--                         and m.user_id = auth.uid()));
--
--     ERROR: infinite recursion detected in policy for relation "memberships"
--     SQLSTATE 42P17
--
-- Routing that same self-reference through a SECURITY INVOKER function gives a
-- different and less helpful error -- `stack depth limit exceeded`,
-- SQLSTATE 54001. Routing it through a SECURITY DEFINER function owned by a
-- superuser is what makes it work, and that is precisely why Supabase's own
-- documentation recommends a SECURITY DEFINER helper for this lookup. The
-- helpers in section 1 follow that pattern.
--
-- So: FORCE is worth turning on for a table whose owner is a NON-superuser role
-- that your application also connects as, because that owner would otherwise
-- read every tenant's rows while believing RLS was protecting it. If you use
-- it, give the owner policies of its own -- once FORCE is set, an owner with no
-- applicable policy sees ZERO rows, measured on the same server -- and keep the
-- helper table out of it if the helpers are owned by that role:
--
--     alter table public.projects force row level security;
--     alter table public.tasks    force row level security;
--     -- leave public.memberships alone if the membership helpers are owned by
--     -- the same role, or they will silently start answering FALSE.
--
-- The runner reports the owner and the FORCE flag of every table it preflights,
-- so you can see which of these two situations you are in.
