-- ============================================================================
--  seed.sql  --  deterministic fixture data
-- ============================================================================
--  Every identifier is a fixed UUID, so the declarative definitions in
--  tests_definitions/ can name them. Nothing here is random.
--
--  The cast, and what each one is for:
--
--    Acme Corp (org A)     alice  owner
--                          carol  member
--    Globex    (org B)     bob    owner
--
--    dave                  authenticated, member of NOTHING
--
--  dave exists on purpose. "A user who belongs to no organisation sees zero
--  rows" is a different assertion from "alice cannot see org B", and it is the
--  one that catches a policy written as `using (auth.uid() is not null)`.
--
--  Row counts the definitions assert against (computed as service_role, which
--  bypasses RLS):
--
--    organisations   2   (Acme, Globex)
--    memberships     3   (alice@Acme, carol@Acme, bob@Globex)
--    projects        3   (p1, p3 in Acme; p2 in Globex)
--    tasks           4   (t1, t2 in p1; t4 in p3; t3 in p2)
--
--  This file is written to be re-runnable: it clears the data it owns first.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Identities
-- ---------------------------------------------------------------------------
insert into auth.users (id, email) values
  ('a1ce0000-0000-4000-8000-00000000000a', 'alice@acme.example'),
  ('b0b00000-0000-4000-8000-00000000000b', 'bob@globex.example'),
  ('ca001000-0000-4000-8000-00000000000c', 'carol@acme.example'),
  ('da7e0000-0000-4000-8000-00000000000d', 'dave@nowhere.example')
on conflict (id) do nothing;

-- ---------------------------------------------------------------------------
-- Clear (children first; the FKs would cascade anyway, but be explicit)
-- ---------------------------------------------------------------------------
delete from public.tasks;
delete from public.projects;
delete from public.memberships;
delete from public.organisations;
delete from public.demo_open_no_rls;
delete from public.demo_open_using_true;

-- ---------------------------------------------------------------------------
-- Organisations
-- ---------------------------------------------------------------------------
insert into public.organisations (id, name, slug) values
  ('a0000000-0000-4000-8000-000000000001', 'Acme Corp', 'acme'),
  ('b0000000-0000-4000-8000-000000000002', 'Globex',    'globex');

-- ---------------------------------------------------------------------------
-- Memberships
--
--   org_a + alice -> owner      (alice may administer Acme)
--   org_a + carol -> member     (carol sees Acme, may not administer it)
--   org_b + bob   -> owner      (bob is a stranger to Acme)
--
-- The alice/carol pair is what lets the suite distinguish "sees own
-- membership rows" from "sees the roster of an organisation I administer".
-- ---------------------------------------------------------------------------
insert into public.memberships (id, org_id, user_id, role) values
  ('c0000000-0000-4000-8000-000000000001', 'a0000000-0000-4000-8000-000000000001', 'a1ce0000-0000-4000-8000-00000000000a', 'owner'),
  ('c0000000-0000-4000-8000-000000000002', 'a0000000-0000-4000-8000-000000000001', 'ca001000-0000-4000-8000-00000000000c', 'member'),
  ('c0000000-0000-4000-8000-000000000003', 'b0000000-0000-4000-8000-000000000002', 'b0b00000-0000-4000-8000-00000000000b', 'owner');

-- ---------------------------------------------------------------------------
-- Projects
-- ---------------------------------------------------------------------------
insert into public.projects (id, org_id, name, created_by) values
  ('90000000-0000-4000-8000-000000000001', 'a0000000-0000-4000-8000-000000000001', 'Acme Website', 'a1ce0000-0000-4000-8000-00000000000a'),
  ('90000000-0000-4000-8000-000000000002', 'b0000000-0000-4000-8000-000000000002', 'Globex CRM',   'b0b00000-0000-4000-8000-00000000000b'),
  ('90000000-0000-4000-8000-000000000003', 'a0000000-0000-4000-8000-000000000001', 'Acme Mobile',  'ca001000-0000-4000-8000-00000000000c');

-- ---------------------------------------------------------------------------
-- Tasks
--
--   t1, t2 are in project p1 (Acme), created by alice
--   t4       is in project p3 (Acme), created by carol
--   t3       is in project p2 (Globex), created by bob
--
-- alice and carol are both members of Acme, so both see all three Acme tasks
-- (t1, t2, t4) while seeing none of Globex's. That is tenant isolation as it
-- is meant to work: membership of the tenant, not authorship of the row, is
-- the read boundary. Authorship is what WITH CHECK protects.
-- ---------------------------------------------------------------------------
insert into public.tasks (id, org_id, project_id, title, created_by, assigned_to) values
  ('70000000-0000-4000-8000-000000000001', 'a0000000-0000-4000-8000-000000000001', '90000000-0000-4000-8000-000000000001', 'Ship the marketing page',   'a1ce0000-0000-4000-8000-00000000000a', 'a1ce0000-0000-4000-8000-00000000000a'),
  ('70000000-0000-4000-8000-000000000002', 'a0000000-0000-4000-8000-000000000001', '90000000-0000-4000-8000-000000000001', 'Write the pricing copy',     'a1ce0000-0000-4000-8000-00000000000a', 'ca001000-0000-4000-8000-00000000000c'),
  ('70000000-0000-4000-8000-000000000003', 'b0000000-0000-4000-8000-000000000002', '90000000-0000-4000-8000-000000000002', 'Migrate the Globex pipeline','b0b00000-0000-4000-8000-00000000000b', 'b0b00000-0000-4000-8000-00000000000b'),
  ('70000000-0000-4000-8000-000000000004', 'a0000000-0000-4000-8000-000000000001', '90000000-0000-4000-8000-000000000003', 'Cut the 2.0 mobile build',  'ca001000-0000-4000-8000-00000000000c', 'a1ce0000-0000-4000-8000-00000000000a');

-- ---------------------------------------------------------------------------
-- Negative-control data.
--
-- Identical in shape to a task, so the assertions written against it are the
-- same assertions the suite runs against tasks -- the only difference is that
-- the table is not protected. That is the point: the suite must fail here
-- while passing on tasks.
-- ---------------------------------------------------------------------------
insert into public.demo_open_no_rls (id, org_id, title, created_by) values
  ('0e000000-0000-4000-8000-000000000001', 'a0000000-0000-4000-8000-000000000001', 'Acme secret (unprotected)', 'a1ce0000-0000-4000-8000-00000000000a'),
  ('0e000000-0000-4000-8000-000000000002', 'b0000000-0000-4000-8000-000000000002', 'Globex secret (unprotected)', 'b0b00000-0000-4000-8000-00000000000b');

insert into public.demo_open_using_true (id, org_id, title, created_by) values
  ('0f000000-0000-4000-8000-000000000001', 'a0000000-0000-4000-8000-000000000001', 'Acme secret (using true)', 'a1ce0000-0000-4000-8000-00000000000a'),
  ('0f000000-0000-4000-8000-000000000002', 'b0000000-0000-4000-8000-000000000002', 'Globex secret (using true)', 'b0b00000-0000-4000-8000-00000000000b');

-- ---------------------------------------------------------------------------
-- Grants. Supabase's default privileges (reproduced in 00_auth_stub.sql)
-- already cover tables created after that file ran; these make the example
-- work even if you ran the files in a different order.
-- ---------------------------------------------------------------------------
grant usage on schema public to anon, authenticated, service_role;
grant select, insert, update, delete on all tables in schema public to anon, authenticated, service_role;
grant usage, select on all sequences in schema public to anon, authenticated, service_role;
