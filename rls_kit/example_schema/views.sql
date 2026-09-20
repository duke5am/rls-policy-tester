-- ============================================================================
--  views.sql  --  one safe view, one deliberately unsafe view, one leaky RPC
-- ============================================================================
--  A view is the second-most-common RLS bypass after forgetting to enable RLS,
--  because a view looks like a read-only convenience and is not.
--
--  A view has no policies. When you select from it, PostgreSQL checks
--  privileges against the view's OWNER, not you. The view owner is typically
--  the same role that owns the tables underneath -- and a table owner is not
--  subject to that table's Row Level Security unless the table is declared
--  FORCE ROW LEVEL SECURITY (which most are not, including on Supabase, where
--  the owner is also a superuser and FORCE would not help anyway).
--
--  So: `select * from public.some_view` can return every tenant's rows even
--  though `select * from public.some_table` correctly returns one tenant's.
--  The developer who added the view did not change any policy. Nothing warned
--  them.
--
--  PostgreSQL 15 added the fix:  WITH (security_invoker = on)
--  which makes the view execute with the caller's privileges, so the RLS of
--  the base tables applies exactly as it would without the view.
--
--  Both views below are identical except for that one option. The test suite
--  asserts the difference, as a user, from the outside.
-- ============================================================================


-- ###########################################################################
-- SAFE: security_invoker = on
-- ###########################################################################
-- Reads through public.tasks as the CALLER, so tasks' SELECT policy applies
-- and each user sees only their own organisations' counts.
--
-- Note the subtlety an aggregate view introduces: with security_invoker OFF
-- this view would not merely expose rows, it would expose a *count* of every
-- tenant's tasks -- which is easy to mistake for harmless metadata. It is not
-- metadata. It is a number derived from rows you are not allowed to read, and
-- in a real product it is a competitor's usage figure.
create or replace view public.org_task_counts
with (security_invoker = on)
as
select t.org_id,
       count(*)::bigint as task_count
  from public.tasks t
 group by t.org_id;

comment on view public.org_task_counts is
  'Task counts per organisation. security_invoker = on, so RLS of public.tasks applies to the caller.';


-- ###########################################################################
-- NEGATIVE CONTROL: the same view with security_invoker left off
-- ###########################################################################
-- This is not part of the example application. It exists so the pack can
-- demonstrate the leak from the outside, as a user, with output.
--
-- Do not copy this view. The fix is one line:
--     ALTER VIEW public.demo_open_view SET (security_invoker = on);
create or replace view public.demo_open_view
as
select t.id, t.org_id, t.title, t.created_by
  from public.tasks t;

comment on view public.demo_open_view is
  'NEGATIVE CONTROL: no security_invoker, so this view runs as its owner and returns every tenant''s tasks. Every deny check against it must FAIL.';


-- ###########################################################################
-- NEGATIVE CONTROL: a SECURITY DEFINER function that returns rows
-- ###########################################################################
-- Same root cause, different object. SECURITY DEFINER is the right tool for a
-- boolean helper like app.is_org_member(): it cannot leak rows because it
-- returns one bit. Applied to anything that returns a set, it runs as the
-- owner -- who bypasses RLS -- and hands back the whole table.
--
-- This is the shape of a Supabase RPC. `create function ... returns setof`
-- with SECURITY DEFINER (or a .sql file that ran as postgres) produces an
-- endpoint that ignores every policy you wrote.
create or replace function public.demo_open_rpc()
returns setof public.tasks
language sql
stable
security definer
set search_path = ''
as $$
  select * from public.tasks
$$;

comment on function public.demo_open_rpc() is
  'NEGATIVE CONTROL: SECURITY DEFINER returning setof, so it bypasses RLS on public.tasks. Every deny check against it must FAIL.';

-- The safe counterpart, for contrast: SECURITY INVOKER.
create or replace function public.my_tasks()
returns setof public.tasks
language sql
stable
security invoker
set search_path = ''
as $$
  select * from public.tasks
$$;

comment on function public.my_tasks() is
  'SECURITY INVOKER, so RLS of public.tasks applies to the caller. The correct shape for an RPC that returns rows.';


-- ###########################################################################
-- Grants
-- ###########################################################################
revoke all on function public.demo_open_rpc() from public;
revoke all on function public.my_tasks()      from public;
grant execute on function public.demo_open_rpc() to anon, authenticated, service_role;
grant execute on function public.my_tasks()      to anon, authenticated, service_role;

grant select on public.org_task_counts to anon, authenticated, service_role;
grant select on public.demo_open_view  to anon, authenticated, service_role;
