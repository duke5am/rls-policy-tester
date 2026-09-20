# rls-policy-tester

[![PyPI](https://img.shields.io/pypi/v/rls-policy-tester)](https://pypi.org/project/rls-policy-tester/)

Prove that user A cannot read user B's rows — **and prove the test would catch it
if they could.**

Row Level Security fails silently. A missing policy or a stray `USING (true)`
does not throw an error; your app works perfectly while every row is readable by
everyone. There is no compiler for this, and it is the classic way to leak an
entire table.

```bash
pip install rls-policy-tester          # from PyPI, Python 3.9+
rls-policy-tester --dsn "host=localhost dbname=mydb user=postgres"

# or straight from a clone, no install:
python3 rls_test_runner.py --dsn "host=localhost dbname=mydb user=postgres" \
    --include-controls
```

## Why the negative controls are the point

Most "RLS test" snippets you will find assert that Alice sees her own rows. They
pass on a table with **RLS switched off entirely** — because Alice still sees her
own rows. They prove nothing.

So this ships with control suites that are *supposed to fail*. Running them
against a deliberately unprotected table:

```
6 passed 8 failed 1 warn   (15 fact(s) and check(s) total)
RESULT: DETECTED -- this is a negative control and the suite correctly reported
        the problem (exit 0)
```

and the failures name the leak and explain it:

```
FAIL  control.alice.cannot_delete_bob_row          as alice   deny (1 row(s) affected)
      LEAK: this identity was allowed to modify 1 row(s) belonging to another tenant.
      why : MUST FAIL. Rolled back.
      sql : delete from public.demo_open_using_true where org_id = 'b0000000-...'
      AFFECTED ROWS: this identity modified 1 row(s) that the policy should have
      refused. The transaction was rolled back, so the database here is unchanged
      -- in production it would not have been.
```

Note the sanity checks that make the zeros meaningful — *"verified non-vacuous:
as admin the same statement returns 2 row(s)"*. A `deny` result is worthless if
the table is empty or the role is broken.

## What it tests

- an anonymous connection cannot read rows it should not
- **user A cannot read, UPDATE or DELETE user B's rows**
- **user A cannot INSERT a row attributed to user B** — the `WITH CHECK` case, and
  the most commonly missing policy
- a service role *can* read everything, so your deny tests are not vacuous
- the same holds through **views and SECURITY DEFINER functions**, not just a
  plain `SELECT` — joining through a view is a real bypass
- applied inside a transaction that is rolled back, so a control run never
  damages the database

## Features that make it usable

- **Test definitions are JSON**, so you add cases without writing Python.
- `--audit-schema public` walks your catalogs and flags tables with **RLS
  disabled** and policies that are `PERMISSIVE_TRUE` / `WIDE_OPEN` — it reads
  `pg_policies`, so it catches a policy nobody reviewed.
- `--json` for CI, `--only` to run one suite.
- Exit codes: `0` pass, `1` real failure, `2` the detector itself is broken
  (a control that was expected to fail and did not), `3` setup error.

## Getting started

Use the included stub to try it end to end; it creates the three roles Supabase
uses (`anon`, `authenticated`, `service_role`) and an `auth.uid()` that reads a
session setting, exactly as Supabase does:

```bash
createdb rls_demo
psql rls_demo -f rls_kit/example_schema/00_auth_stub.sql
psql rls_demo -f rls_kit/example_schema/schema.sql
psql rls_demo -f rls_kit/example_schema/policies.sql
psql rls_demo -f rls_kit/example_schema/views.sql
psql rls_demo -f rls_kit/example_schema/seed.sql

python3 rls_test_runner.py --dsn "host=localhost dbname=rls_demo user=postgres" \
    --file rls_kit/tests_definitions/91_negative_control_using_true.json
```

The definition files and the example schema live inside the `rls_kit/` package
because the installed tool loads them from there — the same two files are what
`rls-policy-tester --include-controls` runs with no `--file` at all, and what the
`setup:` keys in a definition resolve against. After `pip install`, type
`python3 -c "import rls_kit, os; print(os.path.dirname(rls_kit.__file__))"` to
find the installed copy.

Then point it at your own database:

```bash
rls-policy-tester --dsn "$DATABASE_URL" --audit-schema public
```

**Use the direct connection string, not a transaction pooler** — `SET ROLE` and
session settings are session state.

## What this is not

- It is **not a security audit**. It tests the policies you write, against the
  identities you define. It has no view of your infrastructure, your JWT
  handling, or your threat model.
- Anything reachable with the **service key bypasses every policy** it tests.
- The connecting role normally needs to be a superuser, or hold membership in the
  roles it switches to. That connection string is powerful — keep it out of
  version control.
- Not affiliated with or endorsed by Supabase.

## Requirements

Python 3.9+, PostgreSQL (or Supabase), and `psycopg2` — pulled in automatically
by `pip install rls-policy-tester`. PyYAML is optional and only needed if you
write definitions as `.yaml` instead of `.json`
(`pip install rls-policy-tester[yaml]`). The tool exits 3, not 1, when it could
not test anything: `1` always means a check really failed.

## The full pack

The paid pack adds the complete **tenant-isolation suite (70 checks)** covering a
real multi-tenant org/membership model, the **joins-views-functions suite (43
checks)**, three more negative controls, the full `POLICY-PITFALLS.md` with 15
measured pitfalls (including a view that leaks to `anon` and a `TRUNCATE`
bypass), and `WRITING-POLICIES.md`.

<!-- RELATED:START -->

## Related tools

- **[pg-perf-check](https://github.com/duke5am/pg-perf-check)** — PostgreSQL performance diagnostics: 24 read-only checks and 7 SQL files for bloat, missing indexes, slow queries, locks and autovacuum.
  *(if you were searching for "postgres performance tuning queries")*
- **[pg-restore-drill](https://github.com/duke5am/pg-restore-drill)** — Prove your PostgreSQL backup actually restores: a scripted point-in-time recovery drill with a measured RPO/RTO report and a negative control.
  *(if you were searching for "test postgres backup restore")*
- **[postgres-migration-safety-lint](https://github.com/duke5am/postgres-migration-safety-lint)** — Lint SQL migrations before they run: finds statements that take an ACCESS EXCLUSIVE lock, rewrite a table, or destroy data, and gives the safe rewrite.
  *(if you were searching for "postgres migration lock")*

All 28 tools in this set, grouped by what they check: **[dev-tools-index](https://duke5am.github.io/dev-tools-index/)**

If you arrived here searching for one of these, this is the tool: **supabase rls test** · **row level security testing postgres** · **rls policy leak check** · **multi tenant isolation test**

<!-- RELATED:END -->

→ **[Supabase RLS Policy Test Suite](https://duke5am.gumroad.com/l/26-supabase-rls-test-suite)** — $34 on Gumroad <!-- GUMROAD-LINK -->
