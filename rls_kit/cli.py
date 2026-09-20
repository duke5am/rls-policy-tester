#!/usr/bin/env python3
"""rls-policy-tester -- prove that user A cannot read user B's rows.

This is the implementation of the `rls-policy-tester` console script. The
repo-root `rls_test_runner.py` is a thin wrapper around `main()`, so
`python3 rls_test_runner.py ...` keeps working from a clone and the installed
script runs exactly the same code.

A Row Level Security policy that is wrong fails silently. The application keeps
working, the dashboard keeps loading, and every tenant can read every other
tenant's data. There is no compiler for this. This runner is the closest thing:
it connects to your database as several identities, runs your own queries as
each of them, and asserts what each one is and is not allowed to see.

    ./rls_test_runner.py --dsn "$DATABASE_URL"
    ./rls_test_runner.py --dsn "$DATABASE_URL" --list
    ./rls_test_runner.py --dsn "$DATABASE_URL" --json > report.json
    ./rls_test_runner.py --dsn "$DATABASE_URL" --verbose
    ./rls_test_runner.py --dsn "$DATABASE_URL" --audit-schema public

Exit codes:

    0  everything behaved as the definition declared
    1  a check failed, errored, or was inconclusive
    2  a NEGATIVE CONTROL failed to detect the leak it exists to detect,
       which means the detector is broken -- treat this as a build failure
    3  usage, definition or connection problem: nothing was tested

Requirements: Python 3.9+, psycopg2. No other packages. YAML definitions are
supported when PyYAML happens to be installed; JSON always works.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Dict, List, Optional

from . import __product__, __version__
from . import definitions as defs
from . import db as dbmod
from . import engine
from . import report as reportmod

#: The installed console script, used as the argparse prog name.
PROGRAM = "rls-policy-tester"
#: The checkout entry point; the example strings below stay literally true.
SCRIPT = "rls_test_runner.py"

#: Directory holding the package, i.e. where the shipped tests_definitions/
#: and example_schema/ live. Inside the wheel as well as in a checkout.
HERE = os.path.dirname(os.path.abspath(__file__))

DEFAULT_DSN_ENV = ("RLS_TEST_DSN", "DATABASE_URL", "SUPABASE_DB_URL", "PGDSN")

EXIT_OK = 0
EXIT_CHECK_FAILED = 1
EXIT_CONTROL_NOT_DETECTED = 2
EXIT_USAGE = 3


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=PROGRAM,
        description=(
            "Run declarative Row Level Security isolation tests against a "
            "PostgreSQL or Supabase database."
        ),
        epilog=(
            "examples:\n"
            "  rls_test_runner.py --dsn 'postgresql://user@host:5432/db' --list\n"
            "  rls_test_runner.py --dsn \"$DATABASE_URL\" --verbose\n"
            "  rls_test_runner.py --dsn \"$DATABASE_URL\" --include-controls\n"
            "  rls_test_runner.py --dsn \"$DATABASE_URL\" --audit-schema public\n"
            "\n"
            "exit codes: 0 ok, 1 check failed, 2 negative control not detected, "
            "3 usage error\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--dsn",
        default=None,
        help=(
            "libpq connection string, e.g. 'host=127.0.0.1 port=5432 user=postgres "
            "dbname=app' or 'postgresql://postgres@127.0.0.1:5432/app'. "
            "Falls back to $RLS_TEST_DSN, $DATABASE_URL, $SUPABASE_DB_URL, $PGDSN."
        ),
    )
    p.add_argument(
        "--file",
        "-f",
        action="append",
        default=None,
        metavar="PATH",
        help=(
            "a definition file, or a directory of them. Repeatable. Defaults to "
            "the tests_definitions/ directory beside this script."
        ),
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="emit a machine-readable JSON report on stdout instead of the text report",
    )
    p.add_argument(
        "--json-out",
        metavar="PATH",
        default=None,
        help="also write the JSON report to this file",
    )
    p.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help=(
            "show the SQL of every check, the full policy list, and the "
            "anti-vacuity sanity result behind each denial"
        ),
    )
    p.add_argument(
        "--list",
        action="store_true",
        help="list the definitions, identities and check ids, then exit (no connection)",
    )
    p.add_argument(
        "--only",
        action="append",
        default=None,
        metavar="SUBSTRING",
        help="run only checks whose id contains this substring. Repeatable.",
    )
    p.add_argument(
        "--setup",
        dest="setup",
        action="store_true",
        default=None,
        help=(
            "run the definition's setup_reset and setup files before testing "
            "(default when the definition declares any)"
        ),
    )
    p.add_argument(
        "--no-setup",
        dest="setup",
        action="store_false",
        help="never touch the schema; test the database exactly as it is",
    )
    p.add_argument(
        "--include-controls",
        action="store_true",
        help=(
            "also run definitions declared as negative controls "
            "(expected_outcome=\"fail\"). Exit code 0 means the leak WAS "
            "detected."
        ),
    )
    p.add_argument(
        "--controls-only",
        action="store_true",
        help="run only the negative controls (the suite's self-test)",
    )
    p.add_argument(
        "--strict-audit",
        action="store_true",
        help=(
            "treat a permissive policy (a literal TRUE expression) as a failure "
            "in preflight rather than a warning"
        ),
    )
    p.add_argument(
        "--row-limit",
        type=int,
        default=500,
        metavar="N",
        help=(
            "how many rows to pull back for reporting before switching to "
            "count(*) (default 500). The reported row_count is always exact."
        ),
    )
    p.add_argument(
        "--audit-schema",
        metavar="SCHEMA",
        default=None,
        help=(
            "do not run any definition: instead report every table in SCHEMA "
            "that has RLS disabled, RLS with no policies, or a literal-TRUE "
            "policy. Exits 1 if any are found."
        ),
    )
    p.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="print only the summary line and failures",
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__} ({__product__})",
    )
    return p


def resolve_dsn(cli_value: Optional[str]) -> str:
    if cli_value:
        return cli_value
    for name in DEFAULT_DSN_ENV:
        value = os.environ.get(name)
        if value:
            return value
    # Must be EXIT_USAGE (3). `raise SystemExit("text")` exits 1, which this
    # tool reserves for "a check failed" -- so a run that tested nothing at
    # all used to be indistinguishable from a real failure in CI.
    sys.stderr.write(
        "rls_test_runner: no database to test.\n"
        "  Pass --dsn, or set one of: " + ", ".join(DEFAULT_DSN_ENV) + "\n"
        "  Example: rls_test_runner.py --dsn "
        "'host=127.0.0.1 port=5432 user=postgres dbname=app'\n"
    )
    raise SystemExit(EXIT_USAGE)


#: tests_definitions/ ships as package data, so it is found from a wheel and
#: from a checkout alike; the repository-root path is kept as a fallback for
#: older layouts.
_DEFINITION_CANDIDATES = (
    os.path.join(HERE, "tests_definitions"),
    os.path.normpath(os.path.join(HERE, "..", "tests_definitions")),
)


def default_definition_paths() -> List[str]:
    for candidate in _DEFINITION_CANDIDATES:
        if os.path.isdir(candidate):
            return [candidate]
    sys.stderr.write(
        "rls_test_runner: no definitions found.\n"
        "  Looked for " + ", ".join(_DEFINITION_CANDIDATES) + "\n"
        "  Pass --file PATH (a definition file or a directory of them).\n"
    )
    raise SystemExit(EXIT_USAGE)


def filter_checks(definition: defs.SuiteDefinition, needles: Optional[List[str]]) -> int:
    """Restrict a definition's checks to those matching --only. Returns how
    many were dropped."""
    if not needles:
        return 0
    before = len(definition.checks)
    definition.checks = [
        c for c in definition.checks if any(n in c.id for n in needles)
    ]
    return before - len(definition.checks)


def cmd_audit_schema(dsn: str, schema: str, as_json: bool) -> int:
    try:
        policies, findings = engine.audit_schema(dsn, schema)
    except Exception as exc:
        sys.stderr.write(f"rls_test_runner: audit failed: {exc}\n")
        return EXIT_USAGE
    bad = [f for f in findings if f.status in (engine.FAIL, engine.ERROR)]
    if as_json:
        import json as _json

        print(
            _json.dumps(
                {
                    "schema": schema,
                    "ok": not bad,
                    "findings": [f.__dict__ for f in findings],
                    "policies": [p.__dict__ for p in policies],
                },
                indent=2,
                default=str,
            )
        )
        return 1 if bad else 0

    print("=" * 84)
    print(f" RLS SCHEMA AUDIT  --  {schema}")
    print("=" * 84)
    for f in findings:
        mark = reportmod._MARK.get(f.status, f.status)
        print(f"  {mark:<4}  {f.target:<40} {f.message}")
        if f.detail:
            print(f"          ({f.detail})")
    print("-" * 84)
    unprotected = len([f for f in findings if f.status in (engine.FAIL, engine.ERROR)])
    print(
        f" {len(findings)} object(s) inspected, {unprotected} problem(s) found"
    )
    print("-" * 84)
    if bad:
        print("")
        print(" Every row of an unprotected table is readable by any role that")
        print(" holds a SELECT privilege on it. On Supabase, anon and")
        print(" authenticated hold that privilege by default.")
    return 1 if bad else 0


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.audit_schema:
        dsn = resolve_dsn(args.dsn)
        try:
            dbmod.check_reachable(dsn)
        except dbmod.ConnectionError_ as exc:
            sys.stderr.write(f"rls_test_runner: {exc}\n")
            return EXIT_USAGE
        return cmd_audit_schema(dsn, args.audit_schema, args.json)

    # ---- load definitions -------------------------------------------------
    paths = args.file or default_definition_paths()
    try:
        files = defs.discover_definitions(paths)
    except defs.DefinitionError as exc:
        sys.stderr.write(f"rls_test_runner: {exc}\n")
        return EXIT_USAGE

    loaded: List[defs.SuiteDefinition] = []
    for path in files:
        try:
            loaded.append(defs.load_definition(path))
        except defs.DefinitionError as exc:
            sys.stderr.write(f"rls_test_runner: {exc}\n")
            return EXIT_USAGE

    if args.controls_only:
        loaded = [d for d in loaded if d.expected_outcome == "fail"]
    elif not args.include_controls:
        loaded = [d for d in loaded if d.expected_outcome != "fail"]

    for d in loaded:
        filter_checks(d, args.only)
    loaded = [d for d in loaded if d.checks]
    if not loaded:
        sys.stderr.write(
            "rls_test_runner: nothing to run.\n"
            "  Every definition was filtered out. Drop --only, or pass "
            "--include-controls to run the negative controls.\n"
        )
        return EXIT_USAGE

    if args.list:
        sys.stdout.write(reportmod.render_list(loaded))
        return EXIT_OK

    dsn = resolve_dsn(args.dsn)
    try:
        dbmod.check_reachable(dsn)
    except dbmod.ConnectionError_ as exc:
        sys.stderr.write(f"rls_test_runner: {exc}\n")
        return EXIT_USAGE

    # ---- run --------------------------------------------------------------
    runs: List[engine.SuiteRun] = []
    for d in loaded:
        do_setup = args.setup
        if do_setup is None:
            do_setup = bool(d.setup or d.setup_reset)
        try:
            run = engine.run_suite(
                d,
                dsn,
                do_setup=do_setup,
                strict_audit=args.strict_audit,
                fetch_limit=args.row_limit,
                verbose=args.verbose,
            )
        except dbmod.ConnectionError_ as exc:
            sys.stderr.write(f"rls_test_runner: {exc}\n")
            return EXIT_USAGE
        runs.append(run)

    # ---- report -----------------------------------------------------------
    if args.json:
        sys.stdout.write(reportmod.render_json(runs) + "\n")
    else:
        chunks: List[str] = []
        for run in runs:
            if args.quiet and run.passed and run.expected_outcome == "pass":
                counts = run.counts()
                chunks.append(
                    f"{run.suite}: PASS ({counts.get(engine.PASS, 0)} passed, "
                    f"{sum(counts.values())} total)"
                )
                continue
            chunks.append(
                reportmod.render_text(
                    run, verbose=args.verbose, show_policy_audit=not args.quiet
                )
            )
        sys.stdout.write("\n".join(chunks) + "\n")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            fh.write(reportmod.render_json(runs) + "\n")

    return max((reportmod.exit_code_for(r) for r in runs), default=EXIT_OK)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:  # pragma: no cover
        sys.stderr.write("\ninterrupted\n")
        raise SystemExit(130)
