#!/usr/bin/env python3
"""One command: install the example schema, run every test, print one verdict.

    python3 tests/run_suite.py
    python3 tests/run_suite.py --dsn "postgresql://postgres@127.0.0.1:5432/rlsdemo"
    python3 tests/run_suite.py --dsn "$DATABASE_URL" --no-declarative
    RLS_TEST_DSN="$DATABASE_URL" python3 tests/run_suite.py

Three layers run, in order:

  1. tests/test_engine.py            unit tests for the runner. No database.
  2. tests/test_*.py (the rest)      the live unittest suite: real connections,
                                     real roles, assertions on real rows.
  3. tests_definitions/*.json        the declarative suites, including the three
                                     negative controls that must FAIL.

The exit code is 0 only when all three layers agree:

    0  everything behaved as declared -- including the negative controls, which
       exit 0 when they successfully detect their leak
    1  a unit test or live test failed, or a positive suite failed
    2  a negative control did not detect the leak it exists to detect, which
       means the detector is broken and no green run from this pack is
       trustworthy
    3  setup, connection or usage problem: nothing was tested

The schema is installed fresh before the live tests, so a run leaves the
deliberately broken negative-control tables in place and nothing else changed.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.dirname(HERE)
for path in (PACK, HERE):
    if path not in sys.path:
        sys.path.insert(0, path)

import rls_kit  # noqa: E402
from rls_kit import db as dbmod  # noqa: E402
from rls_kit import definitions as defs  # noqa: E402
from rls_kit import engine  # noqa: E402
from rls_kit import report as reportmod  # noqa: E402

RULE = "-" * 84
HEAVY = "=" * 84

EXIT_OK = 0
EXIT_TEST_FAILED = 1
EXIT_DETECTOR_BROKEN = 2
EXIT_USAGE = 3


def resolve_dsn(cli_value):
    if cli_value:
        return cli_value
    for name in ("RLS_TEST_DSN", "DATABASE_URL", "SUPABASE_DB_URL", "PGDSN"):
        value = os.environ.get(name)
        if value:
            return value
    from rls_case import DEFAULT_DSN

    return DEFAULT_DSN


def install_schema(dsn: str) -> bool:
    """Install the example schema from the definition that declares it."""
    definition = defs.load_definition(
        os.path.join(PACK, "tests_definitions", "01_tenant_isolation.json")
    )
    print("SETUP")
    steps = dbmod.apply_setup(dsn, definition)
    ok = True
    for step in steps:
        mark = "ok  " if step.ok else "FAIL"
        print(f"  {mark}  {step.name}")
        if not step.ok:
            ok = False
            print(f"        {step.detail}")
    print("")
    return ok


def run_unittests(verbose: bool) -> unittest.result.TestResult:
    loader = unittest.TestLoader()
    try:
        suite = loader.discover(start_dir=HERE, top_level_dir=HERE, pattern="test_*.py")
    except Exception as exc:  # pragma: no cover
        print(f"could not discover tests: {exc}")
        raise SystemExit(EXIT_USAGE)
    runner = unittest.TextTestRunner(verbosity=2 if verbose else 1, stream=sys.stdout)
    return runner.run(suite)


def run_declarative(dsn: str, verbose: bool):
    files = defs.discover_definitions([os.path.join(PACK, "tests_definitions")])
    runs = []
    for f in files:
        definition = defs.load_definition(f)
        run = engine.run_suite(
            definition, dsn, do_setup=False, verbose=verbose
        )
        runs.append(run)
    return runs


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="run_suite.py",
        description="Run the whole Supabase RLS Policy Test Suite pack end to end.",
    )
    parser.add_argument("--dsn", default=None, help="libpq connection string")
    parser.add_argument("--verbose", "-v", action="store_true", help="verbose test output")
    parser.add_argument(
        "--no-setup",
        action="store_true",
        help="do not install the example schema first; test the database as it is",
    )
    parser.add_argument(
        "--no-declarative",
        action="store_true",
        help="run only the unittest layers, skipping the declarative suites",
    )
    parser.add_argument(
        "--no-unittest",
        action="store_true",
        help="run only the declarative suites",
    )
    args = parser.parse_args(argv)

    dsn = resolve_dsn(args.dsn)

    print(HEAVY)
    print(f" {rls_kit.__product__}  v{rls_kit.__version__}  --  end to end")
    print(HEAVY)
    print(f" dsn     : {dbmod.describe_dsn(dsn)}")
    try:
        dbmod.check_reachable(dsn)
    except dbmod.ConnectionError_ as exc:
        print(f"\n{exc}\n")
        return EXIT_USAGE
    print(f" server  : {dbmod.server_version(dsn).split(' on ')[0]}")
    print("")

    if not args.no_setup:
        if not install_schema(dsn):
            print("SETUP FAILED: nothing was tested.")
            return EXIT_USAGE
    else:
        print("SETUP: skipped (--no-setup)\n")

    t0 = time.time()
    exit_codes = []

    if not args.no_unittest:
        print(HEAVY)
        print(" LAYER 1+2  unittest: engine unit tests and the live identity suite")
        print(HEAVY)
        result = run_unittests(args.verbose)
        if result.skipped:
            print(f"\n  {len(result.skipped)} test(s) skipped:")
            for case, reason in result.skipped[:5]:
                print(f"    {case}: {reason}")
        unit_ok = result.wasSuccessful() and not result.skipped
        if result.skipped and result.wasSuccessful():
            print(
                "\n  NOTE: tests were SKIPPED, so the live layer did not run. "
                "Check the database connection."
            )
            unit_ok = False
        exit_codes.append(EXIT_OK if unit_ok else EXIT_TEST_FAILED)
        print("")

    if not args.no_declarative:
        print(HEAVY)
        print(" LAYER 3  declarative suites from tests_definitions/")
        print(HEAVY)
        runs = run_declarative(dsn, args.verbose)
        broken_controls = []
        for run in runs:
            counts = run.counts()
            code = reportmod.exit_code_for(run)
            exit_codes.append(code)
            label = "PASS" if run.passed else (
                "DETECTED" if run.expected_outcome == "fail" and run.detected_problem
                else "FAIL"
            )
            if run.expected_outcome == "fail" and not run.detected_problem:
                broken_controls.append(run.suite)
            summary = ", ".join(f"{n} {s.lower()}" for s, n in sorted(counts.items()))
            print(f"  {label:<9} {run.suite:<38} {summary}")
            if code != EXIT_OK:
                print(f"            exit {code}")
        print("")
        if broken_controls:
            print("  *** NEGATIVE CONTROL(S) DETECTED NOTHING ***")
            for name in broken_controls:
                print(f"      {name}")
            print(
                "      A known-unprotected table was reported as fine. The "
                "detector is broken;\n      do not trust any green run of this "
                "pack until this is fixed."
            )
            print("")

    elapsed = time.time() - t0
    print(HEAVY)
    worst = max(exit_codes) if exit_codes else EXIT_USAGE
    verdict = {
        EXIT_OK: "PASS -- every layer behaved as declared",
        EXIT_TEST_FAILED: "FAIL -- a test or a positive suite failed",
        EXIT_DETECTOR_BROKEN: "BROKEN -- a negative control detected nothing",
        EXIT_USAGE: "USAGE -- nothing was tested",
    }[worst]
    print(f" RESULT: {verdict}")
    print(f" elapsed: {elapsed:.2f}s   exit code: {worst}")
    print(HEAVY)
    return worst


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:  # pragma: no cover
        sys.stderr.write("\ninterrupted\n")
        raise SystemExit(130)
