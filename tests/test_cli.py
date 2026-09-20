#!/usr/bin/env python3
"""Contract tests for the rls-policy-tester CLI.

What packaging can break, and what nothing else covers: the no-database modes
must keep working, the definition files and the example schema must be found
from inside the installed package (they are package data now), and bad input
must exit 3 with a message rather than a traceback or - worse - exit 1, which
this tool reserves for "a check really failed".

    python3 -m unittest discover -s tests
    python3 tests/test_cli.py -v

No database is used by default. Set ``RLS_TEST_DSN`` to also run the
non-destructive schema audit against a live server, and ``RLS_TEST_DSN`` plus
``RLS_TEST_ALLOW_RESET=1`` to run the destructive negative controls. Point
``RLS_TEST_DSN`` at a DISPOSABLE database: the controls drop and recreate
schema ``public`` through their own setup_reset, exactly as documented.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "rls_test_runner.py"
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

DSN_ENV = ("RLS_TEST_DSN", "DATABASE_URL", "SUPABASE_DB_URL", "PGDSN")

EXPECTED_DEFINITIONS = [
    "90_negative_control_rls_disabled.json",
    "91_negative_control_using_true.json",
]
EXPECTED_SCHEMA_FILES = [
    "00_auth_stub.sql",
    "policies.sql",
    "schema.sql",
    "seed.sql",
    "views.sql",
]


def run_cli(*args):
    env = dict(os.environ)
    for name in DSN_ENV:
        env.pop(name, None)
    return subprocess.run(
        [sys.executable, "-B", str(SCRIPT), *args],
        cwd=str(REPO), capture_output=True, text=True, env=env, timeout=300,
    )


def combined(proc):
    return proc.stdout + proc.stderr


class NoDatabaseTests(unittest.TestCase):
    def test_help(self):
        proc = run_cli("--help")
        self.assertEqual(proc.returncode, 0, combined(proc))
        self.assertIn("usage:", proc.stdout)

    def test_version_matches_the_distribution_version(self):
        proc = run_cli("--version")
        self.assertEqual(proc.returncode, 0, combined(proc))
        self.assertIn("0.1.0", proc.stdout)

    def test_list_needs_no_database(self):
        proc = run_cli("--list", "--include-controls")
        self.assertEqual(proc.returncode, 0, combined(proc))
        self.assertIn("NEGATIVE-CONTROL-rls-disabled", proc.stdout)
        self.assertIn("NEGATIVE-CONTROL-using-true", proc.stdout)
        self.assertIn("control.alice.cannot_read_org_b_rows", proc.stdout)

    def test_list_without_include_controls_says_so(self):
        # Both shipped definitions are negative controls, so a plain --list has
        # nothing to show. It must say that, and it must not be a connection
        # attempt.
        proc = run_cli("--list")
        self.assertEqual(proc.returncode, 3, combined(proc))
        self.assertIn("nothing to run", proc.stderr)
        self.assertNotIn("Traceback", combined(proc))


class BadInputTests(unittest.TestCase):
    def test_no_dsn_is_exit_3_not_exit_1(self):
        # 1 means "a check failed". A run that tested nothing must not look
        # like a failing test in CI.
        proc = run_cli("--include-controls")
        self.assertEqual(proc.returncode, 3, combined(proc))
        self.assertIn("no database to test", proc.stderr)
        self.assertNotIn("Traceback", combined(proc))

    def test_missing_definition_file(self):
        proc = run_cli("--file", "/root/no-such-definition.json", "--dsn", "host=127.0.0.1")
        self.assertEqual(proc.returncode, 3, combined(proc))
        self.assertIn("no such definition file", proc.stderr)
        self.assertNotIn("Traceback", combined(proc))

    def test_malformed_definition_file(self):
        bad = REPO / "tests" / "_tmp_bad_definition.json"
        bad.write_text("{ this is not json", encoding="utf-8")
        try:
            proc = run_cli("--file", str(bad), "--dsn", "host=127.0.0.1")
        finally:
            bad.unlink()
        self.assertEqual(proc.returncode, 3, combined(proc))
        self.assertNotIn("Traceback", combined(proc))
        self.assertTrue(proc.stderr.strip(), "a rejection must explain itself")

    def test_unreachable_database(self):
        proc = run_cli("--dsn", "postgresql://postgres@127.0.0.1:1/rlsdemo",
                       "--include-controls")
        self.assertEqual(proc.returncode, 3, combined(proc))
        self.assertIn("rls_test_runner:", proc.stderr)
        self.assertNotIn("Traceback", combined(proc))

    def test_malformed_dsn(self):
        proc = run_cli("--dsn", "this is not a dsn", "--include-controls")
        self.assertEqual(proc.returncode, 3, combined(proc))
        self.assertNotIn("Traceback", combined(proc))

    def test_unknown_flag(self):
        proc = run_cli("--definitely-not-a-flag")
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn("Traceback", combined(proc))


class PackageDataTests(unittest.TestCase):
    """The definitions and the example schema are runtime data for the installed
    tool, so a wheel missing them would run zero checks and still exit 0."""

    def test_definitions_ship_inside_the_package(self):
        from rls_kit import cli

        found = Path(cli._DEFINITION_CANDIDATES[0])
        self.assertTrue(found.is_dir(), "not found: %s" % found)
        self.assertEqual(found.parent.name, "rls_kit")
        self.assertEqual(sorted(p.name for p in found.glob("*.json")), EXPECTED_DEFINITIONS)

    def test_example_schema_ships_inside_the_package(self):
        from rls_kit import cli

        found = Path(cli._DEFINITION_CANDIDATES[0]).parent / "example_schema"
        self.assertTrue(found.is_dir(), "not found: %s" % found)
        self.assertEqual(sorted(p.name for p in found.glob("*.sql")), EXPECTED_SCHEMA_FILES)

    def test_every_setup_file_in_every_shipped_definition_resolves(self):
        # This is the check that catches a definition shipped without the SQL it
        # needs: resolve_setup_path raises when it cannot find the file.
        from rls_kit import cli, definitions as defs

        files = sorted(Path(cli._DEFINITION_CANDIDATES[0]).glob("*.json"))
        self.assertTrue(files, "no definitions found - the test is vacuous")
        seen = 0
        for path in files:
            definition = defs.load_definition(str(path))
            for rel in list(definition.setup) + list(definition.setup_reset):
                if rel.strip().lower().startswith(("drop ", "create ", "alter ",
                                                   "set ", "grant ", "revoke ",
                                                   "insert ", "select ", "update ")):
                    continue  # an inline statement, not a file reference
                resolved = definition.resolve_setup_path(rel)
                self.assertTrue(Path(resolved).is_file(), "%s -> %s" % (path.name, rel))
                seen += 1
        self.assertGreater(seen, 0, "no setup file references were exercised")


@unittest.skipUnless(os.environ.get("RLS_TEST_DSN"),
                     "set RLS_TEST_DSN to run the live database tests")
class LiveDatabaseTests(unittest.TestCase):
    def test_schema_audit_against_a_real_server(self):
        proc = subprocess.run(
            [sys.executable, "-B", str(SCRIPT),
             "--dsn", os.environ["RLS_TEST_DSN"], "--audit-schema", "public"],
            cwd=str(REPO), capture_output=True, text=True, timeout=300,
        )
        self.assertIn(proc.returncode, (0, 1), combined(proc))
        self.assertIn("RLS SCHEMA AUDIT", proc.stdout)
        self.assertNotIn("Traceback", combined(proc))


@unittest.skipUnless(os.environ.get("RLS_TEST_DSN") and os.environ.get("RLS_TEST_ALLOW_RESET"),
                     "set RLS_TEST_DSN and RLS_TEST_ALLOW_RESET=1 to run the "
                     "destructive negative controls against a disposable database")
class NegativeControlTests(unittest.TestCase):
    def test_controls_detect_the_leaks_they_exist_for(self):
        # Exit 0 here means the leaks WERE detected, which is the pass condition
        # for a negative control. Exit 2 means the detector is broken.
        proc = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "--dsn", os.environ["RLS_TEST_DSN"],
             "--controls-only", "--include-controls"],
            cwd=str(REPO), capture_output=True, text=True, timeout=600,
        )
        self.assertEqual(proc.returncode, 0, combined(proc))
        self.assertIn("DETECTED", proc.stdout + proc.stderr.upper())
        self.assertNotIn("Traceback", combined(proc))


if __name__ == "__main__":
    unittest.main(verbosity=2)
