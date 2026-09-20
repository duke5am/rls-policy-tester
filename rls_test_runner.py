#!/usr/bin/env python3
"""rls_test_runner.py -- prove that user A cannot read user B's rows.

This wrapper exists so `python3 rls_test_runner.py --dsn ...` keeps working
without installing anything. The same CLI is installed as the
`rls-policy-tester` console script; the implementation lives in
`rls_kit/cli.py` so the installed package and the checkout are the same code,
not two versions of it.

    ./rls_test_runner.py --dsn "$DATABASE_URL"
    ./rls_test_runner.py --dsn "$DATABASE_URL" --list
    ./rls_test_runner.py --dsn "$DATABASE_URL" --json > report.json
    ./rls_test_runner.py --dsn "$DATABASE_URL" --audit-schema public

Exit codes:

    0  everything behaved as the definition declared
    1  a check failed, errored, or was inconclusive
    2  a NEGATIVE CONTROL failed to detect the leak it exists to detect,
       which means the detector is broken -- treat this as a build failure
    3  usage, definition or connection problem: nothing was tested

Requirements: Python 3.9+, psycopg2. PyYAML is optional.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rls_kit.cli import main  # noqa: E402

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:  # pragma: no cover
        sys.stderr.write("\ninterrupted\n")
        raise SystemExit(130)
