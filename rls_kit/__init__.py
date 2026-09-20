"""rls_kit -- the engine behind rls_test_runner.py.

Prove, automatically, that user A cannot read user B's rows.

The kit is deliberately small and has no dependencies beyond psycopg2:

    definitions.py  load + validate a declarative suite, expand :params
    db.py           connect, act as an identity (SET ROLE + JWT claims), setup
    engine.py       preflight (anti-vacuity), checks, policy audit
    report.py       human + JSON rendering, exit codes

Everything that decides pass or fail lives in engine.py. Read that file first
if you want to know why a check failed.
"""

#: Kept in step with the version in pyproject.toml, because
#: `rls-policy-tester --version` reports this and pip reports that.
__version__ = "0.1.0"
__product__ = "Supabase RLS Policy Test Suite"

from .definitions import DefinitionError, SuiteDefinition, load_definition  # noqa: F401
from .engine import (  # noqa: F401
    CheckResult,
    PreflightResult,
    SuiteRun,
    audit_schema,
    run_suite,
)
from .report import render_json, render_text, exit_code_for  # noqa: F401

__all__ = [
    "__version__",
    "__product__",
    "DefinitionError",
    "SuiteDefinition",
    "load_definition",
    "CheckResult",
    "PreflightResult",
    "SuiteRun",
    "run_suite",
    "audit_schema",
    "render_text",
    "render_json",
    "exit_code_for",
]
