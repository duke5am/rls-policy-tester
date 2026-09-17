"""Rendering a SuiteRun, and the exit code CI depends on.

Two output formats:

  * text -- the report a human reads. Every failure carries the SQL that
            failed, the rows that leaked, and the reason the check exists.
  * json -- the same data, for a CI job that wants to annotate a pull request
            or post to Slack.

Exit codes (documented in README.md and docs/CI-INTEGRATION.md):

    0  the suite behaved as its definition declared
    1  a check failed, errored, or was inconclusive
    2  a NEGATIVE CONTROL did not detect the leak it exists to detect, which
       means the detector itself is broken. This is a red alert, not a
       test failure.
    3  usage, definition or connection problem -- nothing was tested
"""

from __future__ import annotations

import json
import textwrap
from typing import Any, Dict, List, Optional

from . import __product__, __version__
from . import db as dbmod
from .engine import (
    ERROR,
    FAIL,
    INCONCLUSIVE,
    INFO,
    PASS,
    SKIP,
    WARN,
    CheckResult,
    PreflightResult,
    SuiteRun,
)

WIDTH = 84
_RULE = "-" * WIDTH
_HEAVY = "=" * WIDTH

_MARK = {
    PASS: "ok  ",
    FAIL: "FAIL",
    ERROR: "ERR ",
    WARN: "warn",
    INFO: "info",
    SKIP: "skip",
    INCONCLUSIVE: "????",
}


def exit_code_for(run: SuiteRun) -> int:
    if run.expected_outcome == "fail":
        # A negative control: it is supposed to find the leak. Passing means the
        # detector is broken. Only a real failure counts as detection -- an
        # INCONCLUSIVE check means nothing was proved, which for a control is
        # indistinguishable from having missed the leak.
        return 0 if run.failures else 2
    # A normal suite: an INCONCLUSIVE check proved nothing, so it must not
    # leave CI green.
    return 1 if run.detected_problem else 0


# ---------------------------------------------------------------------------
# Text
# ---------------------------------------------------------------------------
def _wrap(text: str, indent: str, width: int = WIDTH) -> str:
    return textwrap.fill(
        text, width=width, initial_indent=indent, subsequent_indent=indent
    )


def render_text(
    run: SuiteRun,
    verbose: bool = False,
    max_leaked_rows: int = 5,
    show_policy_audit: bool = True,
) -> str:
    out: List[str] = []
    out.append(_HEAVY)
    out.append(f" {__product__}  v{__version__}")
    out.append(_HEAVY)
    out.append(f" suite        : {run.suite}")
    if run.title:
        out.append(f" title        : {run.title}")
    out.append(f" definition   : {run.path}")
    out.append(f" dsn          : {dbmod.describe_dsn(run.dsn)}")
    if run.server_version:
        out.append(f" server       : {run.server_version.split(' on ')[0]}")
    out.append(f" expected     : {run.expected_outcome.upper()}")
    out.append(f" duration     : {run.duration_ms / 1000.0:.2f}s")
    out.append("")

    # -- setup -------------------------------------------------------------
    if run.setup:
        out.append(f"SETUP ({len(run.setup)} step(s))")
        for step in run.setup:
            mark = _MARK[PASS if step.ok else FAIL]
            out.append(f"  {mark}  {step.name}")
            if not step.ok and step.detail:
                out.append(_wrap(step.detail, "        "))
        out.append("")

    # -- preflight ---------------------------------------------------------
    if run.preflight:
        n_bad = sum(1 for p in run.preflight if p.status in (FAIL, ERROR))
        label = f"PREFLIGHT ({len(run.preflight)} fact(s)"
        label += f", {n_bad} problem(s))" if n_bad else ")"
        out.append(label)
        for p in run.preflight:
            if p.status == PASS and not verbose:
                out.append(f"  {_MARK[p.status]}  {p.target:<34} {_short(p.message)}")
                if p.detail and verbose:
                    out.append(_wrap("(" + p.detail + ")", "        "))
                continue
            out.append(f"  {_MARK.get(p.status, p.status):<4}  {p.target}")
            out.append(_wrap(p.message, "        "))
            if p.detail and p.status != PASS:
                out.append(_wrap("(" + p.detail + ")", "        "))
        out.append("")

    # -- policy audit ------------------------------------------------------
    if show_policy_audit and run.policies:
        out.append(f"POLICY AUDIT ({len(run.policies)} policy/policies installed)")
        if verbose:
            for pol in run.policies:
                out.append(
                    f"  {pol.table}.{pol.policy}  FOR {pol.command} "
                    f"TO {pol.roles} ({pol.permissive})"
                )
                out.append(_wrap(f"USING      {pol.using_expr}", "        "))
                out.append(_wrap(f"WITH CHECK {pol.with_check_expr}", "        "))
                if pol.flags:
                    out.append(_wrap("FLAGS " + ", ".join(pol.flags), "        "))
        else:
            tables: Dict[str, int] = {}
            for pol in run.policies:
                tables[pol.table] = tables.get(pol.table, 0) + 1
            for table in sorted(tables):
                out.append(f"  {table:<46} {tables[table]:>3} policy/policies")
            flagged = [p for p in run.policies if p.flags]
            for pol in flagged:
                out.append(
                    f"  {'note':<4}  {pol.table}.{pol.policy}: "
                    f"{', '.join(pol.flags)}"
                )
        out.append("")

    # -- checks ------------------------------------------------------------
    if run.checks:
        n_bad = sum(1 for c in run.checks if c.status != PASS)
        out.append(
            f"CHECKS ({len(run.checks)} check(s)"
            + (f", {n_bad} not passing)" if n_bad else ", all passing)")
        )
        for c in run.checks:
            out.append(f"  {_MARK.get(c.status, c.status):<4}  {_format_check_line(c)}")
            if verbose and c.status == PASS:
                out.append(_wrap("sql : " + _one_line(c.sql), "        "))
                if c.sanity:
                    unit = (
                        "affects" if c.sanity.get("mode") == "write" else "returns"
                    )
                    out.append(
                        _wrap(
                            f"sanity: as {c.sanity['identity']} the same statement "
                            f"{unit} {c.sanity['row_count']} row(s), so the 0-row "
                            f"result is real",
                            "        ",
                        )
                    )
                continue
            if c.status == PASS:
                if c.sanity:
                    unit = (
                        "affects"
                        if c.sanity.get("mode") == "write"
                        else "returns"
                    )
                    out.append(
                        _wrap(
                            f"(verified non-vacuous: as {c.sanity['identity']} the "
                            f"same statement {unit} {c.sanity['row_count']} row(s))",
                            "        ",
                        )
                    )
                continue
            _render_failure(out, c, max_leaked_rows)
        out.append("")
    elif any(p.status in (FAIL, ERROR) for p in run.preflight):
        out.append("CHECKS (0 -- not run: preflight failed)")
        out.append(
            _wrap(
                "The suite refused to run its checks, because a preflight fact "
                "shows the checks would not mean anything. Fix the preflight "
                "problem above and run again.",
                "  ",
            )
        )
        out.append("")

    # -- totals ------------------------------------------------------------
    counts = run.counts()
    parts = [f"{counts.get(PASS, 0)} passed"]
    for status, word in ((FAIL, "failed"), (ERROR, "errored"), (INCONCLUSIVE, "inconclusive")):
        if counts.get(status):
            parts.append(f"{counts[status]} {word}")
    for status in (WARN, INFO, SKIP):
        if counts.get(status):
            parts.append(f"{counts[status]} {status.lower()}")
    total = sum(counts.values())

    out.append(_RULE)
    out.append(" ".join(parts) + f"   ({total} fact(s) and check(s) total)")
    if run.expected_outcome == "fail":
        if run.detected_problem:
            out.append(
                "RESULT: DETECTED -- this is a negative control and the suite "
                "correctly reported the problem (exit 0)"
            )
        else:
            out.append(
                "RESULT: ***NOT DETECTED*** -- this is a negative control, the "
                "table is known to be unprotected, and the suite still reported "
                "everything as fine. THE DETECTOR IS BROKEN (exit 2)"
            )
    else:
        out.append("RESULT: " + ("PASS" if run.passed else "FAIL"))
    out.append(_RULE)

    if not run.passed and run.expected_outcome == "pass":
        out.append("")
        hints = _hints(run)
        if hints:
            out.append("WHAT TO LOOK AT FIRST")
            for h in hints:
                out.append(_wrap("- " + h, "  "))
    return "\n".join(out)


def _short(text: str, limit: int = 46) -> str:
    text = text.splitlines()[0]
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


def _one_line(sql: str) -> str:
    return " ".join(sql.split())


def _format_check_line(c: CheckResult) -> str:
    ident = f"as {c.identity}"
    if c.expect == "error":
        verdict = "expect error"
    elif c.expect == "value":
        verdict = f"value (= {c.observed_value!r}, want {c.expected_value!r})"
    elif c.mode == "write":
        verdict = f"{c.expect} ({c.row_count} row(s) affected)"
    else:
        verdict = f"{c.expect} ({c.row_count} row(s))"
    return f"{c.id:<44} {ident:<16} {verdict}"


def _render_failure(out: List[str], c: CheckResult, max_rows: int) -> None:
    out.append(_wrap(c.message, "        "))
    if c.why:
        out.append(_wrap("why : " + c.why, "        "))
    out.append(_wrap("sql : " + _one_line(c.sql), "        "))
    if c.sanity:
        unit = "row(s) affected" if c.sanity.get("mode") == "write" else "row(s)"
        out.append(
            _wrap(
                f"sanity identity {c.sanity['identity']!r}: "
                + (
                    f"{c.sanity['row_count']} {unit}"
                    if c.sanity["ok"]
                    else "query failed: " + _one_line(str(c.sanity["error"]))
                ),
                "        ",
            )
        )
    if c.error:
        out.append(_wrap("error: " + _one_line(c.error), "        "))
    if c.leaked and c.mode == "write":
        out.append(
            _wrap(
                f"AFFECTED ROWS: this identity modified {c.row_count} row(s) "
                f"that the policy should have refused. The transaction was rolled "
                f"back, so the database here is unchanged -- in production it "
                f"would not have been.",
                "        ",
            )
        )
    elif c.leaked and c.rows:
        out.append(
            _wrap(
                f"LEAKED ROWS ({c.row_count} row(s), showing first "
                f"{min(len(c.rows), max_rows)}):",
                "        ",
            )
        )
        header = c.columns or []
        if header:
            out.append(_wrap("  columns: " + ", ".join(header), "        "))
        for row in c.rows[:max_rows]:
            out.append(_wrap("  " + repr(row), "        "))
        if c.truncated:
            out.append(
                _wrap(
                    "(the row list was truncated by --row-limit; row_count above "
                    "is the exact number the query matched)",
                    "        ",
                )
            )


def _hints(run: SuiteRun) -> List[str]:
    hints: List[str] = []
    for p in run.preflight:
        if p.status in (FAIL, ERROR):
            hints.append(p.message.split(". ")[0] + ".")
            break
    for c in run.checks:
        if c.status == INCONCLUSIVE:
            hints.append(
                f"{c.id}: the check is inconclusive, not passing. Nothing was "
                f"proved. Check that the fixture data the query selects on is "
                f"actually present."
            )
            break
    leaks = [c for c in run.checks if c.leaked]
    if leaks:
        hints.append(
            f"{len(leaks)} check(s) leaked rows to an identity that should not "
            f"have seen them: " + ", ".join(c.id for c in leaks[:4]) + "."
        )
    wrong_deny = [
        c for c in run.checks if c.status == FAIL and c.expect == "allow"
    ]
    if wrong_deny:
        hints.append(
            f"{len(wrong_deny)} check(s) expected access and were denied: "
            + ", ".join(c.id for c in wrong_deny[:4])
            + ". Look for a missing policy, a missing GRANT, or a policy scoped "
              "to the wrong role."
        )
    return hints


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------
def render_json(runs: List[SuiteRun], extra: Optional[Dict[str, Any]] = None) -> str:
    payload: Dict[str, Any] = {
        "product": __product__,
        "version": __version__,
        "suites": [r.to_dict() for r in runs],
    }
    payload["ok"] = all(
        (r.detected_problem if r.expected_outcome == "fail" else r.passed) for r in runs
    )
    payload["exit_code"] = max((exit_code_for(r) for r in runs), default=0)
    totals: Dict[str, int] = {}
    for r in runs:
        for status, n in r.counts().items():
            totals[status] = totals.get(status, 0) + n
    payload["totals"] = totals
    if extra:
        payload.update(extra)
    return json.dumps(payload, indent=2, default=str)


# ---------------------------------------------------------------------------
# --list
# ---------------------------------------------------------------------------
def render_list(definitions: List[Any]) -> str:
    out: List[str] = []
    for d in definitions:
        out.append(f"{d.suite}   ({len(d.checks)} checks, {len(d.identities)} identities)")
        if d.title:
            out.append(f"    {d.title}")
        out.append(f"    file: {d.path}")
        if d.expected_outcome == "fail":
            out.append(
                "    NEGATIVE CONTROL: this suite is expected to FAIL. It exists "
                "to prove the detector works."
            )
        if d.tags:
            out.append("    tags: " + ", ".join(d.tags))
        by_identity: Dict[str, int] = {}
        for c in d.checks:
            by_identity[c.identity] = by_identity.get(c.identity, 0) + 1
        out.append(
            "    identities: "
            + ", ".join(
                f"{name} ({by_identity.get(name, 0)})" for name in sorted(d.identities)
            )
        )
        for c in d.checks:
            out.append(f"      - {c.id}  [as {c.identity}, expect {c.expect}]")
        out.append("")
    return "\n".join(out)
