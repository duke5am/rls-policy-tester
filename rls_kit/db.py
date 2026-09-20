"""Connections, identities and query execution.

The one idea in this file: an *identity* is a connection that has been made to
look like a specific actor to the database. On Supabase that means two things
happen to every request before your SQL runs:

    1. PostgREST connects as a role -- anon, authenticated or service_role,
       taken from the JWT's `role` claim.
    2. PostgREST sets the request GUCs -- request.jwt.claims -- taken from the
       verified JWT.

`auth.uid()` reads that GUC. A policy is therefore a function of (role, GUCs),
and that is exactly what this module reproduces:

    set role <role>;
    select set_config('request.jwt.claims', '{"sub":"<uuid>",...}', false);

Both are session-level, so they are committed once when the session opens and
every subsequent check runs underneath them.

Every check runs inside a transaction that is ALWAYS rolled back. That means a
write check may be a real INSERT, UPDATE or DELETE -- the rowcount it affected
is genuine, and the data is untouched afterwards.
"""

from __future__ import annotations

import os
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

import psycopg2
import psycopg2.extensions

from .definitions import Identity, SuiteDefinition

_ROLE_RE = re.compile(r"\A[A-Za-z_][A-Za-z0-9_$]*\Z")

# SQLSTATEs / messages that mean "Row Level Security refused this".
_RLS_MESSAGE_RE = re.compile(r"row-level security|new row violates", re.IGNORECASE)


class ConnectionError_(Exception):
    """Could not reach the database at all."""


@dataclass
class Result:
    """The outcome of one statement."""

    sql: str
    ok: bool
    rows: List[tuple] = field(default_factory=list)
    rowcount: int = 0
    error: Optional[str] = None
    sqlstate: Optional[str] = None
    duration_ms: float = 0.0
    columns: List[str] = field(default_factory=list)

    @property
    def is_rls_error(self) -> bool:
        """True when the statement was refused by a policy rather than by a
        syntax error, a missing GRANT, or a constraint."""
        if not self.error:
            return False
        if self.sqlstate == "42501" and _RLS_MESSAGE_RE.search(self.error):
            return True
        return bool(_RLS_MESSAGE_RE.search(self.error))

    def has_rows(self) -> bool:
        return len(self.rows) > 0


# ---------------------------------------------------------------------------
# DSN helpers
# ---------------------------------------------------------------------------
def describe_dsn(dsn: str) -> str:
    """A DSN safe to print: the password is replaced with ***."""
    parts = []
    for chunk in dsn.split():
        if chunk.lower().startswith("password="):
            parts.append("password=***")
        else:
            parts.append(chunk)
    return " ".join(parts)


def check_reachable(dsn: str, timeout: int = 10) -> None:
    """Fail early, with a readable message, if the server is not there."""
    try:
        conn = psycopg2.connect(dsn, connect_timeout=timeout)
    except psycopg2.ProgrammingError as exc:
        # A DSN that libpq cannot parse raises ProgrammingError, not
        # OperationalError, so it used to escape this guard as an unhandled
        # traceback straight out of the command line.
        raise ConnectionError_(
            f"cannot use that connection string.\n"
            f"  dsn: {describe_dsn(dsn)}\n"
            f"  error: {str(exc).strip()}\n"
            f"Expected a libpq connection string such as "
            f"'host=127.0.0.1 port=5432 user=postgres dbname=app', or a URL "
            f"such as 'postgresql://postgres@127.0.0.1:5432/app'."
        ) from exc
    except psycopg2.Error as exc:
        raise ConnectionError_(
            f"cannot connect to PostgreSQL.\n"
            f"  dsn: {describe_dsn(dsn)}\n"
            f"  error: {str(exc).strip()}\n"
            f"Check that the server is running and that --dsn is correct. "
            f"For a local server: psql '{dsn}' -c 'select 1'"
        ) from exc
    conn.close()


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------
class Session:
    """A connection that acts as one identity.

    Use as a context manager. Every `run()` leaves the connection clean, ready
    for the next statement: the statement's transaction is always rolled back.
    """

    def __init__(
        self,
        dsn: str,
        identity: Identity,
        verbose: bool = False,
        row_limit: int = 50,
    ) -> None:
        self.dsn = dsn
        self.identity = identity
        self.verbose = verbose
        self.row_limit = row_limit
        self.conn: Optional[psycopg2.extensions.connection] = None
        self._opened = False
        self.open_error: Optional[str] = None

    # -- lifecycle ---------------------------------------------------------
    def open(self) -> None:
        if self._opened:
            return
        try:
            self.conn = psycopg2.connect(self._dsn_for_identity())
        except psycopg2.OperationalError as exc:
            self.open_error = str(exc).strip()
            raise ConnectionError_(
                f"cannot open a session for identity {self.identity.name!r}: "
                f"{self.open_error}"
            ) from exc
        self.conn.autocommit = False
        cur = self.conn.cursor()
        try:
            role = self.identity.role
            if role is not None:
                if not _ROLE_RE.match(role):
                    raise ConnectionError_(
                        f"identity {self.identity.name!r} has an unusable role name "
                        f"{role!r}: role names must match [A-Za-z_][A-Za-z0-9_$]*"
                    )
                cur.execute(f"set role {role}")
            claims = self.identity.resolved_claims()
            if claims:
                import json as _json

                cur.execute(
                    "select set_config('request.jwt.claims', %s, false)",
                    (_json.dumps(claims, separators=(",", ":")),),
                )
                # Legacy single-claim GUCs that older PostgREST versions set and
                # that some auth.uid() definitions still read first.
                if "sub" in claims:
                    cur.execute(
                        "select set_config('request.jwt.claim.sub', %s, false)",
                        (str(claims["sub"]),),
                    )
                if "role" in claims:
                    cur.execute(
                        "select set_config('request.jwt.claim.role', %s, false)",
                        (str(claims["role"]),),
                    )
            # Commit so the role and the GUCs outlive the transaction each
            # check runs in.
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        self._opened = True

    def _dsn_for_identity(self) -> str:
        """Overlay the identity's own credentials on the suite DSN, if it has
        any. Lets a buyer connect directly as `authenticated` with a password
        instead of relying on SET ROLE."""
        if not self.identity.dsn:
            return self.dsn
        base = {}
        for chunk in self.dsn.split():
            if "=" in chunk:
                k, v = chunk.split("=", 1)
                base[k] = v
        for chunk in self.identity.dsn.split():
            if "=" in chunk:
                k, v = chunk.split("=", 1)
                base[k] = v
        return " ".join(f"{k}={v}" for k, v in base.items())

    def close(self) -> None:
        if self.conn is not None:
            try:
                self.conn.rollback()
            except Exception:
                pass
            try:
                self.conn.close()
            except Exception:
                pass
            self.conn = None
        self._opened = False

    def __enter__(self) -> "Session":
        self.open()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # -- statement execution ----------------------------------------------
    def run(self, sql: str) -> Result:
        """Execute one statement and always leave the session clean."""
        if self.conn is None:
            raise ConnectionError_(f"session for {self.identity.name!r} is not open")
        cur = self.conn.cursor()
        started = time.time()
        try:
            cur.execute(sql)
            columns = [d[0] for d in (cur.description or [])]
            rows: List[tuple] = []
            if cur.description is not None:
                rows = cur.fetchmany(self.row_limit)
            result = Result(
                sql=sql,
                ok=True,
                rows=rows,
                rowcount=cur.rowcount,
                columns=columns,
                duration_ms=(time.time() - started) * 1000.0,
            )
        except psycopg2.Error as exc:
            result = Result(
                sql=sql,
                ok=False,
                error=str(exc).strip(),
                sqlstate=getattr(exc, "pgcode", None),
                duration_ms=(time.time() - started) * 1000.0,
            )
        finally:
            # A read is thrown away, a write is thrown away, an error is
            # cleared. The next check starts from the seeded state.
            try:
                self.conn.rollback()
            except Exception:
                pass
        return result

    def scalar(self, sql: str) -> Any:
        res = self.run(sql)
        if not res.ok:
            raise ConnectionError_(
                f"statement failed for identity {self.identity.name!r}: "
                f"{res.error}\n  sql: {sql}"
            )
        if not res.rows:
            return None
        return res.rows[0][0]


def open_sessions(
    dsn: str, identity_names: Sequence[str], definition: SuiteDefinition
) -> Dict[str, Session]:
    """Open one session per identity name, failing with a clear message."""
    sessions: Dict[str, Session] = {}
    for name in identity_names:
        sess = Session(dsn, definition.identity(name))
        try:
            sess.open()
        except ConnectionError_:
            for s in sessions.values():
                s.close()
            raise
        sessions[name] = sess
    return sessions


def close_sessions(sessions: Dict[str, Session]) -> None:
    for s in sessions.values():
        s.close()


# ---------------------------------------------------------------------------
# Installing a suite's schema
# ---------------------------------------------------------------------------
@dataclass
class SetupStep:
    name: str
    ok: bool
    detail: str = ""


def apply_setup(
    dsn: str, definition: SuiteDefinition, verbose: bool = False
) -> List[SetupStep]:
    """Run setup_reset, then every setup file, in order.

    The whole thing is one connection and one transaction per step, so a
    failure names the file that failed rather than a line number in a
    concatenation.
    """
    steps: List[SetupStep] = []
    conn = psycopg2.connect(dsn)
    conn.autocommit = True
    try:
        cur = conn.cursor()
        for stmt in definition.setup_reset:
            try:
                cur.execute(stmt)
                steps.append(SetupStep(name=stmt.strip()[:72], ok=True))
            except psycopg2.Error as exc:
                steps.append(
                    SetupStep(
                        name=stmt.strip()[:72],
                        ok=False,
                        detail=str(exc).strip().splitlines()[0],
                    )
                )
                return steps

        for rel in definition.setup:
            path = definition.resolve_setup_path(rel)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    sql = fh.read()
                cur.execute(sql)
                steps.append(SetupStep(name=os.path.relpath(path), ok=True))
            except (OSError, psycopg2.Error) as exc:
                detail = str(exc).strip().splitlines()[0]
                steps.append(
                    SetupStep(name=os.path.relpath(path), ok=False, detail=detail)
                )
                return steps
    finally:
        conn.close()
    return steps


def server_version(dsn: str) -> str:
    conn = psycopg2.connect(dsn)
    try:
        cur = conn.cursor()
        cur.execute("select version()")
        return cur.fetchone()[0]
    finally:
        conn.close()
