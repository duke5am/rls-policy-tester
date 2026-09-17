"""Preflight, checks and policy audit -- everything that decides pass or fail.

Three ideas do all the work here.

1. NO VACUOUS PASSES.
   A `deny` check passes when the query returns zero rows. So does a `deny`
   check against an empty table, a table whose policy is missing entirely, and
   a table where the identity cannot even run the query. Those are not the same
   thing, and a suite that cannot tell them apart is worse than no suite. Three
   guards prevent it:

     * fixtures   -- every table a suite depends on must exist, have RLS turned
                     on (unless the definition says otherwise), and hold at
                     least `min_rows` rows as seen by the admin identity.
     * sanity     -- a `deny` read check is paired with the SAME query run as an
                     identity that bypasses RLS. If that also returns nothing,
                     the result is INCONCLUSIVE, not PASS: you proved nothing.
     * owner      -- an `allow` check that returns nothing is a FAIL, so a
                     policy that denies everything cannot look healthy.

2. THE TABLE MUST ACTUALLY BE PROTECTED.
   Preflight reads pg_class and pg_policy and reports, by name, a table with
   RLS off, a table with RLS on and no policies, and any policy whose
   expression is literally `true`. With `"strict_audit": true` those are
   failures, not warnings. That is what makes the negative controls fail.

3. WRITES ARE REAL AND STILL HARMLESS.
   Write checks execute actual INSERT/UPDATE/DELETE statements and read the
   real rowcount, then roll back. `deny` on a write means "either zero rows
   were affected, or the statement was refused by a policy" -- and a failure
   for any other reason (a foreign key violation, a missing GRANT) is reported
   as ERROR, never as a pass.
"""

from __future__ import annotations

import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from . import db as dbmod
from .definitions import (
    AuditObject,
    Check,
    Identity,
    SuiteDefinition,
    TableFixture,
)

PASS = "PASS"
FAIL = "FAIL"
ERROR = "ERROR"
WARN = "WARN"
INFO = "INFO"
SKIP = "SKIP"
INCONCLUSIVE = "INCONCLUSIVE"

_BAD_STATUSES = {FAIL, ERROR, INCONCLUSIVE}

_TRAILING_SEMI_RE = re.compile(r";\s*\Z")
_LITERAL_TRUE_RE = re.compile(r"\A\s*(true|'t'|'true'::(boolean|bool))\s*\Z", re.IGNORECASE)

POLCMD_NAMES = {"r": "SELECT", "a": "INSERT", "w": "UPDATE", "d": "DELETE", "*": "ALL"}
POLPERMISSIVE = {True: "PERMISSIVE", False: "RESTRICTIVE"}


# ---------------------------------------------------------------------------
# Result containers
# ---------------------------------------------------------------------------
@dataclass
class PreflightResult:
    id: str
    status: str
    target: str
    message: str
    detail: str = ""


@dataclass
class PolicyInfo:
    table: str
    policy: str
    command: str
    permissive: str
    roles: str
    using_expr: str
    with_check_expr: str
    flags: List[str] = field(default_factory=list)


@dataclass
class CheckResult:
    id: str
    status: str
    identity: str
    mode: str
    expect: str
    sql: str
    table: str = ""
    message: str = ""
    why: str = ""
    row_count: int = 0
    rows: List[List[Any]] = field(default_factory=list)
    columns: List[str] = field(default_factory=list)
    truncated: bool = False
    error: str = ""
    sqlstate: Optional[str] = None
    is_rls_error: bool = False
    observed_value: Any = None
    expected_value: Any = None
    sanity: Optional[Dict[str, Any]] = None
    duration_ms: float = 0.0

    @property
    def leaked(self) -> bool:
        """A deny that failed is a leak: rows reached an identity that should
        not have been able to reach them."""
        return self.status == FAIL and self.expect == "deny" and self.row_count > 0


@dataclass
class SuiteRun:
    suite: str
    title: str
    path: str
    dsn: str
    server_version: str = ""
    expected_outcome: str = "pass"
    preflight: List[PreflightResult] = field(default_factory=list)
    policies: List[PolicyInfo] = field(default_factory=list)
    checks: List[CheckResult] = field(default_factory=list)
    setup: List[dbmod.SetupStep] = field(default_factory=list)
    duration_ms: float = 0.0

    # -- rollups -----------------------------------------------------------
    def _statuses(self) -> List[str]:
        return [p.status for p in self.preflight] + [c.status for c in self.checks]

    @property
    def failures(self) -> List[str]:
        return [s for s in self._statuses() if s in (FAIL, ERROR)]

    @property
    def inconclusive(self) -> List[str]:
        return [s for s in self._statuses() if s == INCONCLUSIVE]

    @property
    def detected_problem(self) -> bool:
        """Did the suite find something wrong? INCONCLUSIVE counts: a check
        that proved nothing is a defect in the suite's ability to prove."""
        return bool(self.failures or self.inconclusive)

    @property
    def passed(self) -> bool:
        if self.expected_outcome == "fail":
            return False  # a negative control is never "passed" in the usual sense
        return not self.detected_problem

    def counts(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for s in self._statuses():
            out[s] = out.get(s, 0) + 1
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "suite": self.suite,
            "title": self.title,
            "definition": self.path,
            "dsn": dbmod.describe_dsn(self.dsn),
            "server_version": self.server_version,
            "expected_outcome": self.expected_outcome,
            "detected_problem": self.detected_problem,
            "counts": self.counts(),
            "duration_ms": round(self.duration_ms, 1),
            "setup": [asdict(s) for s in self.setup],
            "preflight": [asdict(p) for p in self.preflight],
            "policies": [asdict(p) for p in self.policies],
            "checks": [asdict(c) for c in self.checks],
        }


# ---------------------------------------------------------------------------
# Catalog helpers
# ---------------------------------------------------------------------------
def _split_relation(name: str) -> Tuple[str, str]:
    if "." in name:
        schema, rel = name.split(".", 1)
        return schema.strip('"'), rel.strip('"')
    return "public", name.strip('"')


def _table_info(session: dbmod.Session, table: str) -> Optional[Dict[str, Any]]:
    schema, rel = _split_relation(table)
    res = session.run(
        """
        select c.relrowsecurity,
               c.relforcerowsecurity,
               pg_get_userbyid(c.relowner) as owner,
               c.relkind::text,
               (select count(*) from pg_policy p where p.polrelid = c.oid) as n_policies
          from pg_class c
          join pg_namespace n on n.oid = c.relnamespace
         where n.nspname = %s and c.relname = %s
        """
        % (dbmod_sql_literal(schema), dbmod_sql_literal(rel))
    )
    if not res.ok or not res.rows:
        return None
    row = res.rows[0]
    return {
        "schema": schema,
        "rel": rel,
        "rls_enabled": row[0],
        "rls_forced": row[1],
        "owner": row[2],
        "relkind": row[3],
        "n_policies": row[4],
    }


def dbmod_sql_literal(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _load_policies(session: dbmod.Session, table: str) -> List[PolicyInfo]:
    schema, rel = _split_relation(table)
    res = session.run(
        """
        select c.relname,
               p.polname,
               p.polcmd::text,
               p.polpermissive,
               coalesce(nullif(array_to_string(
                   array(select rolname from pg_roles r where r.oid = any(p.polroles)), ','),
                 'PUBLIC'), 'PUBLIC') as roles,
               coalesce(pg_get_expr(p.polqual, p.polrelid), '<none>') as using_expr,
               coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '<none>') as with_check_expr
          from pg_policy p
          join pg_class c on c.oid = p.polrelid
          join pg_namespace n on n.oid = c.relnamespace
         where n.nspname = %s and c.relname = %s
         order by p.polname
        """
        % (dbmod_sql_literal(schema), dbmod_sql_literal(rel))
    )
    out: List[PolicyInfo] = []
    if not res.ok:
        return out
    for row in res.rows:
        flags: List[str] = []
        if _LITERAL_TRUE_RE.match(row[5]) or _LITERAL_TRUE_RE.match(row[6]):
            flags.append("PERMISSIVE_TRUE")
        if row[4] == "PUBLIC":
            flags.append("APPLIES_TO_PUBLIC")
        if any(r in ("anon",) for r in row[4].split(",")):
            flags.append("APPLIES_TO_ANON")
        if _LITERAL_TRUE_RE.match(row[5]) and _LITERAL_TRUE_RE.match(row[6]) and row[2] == "*":
            flags.append("WIDE_OPEN")
        out.append(
            PolicyInfo(
                table=f"{schema}.{rel}",
                policy=row[1],
                command=POLCMD_NAMES.get(row[2], row[2]),
                permissive=POLPERMISSIVE.get(row[3], str(row[3])),
                roles=row[4],
                using_expr=row[5],
                with_check_expr=row[6],
                flags=flags,
            )
        )
    return out


def _count_as(session: dbmod.Session, table: str) -> Optional[int]:
    res = session.run(f"select count(*) from {table}")
    if not res.ok or not res.rows:
        return None
    return int(res.rows[0][0])


def _object_state(session: dbmod.Session, obj: AuditObject) -> Optional[Dict[str, Any]]:
    """Read what a view or function actually is, from the catalog."""
    if obj.kind == "view":
        schema, rel = _split_relation(obj.name)
        res = session.run(
            """
            select c.relkind::text, pg_get_userbyid(c.relowner),
                   coalesce(array_to_string(c.reloptions, ','), ''),
                   n.nspname
              from pg_class c
              join pg_namespace n on n.oid = c.relnamespace
             where n.nspname = %s and c.relname = %s
            """
            % (dbmod_sql_literal(schema), dbmod_sql_literal(rel))
        )
        if not res.ok or not res.rows:
            return None
        row = res.rows[0]
        opts = row[2] or ""
        return {
            "kind": row[0],
            "owner": row[1],
            "reloptions": opts,
            "security_invoker": "security_invoker=on" in opts.replace(" ", ""),
        }
    # function
    schema, rel = _split_relation(obj.name)
    rel = rel.split("(")[0]
    res = session.run(
        """
        select p.prosecdef, pg_get_userbyid(p.proowner),
               pg_get_function_identity_arguments(p.oid),
               n.nspname, p.proretset, p.prorettype::regtype::text
          from pg_proc p
          join pg_namespace n on n.oid = p.pronamespace
         where n.nspname = %s and p.proname = %s
        """
        % (dbmod_sql_literal(schema), dbmod_sql_literal(rel))
    )
    if not res.ok or not res.rows:
        return None
    row = res.rows[0]
    prosecdef = bool(row[0])
    proretset = bool(row[4])
    # A SECURITY DEFINER function that returns a scalar cannot hand back rows,
    # however it is invoked. That is the intended use of SECURITY DEFINER.
    # Only a set-returning one can leak.
    can_leak = prosecdef and proretset
    return {
        "kind": "function",
        "owner": row[1],
        "security_definer": prosecdef,
        "arguments": row[2],
        "returns_set": proretset,
        "returns": row[5],
        "security_invoker": not can_leak,
        "scalar_helper": prosecdef and not proretset,
    }


def _audit_object_results(
    session: dbmod.Session, definition: SuiteDefinition
) -> List[PreflightResult]:
    """Check that each declared view/function is in the state the definition
    says it is. This is what makes a leaky view fail BY NAME."""
    out: List[PreflightResult] = []
    for obj in definition.audit_objects:
        state = _object_state(session, obj)
        ident = f"preflight.{obj.name}"
        if state is None:
            out.append(
                PreflightResult(
                    id=ident,
                    status=FAIL,
                    target=obj.name,
                    message=(
                        f"{obj.kind} {obj.name} does not exist. (For functions, "
                        f"give the name with its argument list if it is "
                        f"overloaded, e.g. public.f(uuid).)"
                    ),
                )
            )
            continue
        invoker = bool(state.get("security_invoker"))
        if obj.kind == "view":
            label = "WITH (security_invoker = on)" if invoker else "WITHOUT security_invoker"
        elif state.get("scalar_helper"):
            label = (
                f"SECURITY DEFINER returning {state.get('returns')} (a scalar, "
                f"so it cannot leak rows)"
            )
        elif invoker:
            label = "SECURITY INVOKER"
        else:
            label = f"SECURITY DEFINER returning {state.get('returns')}"
        if obj.expect == "safe" and not invoker:
            out.append(
                PreflightResult(
                    id=ident,
                    status=FAIL,
                    target=obj.name,
                    message=(
                        f"{obj.kind} {obj.name} is {label} (owner {state['owner']}). "
                        + (
                            "A view with security_invoker off executes as its "
                            "owner, and a table owner is not subject to that "
                            "table's Row Level Security -- so this view returns "
                            f"every tenant's rows no matter how good the "
                            f"policies on the base table are. Fix: "
                            f"ALTER VIEW {obj.name} SET (security_invoker = on); "
                            f"(PostgreSQL 15+). On PostgreSQL 14 and older you "
                            f"have no equivalent: do not expose views over RLS "
                            f"tables, or recreate the view owned by a role with "
                            f"neither BYPASSRLS nor table ownership."
                            if obj.kind == "view"
                            else "A SECURITY DEFINER function executes as its "
                            "owner, who is not subject to Row Level Security. "
                            "That is correct for a boolean helper and wrong for "
                            "anything that returns rows. Fix: declare it "
                            "SECURITY INVOKER, or make its body filter by "
                            "auth.uid() explicitly."
                        )
                    ),
                    detail=obj.why,
                )
            )
        elif obj.expect == "unsafe" and invoker:
            out.append(
                PreflightResult(
                    id=ident,
                    status=FAIL,
                    target=obj.name,
                    message=(
                        f"{obj.kind} {obj.name} is {label}, but this definition "
                        f"declares it as a KNOWN LEAK (expect=\"unsafe\"). The "
                        f"demonstration would be empty: the checks beside it "
                        f"would pass for the right reason and prove nothing. "
                        f"Either the object was fixed (delete this negative "
                        f"control) or it was never broken."
                    ),
                    detail=obj.why,
                )
            )
        else:
            out.append(
                PreflightResult(
                    id=ident,
                    status=PASS if obj.expect == "safe" else WARN,
                    target=obj.name,
                    message=(
                        f"{obj.kind} {obj.name} is {label}"
                        + (
                            " -- as this definition declares"
                            if obj.expect == "unsafe"
                            else ""
                        )
                    ),
                    detail=(
                        f"owner={state['owner']} reloptions={state.get('reloptions', '')}"
                        f"{' (' + obj.why + ')' if obj.why else ''}"
                    ),
                )
            )
    return out


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
def preflight(
    definition: SuiteDefinition,
    admin: dbmod.Session,
    strict_audit: bool = False,
) -> Tuple[List[PreflightResult], List[PolicyInfo]]:
    """Everything that must be true before a single check means anything."""
    results: List[PreflightResult] = []
    all_policies: List[PolicyInfo] = []
    strict = strict_audit or definition.strict_audit

    # --- the anti-vacuity anchor must really bypass RLS --------------------
    # Every deny check is validated by running the same statement as this
    # identity. If it does not actually bypass RLS, it cannot prove that the
    # data exists, and every denial in the suite is unverified.
    who = admin.scalar("select current_user")
    bypass = admin.scalar(
        "select (rolsuper or rolbypassrls) from pg_roles where rolname = current_user"
    )
    if bypass is None:
        results.append(
            PreflightResult(
                id="preflight.admin_identity",
                status=FAIL,
                target=definition.admin_identity,
                message=(
                    f"could not read the role attributes for the admin identity "
                    f"{definition.admin_identity!r}. The runner must be able to "
                    f"prove this identity bypasses RLS."
                ),
            )
        )
    elif not bypass:
        results.append(
            PreflightResult(
                id="preflight.admin_identity",
                status=FAIL,
                target=definition.admin_identity,
                message=(
                    f"the admin identity {definition.admin_identity!r} resolves to "
                    f"the role {who!r}, which is neither a superuser nor BYPASSRLS. "
                    f"It is therefore subject to Row Level Security, so it cannot "
                    f"prove that the rows a deny check looks for actually exist, and "
                    f"every 'deny' result in this suite is unverified. Use "
                    f"service_role (which has BYPASSRLS on Supabase), a superuser, "
                    f"or a role granted BYPASSRLS."
                ),
            )
        )
    else:
        results.append(
            PreflightResult(
                id="preflight.admin_identity",
                status=PASS,
                target=definition.admin_identity,
                message=(
                    f"the admin identity {definition.admin_identity!r} acts as role "
                    f"{who!r}, which bypasses RLS and can therefore prove that the "
                    f"fixture data exists"
                ),
                detail=(
                    "admin_identity was inferred from the declared identities"
                    if definition.admin_identity_inferred
                    else "admin_identity was named explicitly by the definition"
                ),
            )
        )
    if definition.admin_identity_inferred:
        results.append(
            PreflightResult(
                id="preflight.admin_identity_inferred",
                status=INFO,
                target=definition.admin_identity,
                message=(
                    f"the definition does not name an admin_identity, so "
                    f"{definition.admin_identity!r} was chosen as the identity that "
                    f"was already declared. Set admin_identity explicitly if that is "
                    f"not the one you meant."
                ),
            )
        )

    if not definition.fixtures:
        results.append(
            PreflightResult(
                id="preflight.fixtures_declared",
                status=WARN,
                target=definition.suite,
                message=(
                    "The definition declares no fixtures. Anti-vacuity guards are "
                    "limited: a deny check against an empty table will pass "
                    "silently. Add a \"fixtures\": {\"tables\": [...]} block."
                ),
            )
        )

    for fx in definition.fixtures:
        table = fx.table
        info = _table_info(admin, table)
        if info is None:
            results.append(
                PreflightResult(
                    id=f"preflight.{table}.exists",
                    status=FAIL,
                    target=table,
                    message=(
                        f"table {table} does not exist (or the runner has no "
                        f"privilege to see it). Every check against it is "
                        f"meaningless."
                    ),
                )
            )
            continue

        # --- RLS must be on ------------------------------------------------
        if info["relkind"] != "r" and info["relkind"] != "p":
            results.append(
                PreflightResult(
                    id=f"preflight.{table}.relkind",
                    status=FAIL,
                    target=table,
                    message=(
                        f"{table} is a {info['relkind']!r} relation, not a table. "
                        f"A view does not have policies of its own -- it is "
                        f"governed by its owner unless it is declared "
                        f"WITH (security_invoker = on). Test the base table, or "
                        f"add a check that reads the view as an identity."
                    ),
                )
            )
            continue

        if fx.rls_required and not info["rls_enabled"]:
            results.append(
                PreflightResult(
                    id=f"preflight.{table}.rls_enabled",
                    status=FAIL,
                    target=table,
                    message=(
                        f"ROW LEVEL SECURITY IS DISABLED on {table}. "
                        f"relrowsecurity = false. Every row of this table is "
                        f"visible to every role holding a SELECT privilege, and "
                        f"every 'deny' check written against it is guaranteed to "
                        f"fail. This is the single most common way to leak a "
                        f"whole table. Fix: "
                        f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;"
                    ),
                    detail=f"owner={info['owner']} policies={info['n_policies']} forced={info['rls_forced']}",
                )
            )
            continue
        if fx.rls_required and info["rls_enabled"]:
            results.append(
                PreflightResult(
                    id=f"preflight.{table}.rls_enabled",
                    status=PASS,
                    target=table,
                    message=f"RLS is enabled on {table}",
                    detail=(
                        f"owner={info['owner']} policies={info['n_policies']} "
                        f"force_rls={info['rls_forced']}"
                    ),
                )
            )

        # --- owner bypass, if it is relevant ------------------------------
        if info["rls_enabled"] and not info["rls_forced"]:
            me = who
            if me is not None and str(me) == str(info["owner"]):
                results.append(
                    PreflightResult(
                        id=f"preflight.{table}.owner_bypass",
                        status=WARN,
                        target=table,
                        message=(
                            f"the identity this runner connects as ({me}) OWNS "
                            f"{table}, and the table does not FORCE ROW LEVEL "
                            f"SECURITY, so the owner bypasses its policies. Any "
                            f"check run as that identity would see every row. "
                            f"Run the suite as a non-owner role (this pack's "
                            f"admin identity uses service_role/BYPASSRLS for "
                            f"exactly that reason)."
                        ),
                    )
                )

        # --- policies exist ------------------------------------------------
        policies = _load_policies(admin, table)
        all_policies.extend(policies)
        if fx.expect_policy and not policies:
            results.append(
                PreflightResult(
                    id=f"preflight.{table}.has_policies",
                    status=FAIL,
                    target=table,
                    message=(
                        f"RLS is enabled on {table} but there are NO POLICIES. "
                        f"With RLS on and no policy, PostgreSQL denies "
                        f"everything: every 'allow' check will fail and every "
                        f"'deny' check will pass for the wrong reason. A deny "
                        f"check that passes here is not evidence of isolation."
                    ),
                )
            )

        # --- the permissive-policy sniff test ------------------------------
        for pol in policies:
            if "PERMISSIVE_TRUE" in pol.flags:
                status = FAIL if strict else WARN
                results.append(
                    PreflightResult(
                        id=f"preflight.{table}.{pol.policy}.permissive",
                        status=status,
                        target=f"{table}.{pol.policy}",
                        message=(
                            f"policy {pol.policy!r} on {table} uses a literal "
                            f"TRUE expression, which grants everything it "
                            f"applies to. "
                            f"FOR {pol.command} TO {pol.roles} "
                            f"USING {pol.using_expr} WITH CHECK {pol.with_check_expr}. "
                            f"A USING (true) left in from development is the "
                            f"second most common leak: the table looks "
                            f"protected, `select * from pg_policies` returns a "
                            f"row, and every row is readable."
                        ),
                        detail="flags=" + ",".join(pol.flags),
                    )
                )
            if "APPLIES_TO_PUBLIC" in pol.flags:
                results.append(
                    PreflightResult(
                        id=f"preflight.{table}.{pol.policy}.applies_to_public",
                        status=WARN,
                        target=f"{table}.{pol.policy}",
                        message=(
                            f"policy {pol.policy!r} on {table} has no TO clause, "
                            f"so it applies to PUBLIC -- every role, including "
                            f"anon. Add an explicit TO authenticated (or TO the "
                            f"exact role you mean)."
                        ),
                    )
                )

    # --- fixture data actually exists -------------------------------------
    for fx in definition.fixtures:
        if fx.min_rows <= 0:
            continue
        n = _count_as(admin, fx.table)
        if n is None:
            continue
        if n < fx.min_rows:
            results.append(
                PreflightResult(
                    id=f"preflight.{fx.table}.row_count",
                    status=FAIL,
                    target=fx.table,
                    message=(
                        f"{fx.table} holds {n} row(s); the definition requires at "
                        f"least {fx.min_rows}. A deny check against a table with "
                        f"too few rows can pass without testing anything. Load "
                        f"the fixtures (setup files are listed in the definition)."
                    ),
                )
            )
        else:
            results.append(
                PreflightResult(
                    id=f"preflight.{fx.table}.row_count",
                    status=PASS,
                    target=fx.table,
                    message=f"{fx.table} holds {n} row(s) (minimum {fx.min_rows})",
                    detail=fx.note,
                )
            )
    # --- views and functions the definition makes claims about -------------
    results.extend(_audit_object_results(admin, definition))

    return results, all_policies


# ---------------------------------------------------------------------------
# Policy audit (standalone -- used by --audit-schema)
# ---------------------------------------------------------------------------
def audit_schema(dsn: str, schema: str) -> Tuple[List[PolicyInfo], List[PreflightResult]]:
    """Report every table in `schema` that is not actually protected."""
    findings: List[PreflightResult] = []
    policies: List[PolicyInfo] = []
    sess = dbmod.Session(
        dsn, Identity(name="audit", role=None), verbose=False
    )
    sess.open()
    try:
        res = sess.run(
            """
            select c.relname, c.relrowsecurity, c.relforcerowsecurity,
                   pg_get_userbyid(c.relowner),
                   (select count(*) from pg_policy p where p.polrelid = c.oid)
              from pg_class c
              join pg_namespace n on n.oid = c.relnamespace
             where n.nspname = %s
               and c.relkind in ('r', 'p')
             order by c.relname
            """
            % dbmod_sql_literal(schema)
        )
        if not res.ok:
            findings.append(
                PreflightResult(
                    id="audit.connect",
                    status=ERROR,
                    target=schema,
                    message="could not read pg_class: " + (res.error or ""),
                )
            )
            return policies, findings
        for row in res.rows:
            name, rls, forced, owner, n_pol = row
            full = f"{schema}.{name}"
            if not rls:
                findings.append(
                    PreflightResult(
                        id=f"audit.{full}.rls_disabled",
                        status=FAIL,
                        target=full,
                        message=(
                            f"RLS DISABLED on {full} (owner {owner}, {n_pol} "
                            f"policies). Alter: ALTER TABLE {full} ENABLE ROW "
                            f"LEVEL SECURITY;"
                        ),
                    )
                )
            elif n_pol == 0:
                findings.append(
                    PreflightResult(
                        id=f"audit.{full}.no_policies",
                        status=FAIL,
                        target=full,
                        message=(
                            f"RLS enabled on {full} with ZERO policies: "
                            f"fail-closed. Nobody can read it through a "
                            f"non-owner role. Probably a migration that enabled "
                            f"RLS and never added the policies."
                        ),
                    )
                )
            else:
                findings.append(
                    PreflightResult(
                        id=f"audit.{full}.ok",
                        status=PASS,
                        target=full,
                        message=f"{full}: RLS on, {n_pol} policies",
                        detail=f"owner={owner} force_rls={forced}",
                    )
                )
            pols = _load_policies(sess, full)
            policies.extend(pols)
            for pol in pols:
                if "PERMISSIVE_TRUE" in pol.flags:
                    findings.append(
                        PreflightResult(
                            id=f"audit.{full}.{pol.policy}",
                            status=FAIL,
                            target=f"{full}.{pol.policy}",
                            message=(
                                f"permissive policy {pol.policy!r} on {full}: "
                                f"FOR {pol.command} TO {pol.roles} "
                                f"USING {pol.using_expr} "
                                f"WITH CHECK {pol.with_check_expr}"
                            ),
                        )
                    )
        # -- views over RLS tables do not run as the caller by default ------
        # Which tables a view reads is taken from the catalog's dependency
        # graph, not from the text of pg_get_viewdef(): the deparsed definition
        # omits the schema name for anything already on the search_path, so a
        # regex over it silently finds nothing and the audit under-reports.
        vres = sess.run(
            """
            select c.relname,
                   pg_get_userbyid(c.relowner),
                   coalesce(array_to_string(c.reloptions, ','), ''),
                   coalesce((
                     select string_agg(distinct dn.nspname || '.' || dc.relname, ', ')
                       from pg_rewrite rw
                       join pg_depend d  on d.objid = rw.oid
                       join pg_class dc on dc.oid = d.refobjid
                       join pg_namespace dn on dn.oid = dc.relnamespace
                      where rw.ev_class = c.oid
                        and dc.oid <> c.oid
                        and dc.relkind in ('r', 'p', 'v', 'm', 'f')
                   ), '') as reads
              from pg_class c
              join pg_namespace n on n.oid = c.relnamespace
             where n.nspname = %s and c.relkind = 'v'
             order by c.relname
            """
            % dbmod_sql_literal(schema)
        )
        if vres.ok:
            for row in vres.rows:
                vname, vowner, vopts, vreads = row
                full = f"{schema}.{vname}"
                if "security_invoker=on" in (vopts or "").replace(" ", ""):
                    findings.append(
                        PreflightResult(
                            id=f"audit.{full}.view",
                            status=PASS,
                            target=full,
                            message=f"{full}: security_invoker = on, RLS of the base tables applies",
                            detail=f"owner={vowner}",
                        )
                    )
                else:
                    findings.append(
                        PreflightResult(
                            id=f"audit.{full}.view",
                            status=WARN,
                            target=full,
                            message=(
                                f"view {full} runs as its owner ({vowner}), not "
                                f"as the caller: no security_invoker. It reads "
                                f"{vreads or 'no base relations'}. If any of those "
                                f"tables has RLS, this view returns rows that RLS "
                                f"would have hidden. Add "
                                f"ALTER VIEW {full} SET (security_invoker = on); "
                                f"or accept the risk deliberately and note it here."
                            ),
                        )
                    )
        # -- SECURITY DEFINER functions -------------------------------------
        fres = sess.run(
            """
            select p.proname, pg_get_userbyid(p.proowner),
                   pg_get_function_identity_arguments(p.oid),
                   p.prorettype::regtype::text,
                   p.proretset
              from pg_proc p
              join pg_namespace n on n.oid = p.pronamespace
             where n.nspname = %s and p.prosecdef
             order by p.proname
            """
            % dbmod_sql_literal(schema)
        )
        if fres.ok:
            for row in fres.rows:
                fname, fowner, fargs, fret, fretset = row
                full = f"{schema}.{fname}({fargs})"
                # proretset is the authoritative signal. A SECURITY DEFINER
                # function that does not return a set cannot hand back rows, so
                # it cannot leak them -- that is the intended use, and flagging
                # it would be a false positive that teaches buyers to ignore
                # the report.
                returns_rows = bool(fretset)
                findings.append(
                    PreflightResult(
                        id=f"audit.{full}.security_definer",
                        status=FAIL if returns_rows else INFO,
                        target=full,
                        message=(
                            f"function {full} is SECURITY DEFINER (owner {fowner}) "
                            f"and returns {fret}. "
                            + (
                                "It executes as its owner, who is not subject to "
                                "Row Level Security, so it can return every "
                                "tenant's rows regardless of the caller. Make it "
                                "SECURITY INVOKER, or filter its body by "
                                "auth.uid() explicitly."
                                if returns_rows
                                else f"It returns a single {fret}, not a set, so "
                                "it cannot hand back rows and cannot leak them. "
                                "That is the intended use of SECURITY DEFINER: a "
                                "helper that answers a yes/no question about the "
                                "caller. Worth confirming the body filters by "
                                "auth.uid() rather than answering a question about "
                                "the caller's tenant in general."
                            )
                        ),
                    )
                )
    finally:
        sess.close()
    return policies, findings


# ---------------------------------------------------------------------------
# Check evaluation
# ---------------------------------------------------------------------------
def _count_query(sql: str) -> str:
    stripped = _TRAILING_SEMI_RE.sub("", sql.strip())
    return f"select count(*) from (\n{stripped}\n) as _rls_suite_count"


def _evaluate(check: Check, res: dbmod.Result, true_count: int) -> Tuple[str, str]:
    """Return (status, message) for a completed statement."""

    if not res.ok:
        err = res.error or "unknown error"
        if check.expect == "error":
            if check.error_match and not re.search(check.error_match, err):
                return FAIL, (
                    f"expected an error matching /{check.error_match}/, got: {err}"
                )
            if check.error_not_match and re.search(check.error_not_match, err):
                return FAIL, (
                    f"error matched the forbidden pattern /{check.error_not_match}/: {err}"
                )
            return PASS, f"refused as expected: {err.splitlines()[0]}"
        if check.expect == "deny":
            if res.is_rls_error:
                return PASS, f"refused by a policy: {err.splitlines()[0]}"
            return ERROR, (
                f"the statement failed, but not because of Row Level Security, so "
                f"it is not evidence that the row is protected: {err.splitlines()[0]}"
            )
        if check.expect == "ok":
            return FAIL, f"expected the statement to succeed, it failed: {err.splitlines()[0]}"
        return ERROR, f"statement failed: {err.splitlines()[0]}"

    # -- the statement succeeded -------------------------------------------
    if check.expect == "error":
        return FAIL, (
            f"expected an error and the statement SUCCEEDED"
            + (f" (affected {true_count} row(s))" if true_count else "")
            + ". The policy that should have refused this is missing or too "
              "permissive."
        )
    if check.expect == "ok":
        return PASS, "statement succeeded"

    if check.expect == "allow":
        if check.mode == "write":
            if true_count >= 1:
                return PASS, f"allowed: {true_count} row(s) affected"
            return FAIL, (
                "expected this write to be allowed, but 0 rows were affected. "
                "Either no policy permits it, or the SELECT policy does not "
                "also allow the row -- PostgreSQL applies both to UPDATE and "
                "DELETE, and a row you cannot see is a row you cannot change."
            )
        if true_count >= 1:
            return PASS, f"allowed: {true_count} row(s) visible"
        return FAIL, (
            "expected at least 1 row, got 0. No policy permits this identity "
            "to see these rows."
        )

    if check.expect == "deny":
        if true_count == 0:
            return PASS, "denied: 0 rows"
        if check.mode == "write":
            return FAIL, (
                f"LEAK: this identity was allowed to modify {true_count} row(s) "
                f"belonging to another tenant."
            )
        return FAIL, (
            f"LEAK: this identity read {true_count} row(s) it should not be "
            f"able to read."
        )

    if check.expect == "rows":
        if true_count == check.rows:
            return PASS, f"row count is exactly {check.rows} as expected"
        return FAIL, f"expected exactly {check.rows} row(s), got {true_count}"

    if check.expect == "value":
        if not res.rows:
            return FAIL, (
                "expected the statement to produce a value and it returned no "
                "rows at all"
            )
        got = res.rows[0][0]
        if _values_equal(got, check.value):
            return PASS, f"value is {got!r} as expected"
        return FAIL, (
            f"expected the value {check.value!r}, got {got!r}. "
            + (
                "An aggregate that counts more rows than this identity is "
                "allowed to see means the rows are visible to it."
                if isinstance(check.value, (int, float)) and isinstance(got, (int, float))
                else "The statement is well formed but returns something else."
            )
        )

    return ERROR, f"unhandled expectation {check.expect!r}"


def _apply_bounds(check: Check, status: str, message: str, true_count: int) -> Tuple[str, str]:
    if status != PASS:
        return status, message
    if check.min_rows is not None and true_count < check.min_rows:
        return FAIL, f"{message}; but min_rows={check.min_rows} and only {true_count} matched"
    if check.max_rows is not None and true_count > check.max_rows:
        return FAIL, f"{message}; but max_rows={check.max_rows} and {true_count} matched"
    return status, message


def run_checks(
    definition: SuiteDefinition,
    sessions: Dict[str, dbmod.Session],
    fetch_limit: int = 500,
    verbose: bool = False,
) -> List[CheckResult]:
    results: List[CheckResult] = []
    for check in definition.checks:
        sess = sessions.get(check.identity)
        if sess is None:
            results.append(
                CheckResult(
                    id=check.id,
                    status=ERROR,
                    identity=check.identity,
                    mode=check.resolved_mode,
                    expect=check.expect,
                    sql="",
                    message=f"no session for identity {check.identity!r}",
                    why=check.why,
                )
            )
            continue

        sql = definition.resolve(check.sql)
        res = sess.run(sql)
        mode = check.resolved_mode

        # A read that hit the fetch limit needs a real count before we compare.
        true_count = res.rowcount if res.ok else 0
        truncated = False
        if res.ok and mode == "read":
            if len(res.rows) >= fetch_limit:
                truncated = True
                counted = sess.run(_count_query(sql))
                if counted.ok and counted.rows:
                    true_count = int(counted.rows[0][0])
                else:
                    true_count = len(res.rows)
            else:
                true_count = len(res.rows)

        status, message = _evaluate(check, res, true_count)
        status, message = _apply_bounds(check, status, message, true_count)

        sanity: Optional[Dict[str, Any]] = None
        if (
            status == PASS
            and check.expect == "deny"
            and check.sanity_as
            and (mode == "read" or check.sanity_as is not None)
            and check.sanity_as != check.identity
        ):
            s_sess = sessions.get(check.sanity_as)
            if s_sess is None:
                status = ERROR
                message = f"sanity identity {check.sanity_as!r} has no session"
            else:
                s_res = s_sess.run(sql)
                # A read proves non-vacuity by returning rows; a write proves it
                # by AFFECTING rows. An INSERT/UPDATE/DELETE has no result set,
                # so len(rows) is always 0 and would make every write sanity
                # check look empty.
                if mode == "write":
                    s_count = s_res.rowcount if s_res.ok else 0
                else:
                    s_count = len(s_res.rows)
                    if s_res.ok and s_count >= fetch_limit:
                        counted = s_sess.run(_count_query(sql))
                        if counted.ok and counted.rows:
                            s_count = int(counted.rows[0][0])
                sanity = {
                    "identity": check.sanity_as,
                    "ok": s_res.ok,
                    "row_count": s_count if s_res.ok else 0,
                    "mode": mode,
                    "error": s_res.error,
                }
                if not s_res.ok:
                    if check.sanity_required:
                        status = INCONCLUSIVE
                        message = (
                            f"the deny could not be validated: the sanity "
                            f"identity {check.sanity_as!r} could not even run "
                            f"the query ({s_res.error.splitlines()[0] if s_res.error else ''}). "
                            f"A 0-row result proves nothing here."
                        )
                elif s_count == 0:
                    if check.sanity_required:
                        status = INCONCLUSIVE
                        message = (
                            f"the deny could not be validated: the sanity "
                            f"identity {check.sanity_as!r} also sees 0 rows for "
                            f"this query, so a 0-row result for "
                            f"{check.identity!r} proves nothing. Either the "
                            f"fixture data is missing, or the query does not "
                            f"select what you think it selects."
                        )

        results.append(
            CheckResult(
                id=check.id,
                status=status,
                identity=check.identity,
                mode=mode,
                expect=check.expect,
                sql=sql,
                table=check.table or "",
                message=message,
                why=check.why,
                row_count=true_count if res.ok else 0,
                rows=[[_jsonable(v) for v in row] for row in res.rows[:10]],
                columns=list(res.columns),
                truncated=truncated,
                error=res.error or "",
                sqlstate=res.sqlstate,
                is_rls_error=res.is_rls_error,
                observed_value=(
                    _jsonable(res.rows[0][0]) if (res.ok and res.rows) else None
                ),
                expected_value=check.value,
                sanity=sanity,
                duration_ms=res.duration_ms,
            )
        )
    return results


def _values_equal(got: Any, want: Any) -> bool:
    """Compare a database scalar with the JSON value in the definition.

    Tolerant where the type only differs because of the wire format: JSON has
    one number type, so an int in the definition may come back as a Decimal,
    and a Postgres boolean may come back as a Python bool."""
    if got == want:
        return True
    try:
        if isinstance(want, bool) or isinstance(got, bool):
            return bool(got) is bool(want)
        if isinstance(want, (int, float)) and isinstance(got, (int, float)):
            return float(got) == float(want)
        if isinstance(got, str) and str(want) == got:
            return True
        return float(got) == float(want)  # Decimal("3") vs 3
    except (TypeError, ValueError):
        return str(got) == str(want)


def _jsonable(value: Any) -> Any:
    import datetime
    import decimal
    import uuid

    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
        return value.isoformat()
    if isinstance(value, decimal.Decimal):
        # JSON has one number type, so a Decimal is rendered as a number when it
        # is finite, and as a string otherwise (NaN/Infinity are not JSON).
        return float(value) if value.is_finite() else str(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return value.hex() if not isinstance(value, memoryview) else bytes(value).hex()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def run_suite(
    definition: SuiteDefinition,
    dsn: str,
    do_setup: bool = True,
    strict_audit: bool = False,
    fetch_limit: int = 500,
    verbose: bool = False,
) -> SuiteRun:
    started = time.time()
    run = SuiteRun(
        suite=definition.suite,
        title=definition.title,
        path=definition.path,
        dsn=dsn,
        expected_outcome=definition.expected_outcome,
    )

    dbmod.check_reachable(dsn)
    run.server_version = dbmod.server_version(dsn)

    if do_setup and (definition.setup or definition.setup_reset):
        run.setup = dbmod.apply_setup(dsn, definition, verbose=verbose)
        if any(not s.ok for s in run.setup):
            run.preflight.append(
                PreflightResult(
                    id="preflight.setup",
                    status=FAIL,
                    target="setup",
                    message="a setup step failed; no check was run",
                    detail="; ".join(
                        f"{s.name}: {s.detail}" for s in run.setup if not s.ok
                    ),
                )
            )
            run.duration_ms = (time.time() - started) * 1000.0
            return run

    names = sorted(definition.identities)
    sessions = dbmod.open_sessions(dsn, names, definition)
    try:
        admin = sessions[definition.admin_identity]
        pf, policies = preflight(definition, admin, strict_audit=strict_audit)
        run.preflight = pf
        run.policies = policies
        if any(p.status in (FAIL, ERROR) for p in pf):
            run.preflight.append(
                PreflightResult(
                    id="preflight.checks_still_run",
                    status=WARN,
                    target="preflight",
                    message=(
                        "preflight found a problem, so the checks below are NOT "
                        "evidence that isolation works. They are still run, "
                        "because a check that leaks here shows you exactly which "
                        "rows are exposed -- which is more useful than a "
                        "refusal. Read the preflight failures first."
                    ),
                )
            )
        run.checks = run_checks(
            definition, sessions, fetch_limit=fetch_limit, verbose=verbose
        )
    finally:
        dbmod.close_sessions(sessions)

    run.duration_ms = (time.time() - started) * 1000.0
    return run
