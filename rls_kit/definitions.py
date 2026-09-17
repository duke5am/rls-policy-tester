"""Loading and validating a declarative RLS test suite.

A suite is a JSON document (YAML also works if PyYAML is installed). It names
the tables it cares about, the identities it will act as, and the expected
allow/deny outcome of each statement.

The format is documented in tests_definitions/README.md. This module's only
job is to turn a file into a SuiteDefinition, or to refuse it with a message
that says which key is wrong.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

SCHEMA_VERSION = 1

# Which identities exist and what they mean.
KINDS = ("read", "write")

# What a check may expect.
EXPECTATIONS = ("allow", "deny", "error", "ok", "rows", "value")

# A colon that is not part of a PostgreSQL cast (::type) and is at a token
# boundary starts a parameter reference.
_PARAM_RE = re.compile(r"(?<![:\w]):([A-Za-z_][A-Za-z0-9_]*)")

# Leading keyword of a statement, ignoring leading comments and whitespace.
_LEADING_KEYWORD_RE = re.compile(
    r"\A(?:\s|--[^\n]*\n|/\*.*?\*/)*([A-Za-z_]+)", re.DOTALL
)

_WRITE_KEYWORDS = {"insert", "update", "delete", "merge"}
_READ_KEYWORDS = {"select", "values", "table", "with"}


class DefinitionError(Exception):
    """A suite definition is malformed. Always names the offending key."""


# ---------------------------------------------------------------------------
# Identities
# ---------------------------------------------------------------------------
@dataclass
class Identity:
    """One actor the suite can be. Usually a Postgres role plus a JWT."""

    name: str
    role: Optional[str] = None
    user_id: Optional[str] = None
    claims: Dict[str, Any] = field(default_factory=dict)
    dsn: Optional[str] = None
    description: str = ""

    @property
    def is_admin(self) -> bool:
        """True for the identity whose view of the world is unfiltered."""
        return bool(self.claims.get("_admin"))

    def resolved_claims(self) -> Dict[str, Any]:
        """The JWT claims JSON the runner installs for this identity."""
        out = {k: v for k, v in self.claims.items() if not k.startswith("_")}
        if self.user_id is not None:
            out.setdefault("sub", self.user_id)
        if self.role is not None:
            out.setdefault("role", self.role)
        return out


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------
@dataclass
class Check:
    """One assertion: this identity runs this SQL and must get this outcome."""

    id: str
    identity: str
    sql: str
    expect: str
    why: str = ""
    mode: str = "auto"
    rows: Optional[int] = None
    value: Any = None
    min_rows: Optional[int] = None
    max_rows: Optional[int] = None
    error_match: Optional[str] = None
    error_not_match: Optional[str] = None
    sanity_as: Optional[str] = None
    sanity_required: bool = True
    table: Optional[str] = None

    @property
    def resolved_mode(self) -> str:
        """'read' for statements that return rows, 'write' for the rest."""
        if self.mode in KINDS:
            return self.mode
        kw = leading_keyword(self.sql)
        if kw in _WRITE_KEYWORDS:
            return "write"
        if kw == "with":
            # A CTE is a write only if it ends in one. Look for the verb after
            # the CTE list -- approximate but right for every realistic case.
            tail = self.sql.lower()
            if re.search(r"\)\s*(insert|update|delete)\b", tail):
                return "write"
            return "read"
        if kw in _READ_KEYWORDS:
            return "read"
        # Anything we do not recognise is treated as a read: a surprise
        # statement that returns rows then has to return zero rows to pass,
        # which is the conservative direction.
        return "read"


def leading_keyword(sql: str) -> str:
    m = _LEADING_KEYWORD_RE.match(sql)
    return m.group(1).lower() if m else ""


# ---------------------------------------------------------------------------
# Fixtures / anti-vacuity declarations
# ---------------------------------------------------------------------------
@dataclass
class TableFixture:
    """A table the suite depends on, and what must be true of it."""

    table: str
    min_rows: int = 0
    rls_required: bool = True
    note: str = ""
    expect_policy: bool = True


@dataclass
class AuditObject:
    """A view or function the definition makes a claim about.

    A view does not have policies of its own. Unless it is declared
    WITH (security_invoker = on) it executes as its owner, and a table owner
    is not subject to that table's RLS -- so a view over a perfectly protected
    table can hand back every tenant's rows.

    A SECURITY DEFINER function has exactly the same property, from the same
    cause: it runs as its owner.

    `expect` says which state the definition believes the object is in:

        "safe"    -- the view has security_invoker=on, or the function is
                     SECURITY INVOKER. The suite fails if it is not.
        "unsafe"  -- a negative control: the definition is asserting that the
                     object DOES bypass RLS, so that the checks beside it can
                     demonstrate the leak. The suite fails if the object turns
                     out to be safe, because then the demonstration is empty.
    """

    kind: str  # "view" | "function"
    name: str
    expect: str = "safe"
    why: str = ""


@dataclass
class SuiteDefinition:
    path: str
    suite: str
    title: str = ""
    description: str = ""
    identities: Dict[str, Identity] = field(default_factory=dict)
    checks: List[Check] = field(default_factory=list)
    fixtures: List[TableFixture] = field(default_factory=list)
    params: Dict[str, Any] = field(default_factory=dict)
    setup: List[str] = field(default_factory=list)
    setup_reset: List[str] = field(default_factory=list)
    admin_identity: str = "admin"
    admin_identity_inferred: bool = True
    default_sanity_identity: Optional[str] = "admin"
    strict_audit: bool = False
    expected_outcome: str = "pass"  # "pass" | "fail"  (negative controls say "fail")
    tags: List[str] = field(default_factory=list)
    audit_objects: List["AuditObject"] = field(default_factory=list)

    def identity(self, name: str) -> Identity:
        if name not in self.identities:
            raise DefinitionError(
                f"{self.path}: no identity named {name!r}. "
                f"Known identities: {', '.join(sorted(self.identities)) or '(none)'}"
            )
        return self.identities[name]

    def checks_for(self, identity_name: str) -> List[Check]:
        return [c for c in self.checks if c.identity == identity_name]

    def resolve(self, text: str) -> str:
        """Expand :params in a SQL snippet, quoting values as SQL literals."""
        return expand_params(text, self.params, where=self.path)

    def resolve_setup_path(self, rel: str) -> str:
        """Resolve a setup file relative to the definition file's directory,
        then relative to the pack root (the definition's grandparent)."""
        if os.path.isabs(rel) and os.path.exists(rel):
            return rel
        here = os.path.dirname(os.path.abspath(self.path))
        candidates = [
            os.path.join(here, rel),
            os.path.join(os.path.dirname(here), rel),
            os.path.join(os.path.dirname(os.path.dirname(here)), rel),
            rel,
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
        raise DefinitionError(
            f"{self.path}: setup file {rel!r} not found. Looked in: "
            + ", ".join(os.path.normpath(c) for c in candidates)
        )


# ---------------------------------------------------------------------------
# Parameter expansion
# ---------------------------------------------------------------------------
def sql_literal(value: Any) -> str:
    """Render a Python value as a SQL literal.

    Strings are quoted and internal quotes doubled. Numbers, booleans and None
    become bare literals. This is used only for values that came from the
    definition file the operator is running -- it is not a user-input path --
    but it is written to be safe regardless.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    text = str(value).replace("'", "''")
    return "'" + text + "'"


def expand_params(text: str, params: Dict[str, Any], where: str = "<sql>") -> str:
    """Replace :name with the matching parameter value, as a SQL literal."""

    def _sub(m: "re.Match[str]") -> str:
        name = m.group(1)
        if name not in params:
            raise DefinitionError(
                f"{where}: SQL references parameter :{name} which is not defined. "
                f"Defined parameters: {', '.join(sorted(params)) or '(none)'}"
            )
        return sql_literal(params[name])

    return _PARAM_RE.sub(_sub, text)


_WHOLE_PARAM_RE = re.compile(r"\A:([A-Za-z_][A-Za-z0-9_]*)\Z")


def resolve_value(value: str, params: Dict[str, Any], where: str = "<value>") -> str:
    """Resolve a NON-SQL value that may be a bare parameter reference.

    Used for things like an identity's user id, which ends up inside a JSON
    document rather than in a statement. `:alice` becomes the raw parameter
    value with no SQL quoting; anything else is returned unchanged.
    """
    m = _WHOLE_PARAM_RE.match(value.strip())
    if not m:
        return value
    name = m.group(1)
    if name not in params:
        raise DefinitionError(
            f"{where}: references parameter :{name} which is not defined. "
            f"Defined parameters: {', '.join(sorted(params)) or '(none)'}"
        )
    return str(params[name])


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------
def _load_raw(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml  # type: ignore
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise DefinitionError(
                f"{path}: YAML definitions need PyYAML. Install it "
                f"(`pip install pyyaml`) or convert the file to JSON."
            ) from exc
        data = yaml.safe_load(text)
    else:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise DefinitionError(f"{path}: not valid JSON -- {exc}") from exc
    if not isinstance(data, dict):
        raise DefinitionError(f"{path}: top level must be a JSON object")
    return data


def _require(data: Dict[str, Any], key: str, path: str, type_: type) -> Any:
    if key not in data:
        raise DefinitionError(f"{path}: missing required key {key!r}")
    value = data[key]
    if not isinstance(value, type_):
        raise DefinitionError(
            f"{path}: key {key!r} must be {type_.__name__}, got {type(value).__name__}"
        )
    return value


def load_definition(path: str) -> SuiteDefinition:
    """Read, validate and return a suite definition."""
    data = _load_raw(path)

    version = data.get("schema_version", SCHEMA_VERSION)
    if version != SCHEMA_VERSION:
        raise DefinitionError(
            f"{path}: schema_version {version!r} is not supported by this runner "
            f"(expected {SCHEMA_VERSION})"
        )

    suite = _require(data, "suite", path, str)
    params = dict(data.get("params") or {})

    # ---- identities -------------------------------------------------------
    raw_ids = _require(data, "identities", path, dict)
    if not raw_ids:
        raise DefinitionError(f"{path}: 'identities' is empty")
    identities: Dict[str, Identity] = {}
    for name, spec in raw_ids.items():
        if not isinstance(spec, dict):
            raise DefinitionError(f"{path}: identity {name!r} must be an object")
        unknown = set(spec) - {
            "role",
            "user_id",
            "claims",
            "dsn",
            "description",
            "admin",
        }
        if unknown:
            raise DefinitionError(
                f"{path}: identity {name!r} has unknown key(s): "
                + ", ".join(sorted(unknown))
            )
        identities[name] = Identity(
            name=name,
            role=spec.get("role"),
            user_id=(
                resolve_value(str(spec["user_id"]), params, where=f"{path}:{name}")
                if spec.get("user_id") is not None
                else None
            ),
            claims=dict(spec.get("claims") or {}),
            dsn=spec.get("dsn"),
            description=spec.get("description", ""),
        )
        if spec.get("admin"):
            identities[name].claims["_admin"] = True
        if identities[name].role is None and identities[name].dsn is None:
            raise DefinitionError(
                f"{path}: identity {name!r} must set either 'role' or 'dsn'"
            )

    # ---- the anti-vacuity anchor -----------------------------------------
    # The admin identity is the one that bypasses RLS and is therefore allowed
    # to prove that the data a deny check looks for actually exists. An explicit
    # admin_identity must name a declared identity. When it is not given we look
    # for a sensible one rather than refusing to load, because a buyer's suite
    # may well not have an identity called "admin" -- and the runner verifies at
    # runtime that the identity really does bypass RLS, rather than trusting the
    # name. See engine.preflight().
    explicit_admin = data.get("admin_identity")
    if explicit_admin is not None and explicit_admin not in identities:
        raise DefinitionError(
            f"{path}: admin_identity {explicit_admin!r} is not one of the declared "
            f"identities ({', '.join(sorted(identities))}). The admin identity is "
            f"the one that bypasses RLS and is used to prove that a deny check is "
            f"not passing because the table is empty."
        )

    admin_inferred = False
    if explicit_admin is not None:
        admin_identity = explicit_admin
    else:
        admin_identity = None
        flagged = [n for n, i in identities.items() if i.is_admin]
        for candidate in ("admin", "service_role", "service", "superuser", "postgres"):
            if candidate in identities:
                admin_identity = candidate
                break
        if admin_identity is None and flagged:
            admin_identity = sorted(flagged)[0]
        if admin_identity is None:
            admin_identity = sorted(identities)[0]
        admin_inferred = True

    sane_default = data.get("default_sanity_identity")
    if sane_default is None:
        # Default to the admin identity we settled on, whatever it is called.
        default_sanity = admin_identity
    else:
        if sane_default not in identities:
            raise DefinitionError(
                f"{path}: default_sanity_identity {sane_default!r} is not a declared "
                f"identity ({', '.join(sorted(identities))})"
            )
        default_sanity = sane_default

    # ---- fixtures ---------------------------------------------------------
    fixtures: List[TableFixture] = []
    raw_fixtures = data.get("fixtures") or {}
    if isinstance(raw_fixtures, dict):
        raw_tables = raw_fixtures.get("tables") or []
    elif isinstance(raw_fixtures, list):
        raw_tables = raw_fixtures
    else:
        raise DefinitionError(f"{path}: 'fixtures' must be an object or a list")
    for spec in raw_tables:
        if isinstance(spec, str):
            fixtures.append(TableFixture(table=spec))
            continue
        if not isinstance(spec, dict) or "table" not in spec:
            raise DefinitionError(
                f"{path}: each fixture entry needs a 'table' key, got {spec!r}"
            )
        fixtures.append(
            TableFixture(
                table=spec["table"],
                min_rows=int(spec.get("min_rows", 0)),
                rls_required=bool(spec.get("rls_required", True)),
                note=spec.get("note", ""),
                expect_policy=bool(spec.get("expect_policy", True)),
            )
        )

    # ---- checks -----------------------------------------------------------
    raw_checks = _require(data, "checks", path, list)
    if not raw_checks:
        raise DefinitionError(f"{path}: 'checks' is empty")
    checks: List[Check] = []
    seen: Dict[str, int] = {}
    for idx, spec in enumerate(raw_checks):
        where = f"{path}: checks[{idx}]"
        if not isinstance(spec, dict):
            raise DefinitionError(f"{where}: must be an object")
        unknown = set(spec) - {
            "id", "as", "sql", "expect", "why", "mode", "rows", "value",
            "min_rows", "max_rows", "error_match", "error_not_match",
            "sanity_as", "sanity_required", "table",
        }
        if unknown:
            raise DefinitionError(
                f"{where}: unknown key(s): " + ", ".join(sorted(unknown))
            )
        cid = spec.get("id")
        if not cid or not isinstance(cid, str):
            raise DefinitionError(f"{where}: needs a non-empty string 'id'")
        if cid in seen:
            raise DefinitionError(f"{where}: duplicate check id {cid!r}")
        seen[cid] = idx

        who = spec.get("as")
        if who not in identities:
            raise DefinitionError(
                f"{where} ({cid}): 'as' must name a declared identity; "
                f"got {who!r}. Known: {', '.join(sorted(identities))}"
            )
        if "sql" not in spec:
            raise DefinitionError(f"{where} ({cid}): missing 'sql'")
        expect = spec.get("expect", "deny")
        if expect not in EXPECTATIONS:
            raise DefinitionError(
                f"{where} ({cid}): 'expect' must be one of "
                f"{', '.join(EXPECTATIONS)}; got {expect!r}"
            )
        if expect == "rows" and not isinstance(spec.get("rows"), int):
            raise DefinitionError(
                f"{where} ({cid}): expect='rows' requires an integer 'rows' key"
            )
        if expect == "value" and "value" not in spec:
            raise DefinitionError(
                f"{where} ({cid}): expect='value' requires a 'value' key -- the "
                f"scalar the first column of the first row must equal"
            )
        mode = spec.get("mode", "auto")
        if mode not in ("auto",) + KINDS:
            raise DefinitionError(
                f"{where} ({cid}): 'mode' must be auto, read or write; got {mode!r}"
            )
        sanity_as = spec.get("sanity_as", default_sanity)
        if sanity_as is not None and sanity_as not in identities:
            raise DefinitionError(
                f"{where} ({cid}): sanity_as {sanity_as!r} is not a declared identity"
            )
        for key in ("error_match", "error_not_match"):
            if spec.get(key) is not None:
                try:
                    re.compile(spec[key])
                except re.error as exc:
                    raise DefinitionError(
                        f"{where} ({cid}): {key} is not a valid regex -- {exc}"
                    ) from exc

        checks.append(
            Check(
                id=cid,
                identity=who,
                sql=spec["sql"],
                expect=expect,
                why=spec.get("why", ""),
                mode=mode,
                rows=spec.get("rows"),
                value=spec.get("value"),
                min_rows=spec.get("min_rows"),
                max_rows=spec.get("max_rows"),
                error_match=spec.get("error_match"),
                error_not_match=spec.get("error_not_match"),
                sanity_as=sanity_as,
                sanity_required=bool(spec.get("sanity_required", True)),
                table=spec.get("table"),
            )
        )

    # ---- views and functions the suite makes claims about ----------------
    audit_objects: List[AuditObject] = []
    raw_objects = data.get("audit_objects") or []
    if not isinstance(raw_objects, list):
        raise DefinitionError(f"{path}: 'audit_objects' must be a list")
    for idx, spec in enumerate(raw_objects):
        where = f"{path}: audit_objects[{idx}]"
        if not isinstance(spec, dict):
            raise DefinitionError(f"{where}: must be an object")
        unknown = set(spec) - {"kind", "name", "expect", "why"}
        if unknown:
            raise DefinitionError(
                f"{where}: unknown key(s): " + ", ".join(sorted(unknown))
            )
        kind = spec.get("kind")
        if kind not in ("view", "function"):
            raise DefinitionError(
                f"{where}: 'kind' must be 'view' or 'function', got {kind!r}"
            )
        name = spec.get("name")
        if not name or not isinstance(name, str):
            raise DefinitionError(f"{where}: needs a non-empty string 'name'")
        expect = spec.get("expect", "safe")
        if expect not in ("safe", "unsafe"):
            raise DefinitionError(
                f"{where}: 'expect' must be 'safe' or 'unsafe', got {expect!r}"
            )
        audit_objects.append(
            AuditObject(kind=kind, name=name, expect=expect, why=spec.get("why", ""))
        )

    expected = data.get("expected_outcome", "pass")
    if expected not in ("pass", "fail"):
        raise DefinitionError(
            f"{path}: expected_outcome must be 'pass' or 'fail', got {expected!r}"
        )

    return SuiteDefinition(
        path=os.path.abspath(path),
        suite=suite,
        title=data.get("title", ""),
        description=data.get("description", ""),
        identities=identities,
        checks=checks,
        fixtures=fixtures,
        params=params,
        setup=list(data.get("setup") or []),
        setup_reset=list(data.get("setup_reset") or []),
        admin_identity=admin_identity,
        admin_identity_inferred=admin_inferred,
        default_sanity_identity=default_sanity,
        strict_audit=bool(data.get("strict_audit", False)),
        expected_outcome=expected,
        tags=list(data.get("tags") or []),
        audit_objects=audit_objects,
    )


def discover_definitions(paths: List[str]) -> List[str]:
    """Expand the CLI's file/directory arguments into a sorted list of files."""
    found: List[str] = []
    for p in paths:
        if os.path.isdir(p):
            for name in sorted(os.listdir(p)):
                if name.endswith((".json", ".yaml", ".yml")) and not name.startswith("_"):
                    found.append(os.path.join(p, name))
        elif os.path.exists(p):
            found.append(p)
        else:
            raise DefinitionError(f"no such definition file or directory: {p}")
    if not found:
        raise DefinitionError(
            "no definition files found in: " + ", ".join(paths)
        )
    return found
