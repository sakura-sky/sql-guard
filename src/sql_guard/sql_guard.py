"""Deterministic SQL guard layer.

This module is the deterministic floor between an LLM agent and the data
warehouse. It is pure-Python — no GCP / Snowflake / Postgres dependencies —
so it can be unit-tested without credentials and reused across SQL backends.

Default decision flow (in :meth:`SqlGuard.evaluate`):

1. Parse the SQL with sqlglot in the configured dialect.
2. Run each :class:`Rule` against the parsed statement in order.
3. The first rule that returns a :class:`GuardDecision` short-circuits.
4. If no rule fires and a ``bytes_processed`` figure is available, run the
   cost check.

Users can replace or extend the rule list:

    >>> guard = SqlGuard(config, rules=[MyCustomRule(), *default_rules(config)])

Dialect is configurable — anything sqlglot supports works (BigQuery,
Snowflake, Postgres, Trino, DuckDB, ClickHouse, MySQL, Oracle, Databricks…).
Default is ``"bigquery"`` for back-compat with the original ``bq-sql-guard``.

Cost model is configurable too. ``BigQueryOnDemandCost`` is the default; other
warehouses can supply their own (Snowflake credits, Redshift node-hours, …).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final, Protocol, runtime_checkable

import sqlglot
from sqlglot import expressions as exp

from .pii import PiiDenylist

# ---------------------------------------------------------------------------
# Decision shape — what every rule returns
# ---------------------------------------------------------------------------


class GuardOutcome(StrEnum):
    ALLOW = "allow"
    CONFIRM = "confirm"
    DENY = "deny"


@dataclass(frozen=True)
class GuardDecision:
    """Outcome of a single :meth:`SqlGuard.evaluate` call."""

    outcome: GuardOutcome
    reason: str
    cost_usd: float | None = None
    bytes_processed: int | None = None
    referenced_tables: tuple[str, ...] = ()
    pii_columns: tuple[str, ...] = ()

    @property
    def auto_execute(self) -> bool:
        return self.outcome is GuardOutcome.ALLOW

    @property
    def denied(self) -> bool:
        return self.outcome is GuardOutcome.DENY

    def as_dict(self) -> dict[str, object]:
        """Shape used as a tool/JSON response."""
        return {
            "outcome": self.outcome.value,
            "reason": self.reason,
            "auto_execute": self.auto_execute,
            "cost_usd": self.cost_usd,
            "bytes_processed": self.bytes_processed,
            "referenced_tables": list(self.referenced_tables),
            "pii_columns": list(self.pii_columns),
        }


# ---------------------------------------------------------------------------
# Cost model — strategy that converts dry-run bytes to USD
# ---------------------------------------------------------------------------


@runtime_checkable
class CostModel(Protocol):
    """Convert a dry-run figure into a USD cost estimate.

    Warehouses bill differently:

      * BigQuery on-demand: $5 per TiB scanned.
      * Snowflake: credits-per-second × warehouse size — no dry-run.
      * Redshift: provisioned node-hours.

    Implementations should be pure functions of the input bytes; side-effects
    (Vertex pricing queries, etc.) are the caller's job.
    """

    def bytes_to_usd(self, bytes_processed: int) -> float: ...


# 1 TiB of bytes processed costs $5 USD in BigQuery on-demand pricing.
# Source: https://cloud.google.com/bigquery/pricing#analysis_pricing_models
_BIGQUERY_USD_PER_BYTE: Final[float] = 5.0 / (1024**4)


@dataclass(frozen=True)
class BigQueryOnDemandCost:
    """BigQuery on-demand pricing: $5 per TiB scanned (default)."""

    usd_per_tib: float = 5.0

    def bytes_to_usd(self, bytes_processed: int) -> float:
        return bytes_processed * self.usd_per_tib / (1024**4)


@dataclass(frozen=True)
class FlatRateCost:
    """A fixed price per byte. Useful for testing or contractual flat-rate."""

    usd_per_byte: float

    def bytes_to_usd(self, bytes_processed: int) -> float:
        return bytes_processed * self.usd_per_byte


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SqlGuardConfig:
    """Configuration for :class:`SqlGuard`.

    Attributes:
        pii_denylist:
            Column names the guard refuses to project.
        allowed_tables:
            Fully-qualified table names the guard permits. Empty/disabled set
            means "no allowlist enforcement" — every table passes.
        dialect:
            sqlglot dialect for parsing. Defaults to ``"bigquery"``. Any
            dialect sqlglot understands works (``"snowflake"``, ``"postgres"``,
            ``"trino"``, ``"duckdb"``, ``"clickhouse"``, ``"mysql"``,
            ``"oracle"``, ``"databricks"``, …).
        cost_model:
            Strategy to convert dry-run bytes to USD. Defaults to
            :class:`BigQueryOnDemandCost` — swap for Snowflake / Redshift /
            flat-rate models as needed.
        max_cost_usd_auto:
            Soft cap. Below this the guard auto-allows; above it asks for
            confirmation.
        max_cost_usd_hard:
            Hard cap. Above this the guard denies even with user confirmation.
        max_bytes_billed:
            Hard ceiling on dry-run bytes. Bypasses ``cost_model`` so that a
            pricing-model bug can't paper over an unbounded scan.
        enforce_allowed_tables:
            When False, the table allowlist is skipped. Useful for tests.
    """

    pii_denylist: PiiDenylist
    allowed_tables: frozenset[str]
    dialect: str = "bigquery"
    cost_model: CostModel = field(default_factory=BigQueryOnDemandCost)
    max_cost_usd_auto: float = 0.10
    max_cost_usd_hard: float = 20.00
    max_bytes_billed: int = 10 * 1024**3  # 10 GiB
    enforce_allowed_tables: bool = True

    @classmethod
    def from_settings(
        cls,
        pii_denylist: PiiDenylist,
        allowed_tables: Iterable[str],
        *,
        dialect: str = "bigquery",
        cost_model: CostModel | None = None,
        max_cost_usd_auto: float = 0.10,
        max_cost_usd_hard: float = 20.00,
        max_bytes_billed: int = 10 * 1024**3,
        enforce_allowed_tables: bool = True,
    ) -> SqlGuardConfig:
        return cls(
            pii_denylist=pii_denylist,
            allowed_tables=frozenset(t.lower() for t in allowed_tables),
            dialect=dialect,
            cost_model=cost_model or BigQueryOnDemandCost(),
            max_cost_usd_auto=max_cost_usd_auto,
            max_cost_usd_hard=max_cost_usd_hard,
            max_bytes_billed=max_bytes_billed,
            enforce_allowed_tables=enforce_allowed_tables,
        )


# ---------------------------------------------------------------------------
# Rule machinery — pluggable static checks
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RuleContext:
    """Everything a static rule needs to make its decision.

    Built once per :meth:`SqlGuard.evaluate_static` call so individual rules
    don't redo the parsing / table-extraction work.
    """

    sql: str
    statement: exp.Expression
    referenced_tables: frozenset[str]
    config: SqlGuardConfig


@runtime_checkable
class Rule(Protocol):
    """Static rule against a parsed SQL statement.

    Return ``None`` if the rule has nothing to say (let the next rule decide).
    Return a :class:`GuardDecision` to short-circuit with the given outcome
    — typically a DENY.
    """

    def evaluate(self, ctx: RuleContext) -> GuardDecision | None: ...


@dataclass(frozen=True)
class SingleStatementRule:
    """Reject anything that isn't exactly one SQL statement."""

    def evaluate(self, ctx: RuleContext) -> GuardDecision | None:
        # The orchestrator already enforces single-statement parsing; this
        # rule exists for completeness — users replacing the rule list keep
        # the protection.
        return None


@dataclass(frozen=True)
class SelectOnlyRule:
    """Reject anything other than a SELECT or set-operator at the top."""

    def evaluate(self, ctx: RuleContext) -> GuardDecision | None:
        statement = ctx.statement
        if not isinstance(statement, exp.Select | exp.Union):
            return _deny(
                f"Only SELECT statements are allowed; got {type(statement).__name__}.",
            )
        return None


@dataclass(frozen=True)
class NoEmbeddedDmlRule:
    """Reject DML / DDL hidden inside subqueries or CTEs."""

    def evaluate(self, ctx: RuleContext) -> GuardDecision | None:
        for node in ctx.statement.walk():
            if isinstance(
                node,
                exp.Insert
                | exp.Update
                | exp.Delete
                | exp.Merge
                | exp.Create
                | exp.Drop
                | exp.Alter
                | exp.Command,
            ):
                return _deny(
                    f"Disallowed statement type encountered: {type(node).__name__}.",
                )
        return None


@dataclass(frozen=True)
class NoTopLevelStarRule:
    """Reject ``SELECT *`` (and ``* EXCEPT(...)`` / ``* REPLACE(...)``).

    The guard cannot prove that EXCEPT enumerates every PII column, and new
    PII columns added later would silently start leaking. Callers must list
    columns explicitly.
    """

    def evaluate(self, ctx: RuleContext) -> GuardDecision | None:
        if has_top_level_select_star(ctx.statement):
            return _deny(
                "Top-level `SELECT *` is not allowed (including `* EXCEPT(...)` "
                "and `* REPLACE(...)`). List columns explicitly so the PII "
                "denylist can be enforced.",
                referenced_tables=tuple(sorted(ctx.referenced_tables)),
            )
        return None


@dataclass(frozen=True)
class PiiProjectionRule:
    """Reject queries that project PII-denylisted columns."""

    def evaluate(self, ctx: RuleContext) -> GuardDecision | None:
        projected = outermost_projection_names(ctx.statement)
        hits = ctx.config.pii_denylist.matching(projected)
        if hits:
            unique = tuple(sorted(set(hits)))
            return _deny(
                f"Query projects PII columns ({', '.join(unique)}). "
                "Aggregate-only or non-PII columns are allowed.",
                pii_columns=unique,
            )
        return None


@dataclass(frozen=True)
class AllowedTablesRule:
    """Reject table references outside the configured allowlist."""

    def evaluate(self, ctx: RuleContext) -> GuardDecision | None:
        cfg = ctx.config
        if not cfg.enforce_allowed_tables or not cfg.allowed_tables:
            return None
        offenders = sorted(
            t for t in ctx.referenced_tables if t.lower() not in cfg.allowed_tables
        )
        if offenders:
            return _deny(
                "Query references tables outside the allowlist: "
                f"{', '.join(offenders)}.",
                referenced_tables=tuple(sorted(ctx.referenced_tables)),
            )
        return None


def default_rules(_config: SqlGuardConfig) -> list[Rule]:
    """Return the built-in rules in their canonical order.

    Order matters: :class:`NoTopLevelStarRule` runs before
    :class:`PiiProjectionRule` so a ``SELECT * EXCEPT(email)`` gets the
    "list columns" message rather than a confusing PII-message about names
    that happen to appear in EXCEPT.
    """
    return [
        SelectOnlyRule(),
        NoEmbeddedDmlRule(),
        NoTopLevelStarRule(),
        PiiProjectionRule(),
        AllowedTablesRule(),
    ]


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class SqlGuard:
    """Stateless evaluator. Reuse the same instance across calls.

    Construction:

        guard = SqlGuard(config)                              # defaults
        guard = SqlGuard(config, rules=[CustomRule(), ...])   # custom rules

    Methods:

        guard.evaluate_static(sql)                # parse + run static rules
        guard.evaluate_cost(bytes_processed=…)    # cost / cap rules
        guard.evaluate(sql, bytes_processed=…)    # both
    """

    def __init__(
        self,
        config: SqlGuardConfig,
        *,
        rules: Sequence[Rule] | None = None,
    ) -> None:
        self._config = config
        self._rules: tuple[Rule, ...] = tuple(
            rules if rules is not None else default_rules(config)
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def evaluate(
        self,
        sql_query: str,
        *,
        bytes_processed: int | None = None,
    ) -> GuardDecision:
        """Run static rules; if they pass and ``bytes_processed`` is given, also cost."""
        static = self.evaluate_static(sql_query)
        if static.denied or bytes_processed is None:
            return static
        return self.evaluate_cost(
            bytes_processed=bytes_processed,
            referenced_tables=static.referenced_tables,
        )

    def evaluate_static(self, sql_query: str) -> GuardDecision:
        """Parse and apply every configured rule. First DENY wins."""
        if not sql_query or not sql_query.strip():
            return _deny("Empty SQL query.")

        try:
            parsed = sqlglot.parse(sql_query, dialect=self._config.dialect)
        except sqlglot.errors.ParseError as exc:
            return _deny(f"SQL failed to parse: {exc}")

        non_empty = [stmt for stmt in parsed if stmt is not None]
        if len(non_empty) != 1:
            return _deny(f"Exactly one statement is allowed; got {len(non_empty)}.")

        statement = non_empty[0]
        tables = frozenset(referenced_tables(statement))

        ctx = RuleContext(
            sql=sql_query,
            statement=statement,
            referenced_tables=tables,
            config=self._config,
        )

        for rule in self._rules:
            decision = rule.evaluate(ctx)
            if decision is not None:
                return decision

        return GuardDecision(
            outcome=GuardOutcome.CONFIRM,
            reason="Static checks passed; awaiting cost evaluation.",
            referenced_tables=tuple(sorted(tables)),
        )

    def evaluate_cost(
        self,
        *,
        bytes_processed: int,
        referenced_tables: tuple[str, ...] = (),
    ) -> GuardDecision:
        """Cost-cap + auto-execute recommendation.

        Cost-model errors are converted to a DENY rather than propagated —
        callers expect a :class:`GuardDecision`, not exceptions.
        """
        if bytes_processed < 0:
            return _deny("Warehouse returned a negative bytes_processed value.")

        cost_usd = self._config.cost_model.bytes_to_usd(bytes_processed)

        if bytes_processed > self._config.max_bytes_billed:
            return _deny(
                f"Query would scan {format_bytes(bytes_processed)} which "
                f"exceeds the bytes-billed cap of "
                f"{format_bytes(self._config.max_bytes_billed)}.",
                cost_usd=cost_usd,
                bytes_processed=bytes_processed,
                referenced_tables=referenced_tables,
            )

        if cost_usd > self._config.max_cost_usd_hard:
            return _deny(
                f"Estimated cost ${cost_usd:.2f} exceeds the hard cap of "
                f"${self._config.max_cost_usd_hard:.2f}.",
                cost_usd=cost_usd,
                bytes_processed=bytes_processed,
                referenced_tables=referenced_tables,
            )

        if cost_usd <= self._config.max_cost_usd_auto:
            return GuardDecision(
                outcome=GuardOutcome.ALLOW,
                reason=f"Estimated cost ${cost_usd:.4f} is within the auto-run threshold.",
                cost_usd=cost_usd,
                bytes_processed=bytes_processed,
                referenced_tables=referenced_tables,
            )

        return GuardDecision(
            outcome=GuardOutcome.CONFIRM,
            reason=(
                f"Estimated cost ${cost_usd:.2f} requires user confirmation "
                f"(auto threshold ${self._config.max_cost_usd_auto:.2f})."
            ),
            cost_usd=cost_usd,
            bytes_processed=bytes_processed,
            referenced_tables=referenced_tables,
        )


# ---------------------------------------------------------------------------
# Helpers (public — re-exported for users writing their own rules)
# ---------------------------------------------------------------------------


def _deny(
    reason: str,
    *,
    cost_usd: float | None = None,
    bytes_processed: int | None = None,
    referenced_tables: tuple[str, ...] = (),
    pii_columns: tuple[str, ...] = (),
) -> GuardDecision:
    return GuardDecision(
        outcome=GuardOutcome.DENY,
        reason=reason,
        cost_usd=cost_usd,
        bytes_processed=bytes_processed,
        referenced_tables=referenced_tables,
        pii_columns=pii_columns,
    )


def outer_selects(statement: exp.Expression) -> list[exp.Select]:
    """Outermost ``Select`` nodes the user will receive rows from.

    For ``Union`` / ``Except`` / ``Intersect`` descends into both arms so a
    nested set operator's right side can't smuggle PII past us.
    """
    if isinstance(statement, exp.Select):
        return [statement]
    if isinstance(statement, exp.Union | exp.Except | exp.Intersect):
        return [
            s
            for arm in (statement.left, statement.right)
            for s in outer_selects(arm)
        ]
    return []


def outermost_projection_names(statement: exp.Expression) -> list[str]:
    """Every name the PII check should consider for the outer projection.

    Walks both arms of UNION/UNION ALL/EXCEPT/INTERSECT. For each projection,
    contributes the alias (if any) plus every internal ``exp.Column`` ref.
    Projections wrapped in PII-neutralizing functions return no names.
    """
    out: list[str] = []
    for select in outer_selects(statement):
        for projection in select.expressions:
            out.extend(_projection_names(projection))
    return out


def referenced_tables(statement: exp.Expression) -> set[str]:
    """Fully-qualified physical tables referenced by *statement*.

    CTE alias names are excluded — a reference like ``FROM base`` where
    ``base`` is a CTE alias is not a physical table.
    """
    cte_aliases: set[str] = set()
    for cte in statement.find_all(exp.CTE):
        if cte.alias:
            cte_aliases.add(cte.alias.lower())

    out: set[str] = set()
    for table in statement.find_all(exp.Table):
        if not table.catalog and not table.db and table.name.lower() in cte_aliases:
            continue
        out.add(_table_fullname(table))
    return out


def has_top_level_select_star(statement: exp.Expression) -> bool:
    """True if any outermost ``Select`` projects ``*`` in any form."""
    for select in outer_selects(statement):
        for projection in select.expressions:
            if isinstance(projection, exp.Star):
                return True
    return False


def format_bytes(num_bytes: int) -> str:
    """Human-readable bytes for error messages."""
    if num_bytes < 1024**2:
        return f"{num_bytes / 1024:.2f} KiB"
    if num_bytes < 1024**3:
        return f"{num_bytes / 1024**2:.2f} MiB"
    if num_bytes < 1024**4:
        return f"{num_bytes / 1024**3:.2f} GiB"
    return f"{num_bytes / 1024**4:.2f} TiB"


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


# Scalar functions that destroy PII content (return a number or fixed-width
# hash, not the original value). Names match sqlglot's lowercase ``.key``.
_PII_SAFE_FUNC_KEYS: frozenset[str] = frozenset(
    {
        "length",
        "characterlength",
        "char_length",
        "byte_length",
        "bit_count",
        "array_length",
        "farm_fingerprint",
        "md5",
        "sha1",
        "sha256",
        "sha512",
    },
)


def _projection_names(projection: exp.Expression) -> list[str]:
    """Names from a single projection — every PII-relevant column ref.

    Walks the projection tree, but distinguishes between columns that
    *contribute to the returned value* (always flagged) and columns that
    are *consumed by a predicate* (never flagged — the predicate emits a
    scalar, not the column value).

    Specifically:

    * If the projection is wrapped in an aggregate or PII-neutralizing
      scalar function, return no names.
    * If the projection is a ``Subquery`` (``(SELECT ... FROM ...) AS x``),
      recurse into the subquery's outer projections — its WHERE / JOIN /
      HAVING clauses are predicates and do not leak PII.
    * Otherwise, walk the projection but skip columns reachable only via
      predicate clauses (WHERE / HAVING / QUALIFY / ON / ORDER BY / GROUP BY).
    """
    target = projection.unalias() if isinstance(projection, exp.Alias) else projection

    # Subquery projection → recurse into its SELECT list.
    if isinstance(target, exp.Subquery):
        inner = target.this
        if isinstance(inner, exp.Select):
            return [
                name
                for inner_proj in inner.expressions
                for name in _projection_names(inner_proj)
            ]
        # Non-SELECT inside a subquery — fall through to conservative walking.

    if _is_pii_neutralizing(target):
        return []

    names: list[str] = []
    alias = projection.alias_or_name
    if alias and alias != "*":
        names.append(alias)

    for col in _value_contributing_columns(target):
        if col.name:
            names.append(col.name)
    return names


# sqlglot node types whose contents are predicates, not projected values. A
# column reference reachable only through one of these is consumed by a
# filter; it doesn't leak into the result set.
_PREDICATE_BOUNDARY_TYPES: tuple[type, ...] = (
    exp.Where,
    exp.Having,
    exp.Qualify,
    exp.Join,
    exp.Group,
    exp.Order,
    exp.Subquery,  # nested subqueries handled by the Subquery branch above
)


def _value_contributing_columns(expr: exp.Expression) -> list[exp.Column]:
    """Yield every Column ref that contributes to *expr*'s output value.

    Excludes columns reachable only through predicate clauses (WHERE etc.)
    or via a nested ``Subquery``. A column in ``LOWER(email)`` contributes;
    a column in ``CASE WHEN email IS NULL THEN 'x' ELSE 'y' END`` contributes
    (the case condition selects which constant goes out, but doesn't leak
    the email itself — keep flagging it conservatively); a column in
    ``COUNT(* WHERE email IS NULL)`` does not contribute (handled by the
    AggFunc neutraliser above).
    """
    out: list[exp.Column] = []

    def walk(node: exp.Expression) -> None:
        for _child_key, child in _iter_args(node):
            # Skip whole subtrees that are predicate boundaries.
            if isinstance(child, _PREDICATE_BOUNDARY_TYPES):
                continue
            if isinstance(child, exp.Column):
                out.append(child)
                continue
            walk(child)

    if isinstance(expr, exp.Column):
        out.append(expr)
    else:
        walk(expr)
    return out


def _iter_args(node: exp.Expression):  # type: ignore[no-untyped-def]
    """Iterate over a node's children, flattening lists of expressions."""
    for key, value in node.args.items():
        if value is None:
            continue
        if isinstance(value, list):
            for item in value:
                if isinstance(item, exp.Expression):
                    yield key, item
        elif isinstance(value, exp.Expression):
            yield key, value


def _is_pii_neutralizing(expr: exp.Expression) -> bool:
    if isinstance(expr, exp.AggFunc):
        return True
    key = getattr(expr, "key", "")
    return isinstance(key, str) and key.lower() in _PII_SAFE_FUNC_KEYS


def _table_fullname(table: exp.Table) -> str:
    parts = [p for p in (table.catalog, table.db, table.name) if p]
    return ".".join(parts)


# Keep the original USD-per-byte constant as a public name in case anyone
# imported it directly. New code should use the cost-model classes.
_USD_PER_BYTE: Final[float] = _BIGQUERY_USD_PER_BYTE
