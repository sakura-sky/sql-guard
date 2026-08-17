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

import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final, Literal, Protocol, runtime_checkable

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


PiiMode = Literal["reference", "project"]
"""How strictly the PII denylist is applied.

``"reference"`` (default)
    Deny *any* reference to a denylisted column, anywhere in the statement —
    projections, ``WHERE``, ``GROUP BY``, ``HAVING``, ``ORDER BY``, ``JOIN``
    conditions. Denylisted values cannot be probed even indirectly.

``"project"``
    Deny only projections of denylisted columns (checked in every query
    scope). Predicates may reference them.

``"project"`` is the looser setting. It permits a caller to binary-search a
denied value without ever projecting it — ``WHERE email = 'a@b.com'`` returns
zero or non-zero rows, and repeated queries reconstruct the value. Choose it
only when predicate access to PII is a deliberate, accepted trade-off.
"""

_PII_MODES: Final[frozenset[str]] = frozenset({"reference", "project"})


@dataclass(frozen=True)
class SqlGuardConfig:
    """Configuration for :class:`SqlGuard`.

    Attributes:
        pii_denylist:
            Column names the guard refuses to project.
        pii_mode:
            How strictly the denylist applies — see :data:`PiiMode`. Defaults
            to ``"reference"``, which denies any reference to a denylisted
            column. Set to ``"project"`` to allow denylisted columns in
            predicates and only block projections.
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
    pii_mode: PiiMode = "reference"
    cost_model: CostModel = field(default_factory=BigQueryOnDemandCost)
    max_cost_usd_auto: float = 0.10
    max_cost_usd_hard: float = 20.00
    max_bytes_billed: int = 10 * 1024**3  # 10 GiB
    enforce_allowed_tables: bool = True

    def __post_init__(self) -> None:
        # Fail loudly on a typo. Silently falling back to a default would pick
        # a policy the operator did not ask for — the one thing a guard must
        # never do.
        if self.pii_mode not in _PII_MODES:
            raise ValueError(
                f"pii_mode must be one of {sorted(_PII_MODES)}; got {self.pii_mode!r}.",
            )

    @classmethod
    def from_settings(
        cls,
        pii_denylist: PiiDenylist,
        allowed_tables: Iterable[str],
        *,
        dialect: str = "bigquery",
        pii_mode: PiiMode = "reference",
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
            pii_mode=pii_mode,
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
class NoSelectStarRule:
    """Reject ``SELECT *`` in *any* query scope.

    Covers bare ``*``, ``* EXCEPT(...)``, ``* REPLACE(...)`` and qualified
    ``t.*``, in the outer select list and inside CTE bodies, derived tables
    and subqueries alike.

    The guard cannot prove that EXCEPT enumerates every PII column, and new
    PII columns added later would silently start leaking. Callers must list
    columns explicitly.

    The all-scope reach is what makes :class:`PiiProjectionRule` sound. A star
    anywhere makes that scope's projection list unresolvable without a schema,
    so a denied column could flow out through it —
    ``WITH c AS (SELECT * FROM t) SELECT city FROM c`` never names
    ``BillingCity``, yet returns it. Same rationale as the docstring above:
    the guard cannot prove what ``*`` contains.
    """

    def evaluate(self, ctx: RuleContext) -> GuardDecision | None:
        if has_select_star(ctx.statement):
            return _deny(
                "`SELECT *` is not allowed in any query scope — including "
                "`* EXCEPT(...)`, `* REPLACE(...)`, qualified `t.*`, and stars "
                "inside CTEs or subqueries. List columns explicitly so the PII "
                "denylist can be enforced.",
                referenced_tables=tuple(sorted(ctx.referenced_tables)),
            )
        return None


# Back-compat alias: the rule outgrew its "top-level" name when it was extended
# to every scope. Consumers importing the old name keep working.
NoTopLevelStarRule = NoSelectStarRule


@dataclass(frozen=True)
class NoUnresolvableColumnsRule:
    """Reject constructs whose column set the guard cannot enumerate.

    Sibling of :class:`NoSelectStarRule`, same argument: if the guard cannot
    name the columns a construct touches, it cannot prove they are denylist-
    free. Two such constructs exist beyond ``SELECT *``:

    **Whole-row references.** A bare table alias in a value position expands to
    every column in the row — a ``STRUCT`` in BigQuery, a composite in Postgres,
    a struct in DuckDB::

        SELECT c FROM `p.d.customers` AS c          -- every column, incl. PII
        SELECT TO_JSON_STRING(c) FROM `p.d.t` AS c  -- same, as JSON text

    This parses as an ordinary ``exp.Column`` named ``c``, so a denylist check
    sees one unremarkable non-PII name. It is strictly more powerful than
    ``SELECT *``, which the guard already rejects.

    **``NATURAL JOIN``.** Joins on whatever columns the two tables happen to
    share. Which columns those are is a schema fact the guard does not have, so
    it cannot rule out a denied column among them. ``JOIN ... USING (col)`` is
    fine by contrast — the columns are named, and
    :func:`all_referenced_column_names` reads them.
    """

    def evaluate(self, ctx: RuleContext) -> GuardDecision | None:
        for join in ctx.statement.find_all(exp.Join):
            method = join.args.get("method")
            if isinstance(method, str) and method.upper() == "NATURAL":
                return _deny(
                    "`NATURAL JOIN` is not allowed — it joins on whichever "
                    "columns the tables share, which the guard cannot "
                    "enumerate without a schema, so it cannot rule out a PII "
                    "column among them. Use an explicit `JOIN ... ON` or "
                    "`USING (...)` naming the join columns.",
                    referenced_tables=tuple(sorted(ctx.referenced_tables)),
                )

        offenders = sorted(set(whole_row_references(ctx.statement)))
        if offenders:
            return _deny(
                f"Query references whole rows by table alias "
                f"({', '.join(offenders)}). A bare table alias expands to every "
                "column in the row, so the guard cannot prove the result is "
                "free of PII — the same reason `SELECT *` is rejected. "
                "Reference the columns you need explicitly (`alias.column`).",
                referenced_tables=tuple(sorted(ctx.referenced_tables)),
            )
        return None


@dataclass(frozen=True)
class PiiProjectionRule:
    """Reject queries that touch PII-denylisted columns.

    Two modes, selected by :attr:`SqlGuardConfig.pii_mode`:

    ``"reference"`` (default)
        Deny any reference to a denied column anywhere in the statement.
        Projection-only checking leaves the value probeable:
        ``WHERE BillingCity = 'Columbus'`` never projects the column, but the
        row count answers a yes/no question about its value, and enough such
        questions reconstruct it.

    ``"project"``
        Deny only projections, checked in *every* scope.

    Both modes match on the underlying column names within each scope, so an
    alias cannot launder a denied column:
    ``WITH c AS (SELECT BillingCity AS city FROM t) SELECT city FROM c`` is
    caught in the CTE scope, where ``BillingCity`` is still named. Checking
    only the outermost select list would see ``city`` and pass it.
    """

    def evaluate(self, ctx: RuleContext) -> GuardDecision | None:
        if ctx.config.pii_mode == "project":
            names = all_projection_names(ctx.statement)
            hits = ctx.config.pii_denylist.matching(names)
            if hits:
                unique = tuple(sorted(set(hits)))
                return _deny(
                    f"Query projects PII columns ({', '.join(unique)}). "
                    "Aggregate-only or non-PII columns are allowed.",
                    pii_columns=unique,
                )
            return None

        names = all_referenced_column_names(ctx.statement)
        hits = ctx.config.pii_denylist.matching(names)
        if hits:
            unique = tuple(sorted(set(hits)))
            return _deny(
                f"Query references PII columns ({', '.join(unique)}). "
                "Denylisted columns cannot be projected, filtered, grouped, or "
                "sorted on — not even via an alias, CTE or subquery. Use "
                'non-PII columns, or run the guard with pii_mode="project" if '
                "predicate access to PII is an accepted trade-off.",
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
        offenders = sorted(t for t in ctx.referenced_tables if t.lower() not in cfg.allowed_tables)
        if offenders:
            return _deny(
                f"Query references tables outside the allowlist: {', '.join(offenders)}.",
                referenced_tables=tuple(sorted(ctx.referenced_tables)),
            )
        return None


def default_rules(_config: SqlGuardConfig) -> list[Rule]:
    """Return the built-in rules in their canonical order.

    Order matters: :class:`NoSelectStarRule` runs before
    :class:`PiiProjectionRule` so a ``SELECT * EXCEPT(email)`` gets the
    "list columns" message rather than a confusing PII-message about names
    that happen to appear in EXCEPT.

    That ordering also keeps the star rule's guarantee ahead of the PII check
    in every scope, not just the outermost one: a star inside a CTE is
    rejected before :class:`PiiProjectionRule` tries to resolve a projection
    list it cannot see.

    :class:`NoUnresolvableColumnsRule` sits in the same slot and for the same
    reason — whole-row aliases and ``NATURAL JOIN`` hide their column sets from
    the denylist, so they are rejected before the PII check runs and reports a
    misleading "no PII found".
    """
    return [
        SelectOnlyRule(),
        NoEmbeddedDmlRule(),
        NoSelectStarRule(),
        NoUnresolvableColumnsRule(),
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
        self._rules: tuple[Rule, ...] = tuple(rules if rules is not None else default_rules(config))

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
                f"Estimated cost {format_cost(cost_usd)} exceeds the hard cap of "
                f"{format_cost(self._config.max_cost_usd_hard)}.",
                cost_usd=cost_usd,
                bytes_processed=bytes_processed,
                referenced_tables=referenced_tables,
            )

        # NOTE: `<=` means a query costing *exactly* the threshold is auto-run.
        # Setting `max_cost_usd_auto=0.00` will still auto-allow any query
        # whose dry-run returns literal 0 bytes (cached / metadata-only).
        # To force confirm-on-every-query for demos, set a negative threshold
        # (e.g. -0.01) so no non-negative cost can ever satisfy `<=`.
        if cost_usd <= self._config.max_cost_usd_auto:
            return GuardDecision(
                outcome=GuardOutcome.ALLOW,
                reason=f"Estimated cost {format_cost(cost_usd)} is within the auto-run threshold.",
                cost_usd=cost_usd,
                bytes_processed=bytes_processed,
                referenced_tables=referenced_tables,
            )

        return GuardDecision(
            outcome=GuardOutcome.CONFIRM,
            reason=(
                f"Estimated cost {format_cost(cost_usd)} requires user confirmation "
                f"(auto threshold {format_cost(self._config.max_cost_usd_auto)})."
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
        return [s for arm in (statement.left, statement.right) for s in outer_selects(arm)]
    return []


def outermost_projection_names(statement: exp.Expression) -> list[str]:
    """Every name the PII check should consider for the outer projection.

    Walks both arms of UNION/UNION ALL/EXCEPT/INTERSECT. For each projection,
    contributes the alias (if any) plus every internal ``exp.Column`` ref.
    Projections wrapped in PII-neutralizing functions return no names.

    .. warning::
       Outermost scope only. A denied column projected inside a CTE or derived
       table and re-exposed under an alias is invisible here. Rules enforcing a
       denylist want :func:`all_projection_names`; this helper is retained for
       callers that specifically need the outer select list.
    """
    out: list[str] = []
    for select in outer_selects(statement):
        for projection in select.expressions:
            out.extend(_projection_names(projection))
    return out


def all_selects(statement: exp.Expression) -> list[exp.Select]:
    """Every ``Select`` scope in *statement*, outermost included.

    Covers CTE bodies, derived tables, scalar and ``IN`` subqueries, and every
    arm of a set operation — anywhere a projection list can hide.
    """
    return list(statement.find_all(exp.Select))


def all_projection_names(statement: exp.Expression) -> list[str]:
    """Projection names from *every* scope, not just the outermost.

    Each scope contributes its own projections' aliases plus the underlying
    ``exp.Column`` refs, so a denied column is caught in the scope that names
    it even if later scopes only ever see the alias.
    """
    out: list[str] = []
    for select in all_selects(statement):
        for projection in select.expressions:
            out.extend(_projection_names(projection))
    return out


def all_referenced_column_names(statement: exp.Expression) -> list[str]:
    """Every column name referenced anywhere in *statement*, in any clause.

    Includes projections, ``WHERE``, ``GROUP BY``, ``HAVING``, ``ORDER BY``,
    ``QUALIFY`` and ``JOIN`` conditions, at every nesting depth. This is the
    name set behind ``pii_mode="reference"``: a denied column used purely as a
    filter still leaks its values one predicate at a time.

    Projection aliases are folded in as well, so ``SELECT other AS email``
    is caught by an ``email`` denylist entry. Star refs (``t.*``) contribute
    no name — :class:`NoSelectStarRule` rejects those outright.

    Column names do not all arrive as ``exp.Column``. sqlglot parses several
    positions as bare ``exp.Identifier``, and each is a way to name a denied
    column without producing a single ``exp.Column`` node, so each is harvested
    explicitly:

    * ``JOIN ... USING (email)`` — ``Join.args["using"]``.
    * ``... AS g(email)`` column aliases — ``TableAlias.args["columns"]``.
    * ``STRUCT('a@b.com' AS email)`` field names — ``exp.PropertyEQ``.

    ``NATURAL JOIN`` names no columns at all and is rejected outright by
    :class:`NoUnresolvableColumnsRule`.
    """
    names: list[str] = list(all_projection_names(statement))
    for column in statement.find_all(exp.Column):
        if isinstance(column.this, exp.Star):
            continue
        if column.name:
            names.append(column.name)

    for join in statement.find_all(exp.Join):
        for identifier in join.args.get("using") or ():
            if isinstance(identifier, exp.Identifier) and identifier.name:
                names.append(identifier.name)

    for table_alias in statement.find_all(exp.TableAlias):
        for identifier in table_alias.args.get("columns") or ():
            if isinstance(identifier, exp.Identifier) and identifier.name:
                names.append(identifier.name)

    for prop in statement.find_all(exp.PropertyEQ):
        field = prop.this
        if isinstance(field, exp.Identifier) and field.name:
            names.append(field.name)

    return names


def whole_row_references(statement: exp.Expression) -> list[str]:
    """Unqualified column refs that actually name a row source, not a column.

    ``SELECT c FROM tbl AS c`` parses identically to a column named ``c``, but
    the engine returns the whole row. Any unqualified ``exp.Column`` whose name
    matches a *range variable* — a table alias, bare table name, CTE alias, or
    derived-table / ``VALUES`` / ``PIVOT`` alias — is a candidate.

    Two refinements keep the false-positive rate survivable, because a rule
    that denies ordinary analytics gets switched off and protects nothing:

    * **A table contributes only the name it is actually addressable by.** For
      ``FROM \\`p.d.status\\` AS s`` that is ``s``, not ``status``, so
      ``SELECT order_id, status FROM orders o JOIN \\`p.d.status\\` s ...``
      keeps working — ``status`` there is a column, and no range variable of
      that name exists.
    * **Where the guard can see a scope's output columns, it uses them.** A CTE
      or derived table names its own projections, so if the reference matches
      one it is a column, not a row::

          WITH revenue AS (SELECT uid, SUM(x) AS revenue FROM t GROUP BY uid)
          SELECT uid, revenue FROM revenue        -- allowed: revenue is a column

      Naming a CTE after the metric it computes is a mainstream idiom; denying
      it would be untenable. For a physical table the guard has no schema, so
      the reference stays denied and must be qualified (``c.col``).

    Bare ``UNNEST`` aliases are deliberately *not* treated as range variables.
    ``SELECT s FROM t, UNNEST(t.tags) AS s`` is idiomatic for a scalar array,
    and when the array holds structs the exposure is identical to selecting the
    struct column directly (``SELECT t.tags FROM t``) — which no parse-level
    rule can catch either. That whole class is a denylist-configuration
    concern: denylist the containing column. See the README's coverage limits.
    """
    ranges = _range_variables(statement)
    if not ranges:
        return []

    out: list[str] = []
    for column in statement.find_all(exp.Column):
        if isinstance(column.this, exp.Star) or column.table or not column.name:
            continue
        key = column.name.lower()
        if key not in ranges:
            continue
        exposed = ranges[key]
        # A scope we can read that publishes a column of this name — the
        # reference resolves to that column, not to the row.
        if exposed is not None and key in exposed:
            continue
        out.append(column.name)
    return out


def _range_variables(statement: exp.Expression) -> dict[str, frozenset[str] | None]:
    """Map each addressable row-source name to the columns it exposes.

    The value is ``None`` when the guard cannot see the column list (a physical
    table, a ``PIVOT``), and a frozenset of output names when it can (a CTE
    body, a derived table, a ``VALUES`` column alias list). ``None`` is the
    conservative reading and always wins a collision.
    """
    out: dict[str, frozenset[str] | None] = {}

    def add(name: str | None, columns: frozenset[str] | None) -> None:
        if not name:
            return
        key = name.lower()
        if key in out and out[key] is not None and columns is None:
            out[key] = None
        elif key not in out:
            out[key] = columns
        elif columns is None:
            out[key] = None

    cte_aliases = {cte.alias.lower() for cte in statement.find_all(exp.CTE) if cte.alias}

    for table in statement.find_all(exp.Table):
        # `FROM my_cte` parses as an exp.Table. Recording it here would mask
        # the CTE's readable column list with an unknown one, and unknown wins
        # collisions — which is exactly how a CTE named after the metric it
        # computes ends up wrongly denied.
        if not table.catalog and not table.db and table.name.lower() in cte_aliases:
            continue
        # Only the name the table is actually addressable by: an aliased table
        # cannot be referenced by its bare name.
        add(table.alias or table.name, None)

    for cte in statement.find_all(exp.CTE):
        add(cte.alias, _scope_output_names(cte.this))

    for table_alias in statement.find_all(exp.TableAlias):
        parent = table_alias.parent
        if isinstance(parent, exp.Table | exp.CTE):
            continue  # already recorded above
        if isinstance(parent, exp.Unnest):
            continue  # see whole_row_references docstring
        exposed: frozenset[str] | None = None
        if isinstance(parent, exp.Subquery):
            exposed = _scope_output_names(parent.this)
        else:
            columns = [
                identifier.name
                for identifier in table_alias.args.get("columns") or ()
                if isinstance(identifier, exp.Identifier) and identifier.name
            ]
            if columns:
                exposed = frozenset(c.lower() for c in columns)
        add(table_alias.name, exposed)

    return out


def _scope_output_names(expr: exp.Expression | None) -> frozenset[str] | None:
    """Output column names of a CTE body or derived table, if readable."""
    if expr is None:
        return None
    selects = outer_selects(expr)
    if not selects:
        return None
    names: set[str] = set()
    for select in selects:
        for projection in select.expressions:
            if _is_star_projection(projection):
                # A star hides the real output names; NoSelectStarRule rejects
                # this query anyway, but don't claim knowledge we lack.
                return None
            name = projection.alias_or_name
            if name:
                names.add(name.lower())
    return frozenset(names)


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
    """True if any outermost ``Select`` projects ``*`` in any form.

    Outermost scope only — see :func:`has_select_star` for the all-scope check
    that :class:`NoSelectStarRule` actually enforces.
    """
    for select in outer_selects(statement):
        for projection in select.expressions:
            if _is_star_projection(projection):
                return True
    return False


def has_select_star(statement: exp.Expression) -> bool:
    """True if *any* scope projects ``*`` in any form.

    Includes CTE bodies, derived tables and subqueries. ``COUNT(*)`` is not a
    star projection — it is an aggregate that emits a scalar, and stays allowed.
    """
    for select in all_selects(statement):
        for projection in select.expressions:
            if _is_star_projection(projection):
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


def format_cost(cost_usd: float) -> str:
    """Human-readable USD cost for guard reason messages.

    Uses 2 decimals for costs >= 1 cent. For sub-cent costs, picks the number
    of decimals dynamically so at least two significant figures always show —
    a real BigQuery dry-run cost of $0.00000019 renders as ``$0.00000019``
    rather than the ``$0.00`` a flat ``%.2f`` would produce. Negative costs
    (used as a sentinel by operators who want the guard's confirm gate to
    trip on every query — see the ``CostCapRule`` note) render with the sign
    outside the dollar sign, e.g. ``-$0.01``.
    """
    sign = "-" if cost_usd < 0 else ""
    magnitude = abs(cost_usd)
    if magnitude == 0:
        return "$0.00"
    if magnitude >= 0.01:
        return f"{sign}${magnitude:.2f}"
    # Sub-cent: enough decimals for at least two significant figures.
    decimals = 1 - math.floor(math.log10(magnitude))
    return f"{sign}${magnitude:.{decimals}f}"


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


# Scalar functions that destroy PII content (return a number or fixed-width
# hash, not the original value). Names match sqlglot's lowercase ``.key``.
#
# NOTE: several entries here do not match any sqlglot key and therefore never
# fire — BigQuery's ``MD5`` parses as ``MD5Digest`` (key ``md5digest``),
# ``SHA256`` as ``SHA2`` (key ``sha2``), and ``FARM_FINGERPRINT`` as
# ``Anonymous``. The practical effect is that hashed PII is *denied*, which is
# the safe direction — a hashed email is still a stable pseudonymous
# identifier, and a short one is trivially reversible by dictionary attack —
# so the mismatch is left as-is rather than "fixed" into a loosening. Do not
# add the real keys without deciding that hashed PII is acceptable output.
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


# Aggregates that reduce their input to a derived statistic, so a denied column
# inside one cannot reach the caller. Deliberately excludes MIN / MAX /
# ANY_VALUE / ARRAY_AGG / STRING_AGG / LOGICAL_OR / percentile- and mode-style
# aggregates, all of which return an input value verbatim.
_VALUE_DESTROYING_AGG_KEYS: frozenset[str] = frozenset(
    {
        "count",
        "countif",
        "sum",
        "avg",
        "approxdistinct",
        "stddev",
        "stddevpop",
        "stddevsamp",
        "variance",
        "variancepop",
        "variancesamp",
    },
)

# Aggregates for which a ``*`` argument is a row *count*, not a row expansion.
_COUNTING_AGG_KEYS: frozenset[str] = frozenset({"count", "countif", "approxdistinct"})


def _is_star_projection(projection: exp.Expression) -> bool:
    """True if *projection* expands to an unknown set of columns.

    Checking the projection's root node is not enough. Every one of these is a
    whole-row expansion with the ``Star`` buried one or more levels down, and a
    root-node ``isinstance`` test lets all of them through::

        SELECT t.*                          -- Column(Star)      any dialect
        SELECT OBJECT_CONSTRUCT(*)          -- StarMap(Star)     snowflake
        SELECT COLUMNS(*)                   -- Columns(Star)     duckdb
        SELECT * APPLY(toString)            -- Apply(Star)       clickhouse
        SELECT ROW(c.*)                     -- Struct(Column())  trino

    So the check is a deep walk with one carve-out: a star consumed by a
    count-style aggregate is not an expansion, because the aggregate emits a
    scalar rather than the row. ``COUNT(*)`` and ``COUNT(DISTINCT *)`` stay
    allowed; nothing else that swallows a star does.

    ClickHouse's regex column selector ``COLUMNS('e.*')`` is also an expansion
    but parses with no ``Star`` node at all — a ``Columns`` node wrapping a
    string literal — so it is matched on node type.
    """
    if isinstance(projection, exp.Columns) or any(projection.find_all(exp.Columns)):
        return True
    for star in projection.find_all(exp.Star):
        if not _star_is_counted(star, projection):
            return True
    return False


def _star_is_counted(star: exp.Star, projection: exp.Expression) -> bool:
    """True if *star* is an argument to a count-style aggregate.

    Walks from *star* up to *projection*. ``exp.Distinct`` is a permitted
    intermediate so ``COUNT(DISTINCT *)`` resolves the same as ``COUNT(*)``.
    """
    node: exp.Expression | None = star.parent
    while node is not None:
        key = getattr(node, "key", "")
        if isinstance(node, exp.AggFunc) and isinstance(key, str):
            return key.lower() in _COUNTING_AGG_KEYS
        if not isinstance(node, exp.Distinct):
            return False
        if node is projection:
            return False
        node = node.parent
    return False


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
    # `.this` rather than `.unalias()`: identical result for an Alias (that is
    # all unalias does), but sqlglot leaves `unalias` untyped, which trips
    # mypy's strict `no-untyped-call`.
    target = projection.this if isinstance(projection, exp.Alias) else projection

    # Subquery projection → recurse into its SELECT list.
    if isinstance(target, exp.Subquery):
        inner = target.this
        if isinstance(inner, exp.Select):
            return [
                name for inner_proj in inner.expressions for name in _projection_names(inner_proj)
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
    """True if *expr* cannot carry a PII value out to the caller.

    Aggregation alone does not neutralise anything. ``MAX(email)`` returns a
    real address; ``ARRAY_AGG(email)`` returns all of them; ``STRING_AGG`` and
    ``ANY_VALUE`` likewise. Only aggregates that reduce their input to a
    derived statistic qualify, so the test is an explicit allowlist rather
    than ``isinstance(expr, exp.AggFunc)``.
    """
    key = getattr(expr, "key", "")
    if not isinstance(key, str):
        return False
    lowered = key.lower()
    if isinstance(expr, exp.AggFunc):
        return lowered in _VALUE_DESTROYING_AGG_KEYS
    return lowered in _PII_SAFE_FUNC_KEYS


def _table_fullname(table: exp.Table) -> str:
    parts = [p for p in (table.catalog, table.db, table.name) if p]
    return ".".join(parts)


# Keep the original USD-per-byte constant as a public name in case anyone
# imported it directly. New code should use the cost-model classes.
_USD_PER_BYTE: Final[float] = _BIGQUERY_USD_PER_BYTE
