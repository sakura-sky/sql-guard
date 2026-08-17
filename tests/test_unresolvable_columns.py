"""Regressions for the four bypasses found reviewing the 0.2.0 scope fix.

The first pass at 0.2.0 closed alias laundering and predicate probing, then an
adversarial review broke it again four more ways. Each SQL string below was
empirically confirmed to reach ``confirm``/``allow`` against that intermediate
build; all are denied now.

* **Whole-row alias** — ``SELECT c FROM t AS c`` returns every column in the
  row as a struct. Strictly worse than ``SELECT *``, and it parses as an
  ordinary column named ``c``, so the denylist saw nothing to object to.
* **Nested stars** — the star check only looked at the projection's root node,
  so any construct wrapping the star (``OBJECT_CONSTRUCT(*)``, ``COLUMNS(*)``,
  ``* APPLY(f)``) sailed through on non-BigQuery dialects.
* **Identifier-only column refs** — ``JOIN ... USING (email)`` and
  ``AS g(email)`` carry column names as ``exp.Identifier``, never
  ``exp.Column``, so reference mode's ``find_all(exp.Column)`` sweep missed
  them entirely. ``NATURAL JOIN`` names no columns at all.
* **Value-preserving aggregates** — every ``exp.AggFunc`` was treated as
  PII-neutralising, so ``MAX(email)`` and ``ARRAY_AGG(email)`` counted as
  "aggregate only" and passed ``pii_mode="project"``.
"""

from __future__ import annotations

import pytest

from sql_guard import GuardOutcome, PiiDenylist, SqlGuard, SqlGuardConfig

_CUSTOMERS = "`example-project.analytics.customers`"


def _guard(
    pii_denylist: PiiDenylist,
    mode: str = "reference",
    dialect: str = "bigquery",
    *,
    enforce_tables: bool = True,
) -> SqlGuard:
    return SqlGuard(
        SqlGuardConfig.from_settings(
            pii_denylist=pii_denylist,
            allowed_tables=["example-project.analytics.customers"] if enforce_tables else [],
            pii_mode=mode,  # type: ignore[arg-type]
            dialect=dialect,
            enforce_allowed_tables=enforce_tables,
        ),
    )


# ---------------------------------------------------------------------------
# Whole-row references via a table alias
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "sql"),
    [
        ("bare_alias", f"SELECT c FROM {_CUSTOMERS} AS c"),
        ("json_of_alias", f"SELECT TO_JSON_STRING(c) AS j FROM {_CUSTOMERS} AS c"),
        ("agg_of_alias", f"SELECT ARRAY_AGG(c) AS rows FROM {_CUSTOMERS} AS c"),
        ("struct_of_alias", f"SELECT STRUCT(c) AS s FROM {_CUSTOMERS} AS c"),
        ("table_name_no_alias", f"SELECT customers FROM {_CUSTOMERS}"),
        (
            "cte_name",
            f"WITH x AS (SELECT uid, email FROM {_CUSTOMERS}) SELECT x FROM x",
        ),
        ("alias_in_where", f"SELECT uid FROM {_CUSTOMERS} AS c WHERE c IS NOT NULL"),
    ],
)
@pytest.mark.parametrize("mode", ["reference", "project"])
def test_whole_row_reference_is_denied(
    pii_denylist: PiiDenylist,
    name: str,
    sql: str,
    mode: str,
) -> None:
    """A bare table alias returns the entire row, PII included.

    This must be denied in both modes — it is an unresolvable projection, not
    a predicate question, so ``pii_mode`` has no bearing on it.
    """
    decision = _guard(pii_denylist, mode).evaluate_static(sql)
    assert decision.outcome is GuardOutcome.DENY, f"{name} passed the guard: {decision.reason}"


def test_whole_row_deny_message_names_the_alias_and_the_fix(pii_denylist: PiiDenylist) -> None:
    decision = _guard(pii_denylist).evaluate_static(f"SELECT c FROM {_CUSTOMERS} AS c")
    assert decision.outcome is GuardOutcome.DENY
    assert "c" in decision.reason
    assert "alias.column" in decision.reason


@pytest.mark.parametrize(
    ("name", "sql"),
    [
        (
            "derived_table_alias",
            f"SELECT d FROM (SELECT uid, tier FROM {_CUSTOMERS}) AS d",
        ),
        (
            "json_of_derived_alias",
            f"SELECT TO_JSON_STRING(d) AS j FROM (SELECT uid, tier FROM {_CUSTOMERS}) AS d",
        ),
        (
            "cte_row_via_json",
            f"WITH c AS (SELECT uid, email FROM {_CUSTOMERS}) SELECT TO_JSON_STRING(c) AS j FROM c",
        ),
        (
            "pivot_alias",
            f"SELECT pv FROM {_CUSTOMERS} PIVOT(SUM(lifetime_spend) FOR tier IN ('a', 'b')) AS pv",
        ),
    ],
)
def test_non_table_row_sources_are_also_whole_row_references(
    pii_denylist: PiiDenylist,
    name: str,
    sql: str,
) -> None:
    """Derived tables, CTEs and PIVOTs are row sources too, not just tables.

    An earlier cut of this rule built its name set from ``exp.Table`` and
    ``exp.CTE`` alone, so aliasing a subquery or a PIVOT re-opened the whole-row
    leak.
    """
    decision = _guard(pii_denylist).evaluate_static(sql)
    assert decision.outcome is GuardOutcome.DENY, f"{name} passed the guard: {decision.reason}"


def test_values_alias_whole_row_is_denied(pii_denylist: PiiDenylist) -> None:
    guard = _guard(pii_denylist, dialect="postgres", enforce_tables=False)
    decision = guard.evaluate_static("SELECT v FROM (VALUES ('a')) AS v(x)")
    assert decision.outcome is GuardOutcome.DENY


def test_clickhouse_regex_column_selector_is_denied(pii_denylist: PiiDenylist) -> None:
    """``COLUMNS('e.*')`` expands to many columns with no ``Star`` node at all.

    A star check that only looks for ``exp.Star`` misses it entirely.
    """
    guard = _guard(pii_denylist, dialect="clickhouse", enforce_tables=False)
    decision = guard.evaluate_static("SELECT COLUMNS('e.*') FROM customers")
    assert decision.outcome is GuardOutcome.DENY


# ---------------------------------------------------------------------------
# False-positive boundary — a rule that denies ordinary analytics gets disabled
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "sql"),
    [
        (
            "cte_named_after_its_metric",
            (
                "WITH revenue AS ("
                f"SELECT uid, SUM(lifetime_spend) AS revenue FROM {_CUSTOMERS} GROUP BY uid"
                ") SELECT uid, revenue FROM revenue ORDER BY revenue DESC"
            ),
        ),
        (
            "cte_named_month",
            (
                "WITH month AS ("
                f"SELECT DATE_TRUNC(signup_date, MONTH) AS month, lifetime_spend FROM {_CUSTOMERS}"
                ") SELECT month, SUM(lifetime_spend) AS s FROM month GROUP BY month"
            ),
        ),
        (
            "cte_passthrough_column",
            (
                f"WITH sessions AS (SELECT uid, sessions FROM {_CUSTOMERS}) "
                "SELECT uid, sessions FROM sessions"
            ),
        ),
        (
            # The table is addressable only as `c`, so a bare `customers` is a
            # column reference, not a row reference.
            "column_sharing_name_with_aliased_table",
            f"SELECT c.uid, customers FROM {_CUSTOMERS} AS c",
        ),
        (
            "scalar_unnest_alias",
            f"SELECT s FROM {_CUSTOMERS} AS t, UNNEST(t.tags) AS s",
        ),
    ],
)
def test_legitimate_names_colliding_with_row_sources_still_pass(
    pii_denylist: PiiDenylist,
    name: str,
    sql: str,
) -> None:
    """Naming a CTE after the metric it computes is mainstream, not an attack.

    The rule resolves the ambiguity from the AST: a CTE or derived table
    publishes its own output names, so a reference matching one is a column.
    An aliased table contributes only its alias, so a column sharing a name
    with some *other* table in the query is unaffected.
    """
    decision = _guard(pii_denylist).evaluate_static(sql)
    assert decision.outcome is not GuardOutcome.DENY, f"{name} wrongly denied: {decision.reason}"


@pytest.mark.parametrize(
    ("name", "sql"),
    [
        ("qualified_column", f"SELECT c.tier FROM {_CUSTOMERS} AS c"),
        ("qualified_in_agg", f"SELECT COUNT(c.uid) AS n FROM {_CUSTOMERS} AS c"),
        (
            "qualified_join",
            f"SELECT a.tier FROM {_CUSTOMERS} a JOIN {_CUSTOMERS} b ON a.uid = b.uid",
        ),
        ("unrelated_column", f"SELECT tier FROM {_CUSTOMERS} AS c"),
    ],
)
def test_qualified_references_still_pass(
    pii_denylist: PiiDenylist,
    name: str,
    sql: str,
) -> None:
    """Qualifying the reference resolves the ambiguity — these must not trip.

    This is the false-positive boundary of the whole-row rule: only an
    *unqualified* name matching a table or alias is treated as a whole row.
    """
    decision = _guard(pii_denylist).evaluate_static(sql)
    assert decision.outcome is not GuardOutcome.DENY, f"{name} wrongly denied: {decision.reason}"


# ---------------------------------------------------------------------------
# Stars nested inside a wrapping construct
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("dialect", "sql"),
    [
        ("snowflake", "SELECT OBJECT_CONSTRUCT(*) FROM customers"),
        ("snowflake", "SELECT OBJECT_CONSTRUCT_KEEP_NULL(*) FROM customers"),
        ("duckdb", "SELECT COLUMNS(*) FROM customers"),
        ("clickhouse", "SELECT * APPLY(toString) FROM customers"),
        ("trino", "SELECT ROW(c.*) FROM customers c"),
    ],
)
def test_nested_star_is_denied(pii_denylist: PiiDenylist, dialect: str, sql: str) -> None:
    """A star wrapped in a function still expands to the whole row.

    Checking only the projection's root node missed every one of these.
    """
    guard = _guard(pii_denylist, dialect=dialect, enforce_tables=False)
    decision = guard.evaluate_static(sql)
    assert decision.outcome is GuardOutcome.DENY, f"[{dialect}] {sql}: {decision.reason}"


@pytest.mark.parametrize(
    "sql",
    [
        f"SELECT COUNT(*) AS n FROM {_CUSTOMERS}",
        f"SELECT COUNT(DISTINCT tier) AS n FROM {_CUSTOMERS}",
        f"SELECT tier, COUNT(*) AS n FROM {_CUSTOMERS} GROUP BY tier",
    ],
)
def test_counting_stars_survive_the_deep_star_check(pii_denylist: PiiDenylist, sql: str) -> None:
    """``COUNT(*)`` counts rows; it does not expand them. Must stay allowed.

    Pins the one carve-out in the deep star walk, so a future tightening
    cannot quietly swallow the most common aggregate in the codebase.
    """
    decision = _guard(pii_denylist).evaluate_static(sql)
    assert decision.outcome is not GuardOutcome.DENY, decision.reason


# ---------------------------------------------------------------------------
# Column names that never become an exp.Column
# ---------------------------------------------------------------------------


def test_join_using_denied_column_is_denied(pii_denylist: PiiDenylist) -> None:
    """``USING (email)`` is a value oracle and produces no ``exp.Column``.

    The join returns rows only where the denied column matches, so the row
    count answers a question about its value.
    """
    sql = f"SELECT COUNT(*) AS n FROM {_CUSTOMERS} a JOIN {_CUSTOMERS} b USING (email)"
    decision = _guard(pii_denylist).evaluate_static(sql)
    assert decision.outcome is GuardOutcome.DENY
    assert any("email" in c.lower() for c in decision.pii_columns)


def test_join_using_allowed_column_still_passes(pii_denylist: PiiDenylist) -> None:
    """``USING`` on a non-PII column is ordinary SQL and must keep working."""
    sql = f"SELECT COUNT(*) AS n FROM {_CUSTOMERS} a JOIN {_CUSTOMERS} b USING (uid)"
    decision = _guard(pii_denylist).evaluate_static(sql)
    assert decision.outcome is not GuardOutcome.DENY, decision.reason


def test_natural_join_is_denied(pii_denylist: PiiDenylist) -> None:
    """``NATURAL JOIN`` joins on unknown shared columns — unprovable, so denied."""
    sql = f"SELECT COUNT(*) AS n FROM {_CUSTOMERS} NATURAL JOIN {_CUSTOMERS}"
    decision = _guard(pii_denylist).evaluate_static(sql)
    assert decision.outcome is GuardOutcome.DENY
    assert "NATURAL JOIN" in decision.reason


def test_values_column_alias_carrying_denied_name_is_denied(pii_denylist: PiiDenylist) -> None:
    """``AS g(email)`` names a denied column as a bare Identifier."""
    guard = _guard(pii_denylist, dialect="postgres", enforce_tables=False)
    sql = "SELECT COUNT(*) AS n FROM customers JOIN (VALUES ('a@b.com')) AS g(email) USING (email)"
    decision = guard.evaluate_static(sql)
    assert decision.outcome is GuardOutcome.DENY
    assert any("email" in c.lower() for c in decision.pii_columns)


def test_struct_field_named_after_denied_column_is_denied(pii_denylist: PiiDenylist) -> None:
    """``STRUCT('a@b.com' AS email)`` parses the field name as PropertyEQ."""
    sql = f"SELECT STRUCT('a@b.com' AS email) AS s, uid FROM {_CUSTOMERS}"
    decision = _guard(pii_denylist).evaluate_static(sql)
    assert decision.outcome is GuardOutcome.DENY
    assert any("email" in c.lower() for c in decision.pii_columns)


# ---------------------------------------------------------------------------
# Aggregates that return their input verbatim
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "sql"),
    [
        ("max", f"SELECT MAX(email) AS x FROM {_CUSTOMERS}"),
        ("min", f"SELECT MIN(email) AS x FROM {_CUSTOMERS}"),
        ("array_agg", f"SELECT ARRAY_AGG(email) AS x FROM {_CUSTOMERS}"),
        ("string_agg", f"SELECT STRING_AGG(email) AS x FROM {_CUSTOMERS}"),
        ("any_value", f"SELECT ANY_VALUE(email) AS x FROM {_CUSTOMERS}"),
        ("max_in_cte", f"WITH c AS (SELECT MAX(email) AS m FROM {_CUSTOMERS}) SELECT m FROM c"),
    ],
)
@pytest.mark.parametrize("mode", ["reference", "project"])
def test_value_preserving_aggregates_are_denied(
    pii_denylist: PiiDenylist,
    name: str,
    sql: str,
    mode: str,
) -> None:
    """These return real PII values, so "it's an aggregate" is no defence.

    ``project`` mode blocks projections of denied columns — and every one of
    these *is* a projection of the value, merely routed through an aggregate.
    """
    decision = _guard(pii_denylist, mode).evaluate_static(sql)
    assert decision.outcome is GuardOutcome.DENY, f"{name} passed in {mode}: {decision.reason}"
    assert any("email" in c.lower() for c in decision.pii_columns)


@pytest.mark.parametrize(
    ("name", "sql"),
    [
        ("count", f"SELECT COUNT(email) AS n FROM {_CUSTOMERS}"),
        ("countif", f"SELECT COUNTIF(email IS NOT NULL) AS n FROM {_CUSTOMERS}"),
    ],
)
def test_reducing_aggregates_over_pii_pass_only_in_project_mode(
    pii_denylist: PiiDenylist,
    name: str,
    sql: str,
) -> None:
    """Counts reduce to a statistic, so ``project`` mode permits them.

    ``reference`` mode still denies — a count is a probe. This pins the exact
    line between the two modes.
    """
    assert _guard(pii_denylist, "project").evaluate_static(sql).outcome is not GuardOutcome.DENY
    assert _guard(pii_denylist, "reference").evaluate_static(sql).outcome is GuardOutcome.DENY


@pytest.mark.parametrize(
    "sql",
    [
        f"SELECT MAX(lifetime_spend) AS m FROM {_CUSTOMERS}",
        f"SELECT ARRAY_AGG(tier) AS tiers FROM {_CUSTOMERS}",
        f"SELECT tier, MIN(lifetime_spend) AS lo FROM {_CUSTOMERS} GROUP BY tier",
    ],
)
def test_value_preserving_aggregates_over_allowed_columns_still_pass(
    pii_denylist: PiiDenylist,
    sql: str,
) -> None:
    """Narrowing the aggregate exemption must not break non-PII aggregation."""
    decision = _guard(pii_denylist).evaluate_static(sql)
    assert decision.outcome is not GuardOutcome.DENY, decision.reason
