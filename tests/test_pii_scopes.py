"""Regressions for the 0.2.0 PII scope fixes.

Two classes of bypass, both found by adversarial review of a deployed agent
and both confirmed against 0.1.1 before the fix:

**Scope aliasing.** ``PiiProjectionRule`` only inspected the outermost select
list, so any construct that renames a denied column in an inner scope laundered
it — CTEs, derived tables, UNION arms, and chains of the above. The star rule
had the same outermost-only blind spot, which matters once PII checking is
all-scope: a ``SELECT *`` inside a CTE makes that scope's projection list
unresolvable, so the guard cannot prove a denied column is absent.

**Value probing.** The denylist gated projection only, so ``WHERE``,
``GROUP BY``, ``HAVING`` and ``ORDER BY`` references passed. None of those
return the column, but each answers questions about its value, and enough
answers reconstruct it. ``pii_mode="reference"`` (the default) closes this;
``pii_mode="project"`` is the documented loosening path.

Every SQL string here is a *bypass* — each one returned CONFIRM on 0.1.1.
"""

from __future__ import annotations

import pytest

from sql_guard import GuardOutcome, PiiDenylist, SqlGuard, SqlGuardConfig

_CUSTOMERS = "`example-project.analytics.customers`"
_IDENTITY = "`example-project.analytics.identity`"


# ---------------------------------------------------------------------------
# Issue 1 — alias laundering across query scopes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "sql"),
    [
        (
            "cte_alias",
            f"WITH c AS (SELECT email AS city FROM {_CUSTOMERS}) SELECT city FROM c",
        ),
        (
            "derived_table",
            f"SELECT x FROM (SELECT email AS x FROM {_CUSTOMERS})",
        ),
        (
            "union_arm_derived",
            (
                f"SELECT uid FROM {_CUSTOMERS} "
                f"UNION ALL "
                f"SELECT c FROM (SELECT email AS c FROM {_CUSTOMERS})"
            ),
        ),
        (
            "union_arm_cte",
            (
                f"WITH laundered AS (SELECT email AS e FROM {_CUSTOMERS}) "
                f"SELECT uid FROM {_CUSTOMERS} UNION ALL SELECT e FROM laundered"
            ),
        ),
        (
            "multi_hop_chain",
            (
                f"WITH a AS (SELECT email AS e1 FROM {_CUSTOMERS}), "
                f"b AS (SELECT e1 AS e2 FROM a), "
                f"c AS (SELECT e2 AS e3 FROM b) "
                f"SELECT e3 FROM c"
            ),
        ),
        (
            "nested_derived_chain",
            f"SELECT z FROM (SELECT y AS z FROM (SELECT email AS y FROM {_CUSTOMERS}))",
        ),
        (
            "cte_feeding_join",
            (
                f"WITH c AS (SELECT uid, email AS handle FROM {_CUSTOMERS}) "
                f"SELECT t.uid, c.handle FROM {_IDENTITY} t JOIN c ON t.uid = c.uid"
            ),
        ),
    ],
)
@pytest.mark.parametrize("mode", ["reference", "project"])
def test_alias_laundering_is_denied_in_every_mode(
    pii_denylist: PiiDenylist,
    name: str,
    sql: str,
    mode: str,
) -> None:
    """An alias in an inner scope must never launder a denied column.

    These are denied in *both* modes: the denied column is projected in the
    scope that names it, which is a projection regardless of policy.
    """
    guard = _guard(pii_denylist, mode)
    decision = guard.evaluate_static(sql)
    assert decision.outcome is GuardOutcome.DENY, f"{name} passed the guard: {decision.reason}"
    assert any("email" in c.lower() for c in decision.pii_columns), (
        f"{name} denied but did not name the offending column: {decision.pii_columns}"
    )


# ---------------------------------------------------------------------------
# Issue 1b — SELECT * hiding a scope's projection list
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "sql"),
    [
        ("star_in_cte", f"WITH c AS (SELECT * FROM {_CUSTOMERS}) SELECT city FROM c"),
        ("star_in_derived", f"SELECT city FROM (SELECT * FROM {_CUSTOMERS})"),
        (
            "star_except_in_cte",
            f"WITH c AS (SELECT * EXCEPT(email) FROM {_CUSTOMERS}) SELECT city FROM c",
        ),
        (
            "star_in_union_arm",
            f"SELECT uid FROM {_CUSTOMERS} UNION ALL SELECT * FROM {_IDENTITY}",
        ),
        ("qualified_star_top_level", f"SELECT t.* FROM {_CUSTOMERS} t"),
        (
            "qualified_star_in_cte",
            f"WITH c AS (SELECT t.* FROM {_CUSTOMERS} t) SELECT city FROM c",
        ),
        (
            "star_in_scalar_subquery",
            f"SELECT (SELECT * FROM {_IDENTITY} LIMIT 1) AS x",
        ),
    ],
)
@pytest.mark.parametrize("mode", ["reference", "project"])
def test_select_star_is_denied_in_every_scope(
    pii_denylist: PiiDenylist,
    name: str,
    sql: str,
    mode: str,
) -> None:
    """A star anywhere makes that scope's projection unprovable — reject it.

    The guard cannot enumerate what ``*`` expands to without a schema, so it
    cannot show the scope is free of denied columns.
    """
    guard = _guard(pii_denylist, mode)
    decision = guard.evaluate_static(sql)
    assert decision.outcome is GuardOutcome.DENY, f"{name} passed the guard: {decision.reason}"
    assert "*" in decision.reason


def test_count_star_survives_the_all_scope_star_rule(pii_denylist: PiiDenylist) -> None:
    """``COUNT(*)`` is an aggregate, not a star projection — still allowed.

    Guards against an over-broad star rule that walks for ``exp.Star`` nodes
    instead of inspecting select-list entries.
    """
    guard = _guard(pii_denylist, "reference")
    sql = (
        f"WITH c AS (SELECT tier FROM {_CUSTOMERS}) SELECT tier, COUNT(*) AS n FROM c GROUP BY tier"
    )
    decision = guard.evaluate_static(sql)
    assert decision.outcome is not GuardOutcome.DENY, decision.reason


# ---------------------------------------------------------------------------
# Issue 2 — value probing through predicates
# ---------------------------------------------------------------------------


_PROBES: list[tuple[str, str]] = [
    ("where_equality", f"SELECT COUNT(*) AS n FROM {_CUSTOMERS} WHERE email = 'a@b.com'"),
    ("where_like_prefix", f"SELECT COUNT(*) AS n FROM {_CUSTOMERS} WHERE email LIKE 'a%'"),
    ("where_inequality", f"SELECT COUNT(*) AS n FROM {_CUSTOMERS} WHERE email > 'm'"),
    ("group_by_only", f"SELECT COUNT(*) AS n FROM {_CUSTOMERS} GROUP BY email"),
    (
        "having",
        f"SELECT tier, COUNT(*) AS n FROM {_CUSTOMERS} GROUP BY tier HAVING MIN(email) > 'm'",
    ),
    ("order_by", f"SELECT tier FROM {_CUSTOMERS} ORDER BY email LIMIT 1"),
    (
        "join_on",
        f"SELECT a.tier FROM {_CUSTOMERS} a JOIN {_IDENTITY} b ON a.email = b.email",
    ),
    (
        "where_in_cte",
        f"WITH c AS (SELECT uid FROM {_CUSTOMERS} WHERE email = 'a@b.com') SELECT uid FROM c",
    ),
    (
        "case_expression",
        f"SELECT SUM(CASE WHEN email = 'a@b.com' THEN 1 ELSE 0 END) AS hit FROM {_CUSTOMERS}",
    ),
    (
        "aggregate_over_pii",
        f"SELECT COUNTIF(email = 'a@b.com') AS hit FROM {_CUSTOMERS}",
    ),
]


@pytest.mark.parametrize(("name", "sql"), _PROBES)
def test_value_probing_is_denied_in_reference_mode(
    pii_denylist: PiiDenylist,
    name: str,
    sql: str,
) -> None:
    """Every one of these extracts a denied value without projecting it.

    Each returns a count or an ordering that answers a yes/no question about
    the column, so a caller can binary-search the value across queries.
    """
    guard = _guard(pii_denylist, "reference")
    decision = guard.evaluate_static(sql)
    assert decision.outcome is GuardOutcome.DENY, f"{name} passed the guard: {decision.reason}"
    assert any("email" in c.lower() for c in decision.pii_columns)


@pytest.mark.parametrize(("name", "sql"), _PROBES)
def test_value_probing_is_permitted_in_project_mode(
    pii_denylist: PiiDenylist,
    name: str,
    sql: str,
) -> None:
    """The documented loosening path, pinned so it cannot drift silently.

    ``pii_mode="project"`` deliberately allows predicate access to denied
    columns. This test records that trade-off rather than endorsing it.
    """
    guard = _guard(pii_denylist, "project")
    decision = guard.evaluate_static(sql)
    assert decision.outcome is not GuardOutcome.DENY, f"{name}: {decision.reason}"


def test_reference_mode_deny_message_names_columns_and_the_alternative(
    pii_denylist: PiiDenylist,
) -> None:
    """Deny messages state the rule, name the columns, suggest the way out."""
    guard = _guard(pii_denylist, "reference")
    decision = guard.evaluate_static(f"SELECT COUNT(*) AS n FROM {_CUSTOMERS} WHERE email = 'x'")
    assert decision.outcome is GuardOutcome.DENY
    assert "PII" in decision.reason
    assert "email" in decision.reason
    assert "pii_mode" in decision.reason


# ---------------------------------------------------------------------------
# Legit queries that must keep working
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "sql"),
    [
        (
            "aggregate_over_allowed_columns",
            (
                f"SELECT tier, COUNT(*) AS n, AVG(lifetime_spend) AS avg_spend "
                f"FROM {_CUSTOMERS} GROUP BY tier"
            ),
        ),
        (
            "pii_free_cte",
            (
                f"WITH base AS (SELECT uid, tier, lifetime_spend FROM {_CUSTOMERS}) "
                f"SELECT tier, AVG(lifetime_spend) AS avg_spend FROM base GROUP BY tier"
            ),
        ),
        (
            "multi_hop_pii_free_chain",
            (
                f"WITH a AS (SELECT uid, tier FROM {_CUSTOMERS}), "
                f"b AS (SELECT uid, tier AS band FROM a) "
                f"SELECT band, COUNT(*) AS n FROM b GROUP BY band"
            ),
        ),
        (
            "pii_free_union",
            f"SELECT tier FROM {_CUSTOMERS} UNION ALL SELECT tier FROM {_IDENTITY}",
        ),
        (
            "pii_free_derived_table",
            f"SELECT band, COUNT(*) AS n FROM (SELECT tier AS band FROM {_CUSTOMERS}) GROUP BY band",
        ),
        (
            "where_on_allowed_column",
            (
                f"SELECT tier, COUNT(*) AS n FROM {_CUSTOMERS} "
                f"WHERE lifetime_spend > 5000 GROUP BY tier"
            ),
        ),
        (
            "order_by_allowed_column",
            f"SELECT tier, COUNT(*) AS n FROM {_CUSTOMERS} GROUP BY tier ORDER BY n DESC",
        ),
    ],
)
@pytest.mark.parametrize("mode", ["reference", "project"])
def test_legitimate_queries_still_pass(
    pii_denylist: PiiDenylist,
    name: str,
    sql: str,
    mode: str,
) -> None:
    """The fix must not cost us ordinary analytics.

    None of these name a denied column in any scope, so both modes allow them.
    """
    guard = _guard(pii_denylist, mode)
    decision = guard.evaluate_static(sql)
    assert decision.outcome is not GuardOutcome.DENY, f"{name} wrongly denied: {decision.reason}"


# ---------------------------------------------------------------------------
# Config surface
# ---------------------------------------------------------------------------


def test_reference_is_the_default_mode(pii_denylist: PiiDenylist) -> None:
    config = SqlGuardConfig.from_settings(pii_denylist=pii_denylist, allowed_tables=[])
    assert config.pii_mode == "reference"


def test_invalid_pii_mode_raises(pii_denylist: PiiDenylist) -> None:
    """A typo must fail loudly, not silently pick a policy nobody chose."""
    with pytest.raises(ValueError, match="pii_mode"):
        SqlGuardConfig.from_settings(
            pii_denylist=pii_denylist,
            allowed_tables=[],
            pii_mode="referece",  # type: ignore[arg-type]
        )


def test_no_top_level_star_rule_alias_still_importable() -> None:
    """Consumers pinning the old rule name keep working."""
    from sql_guard import NoSelectStarRule, NoTopLevelStarRule

    assert NoTopLevelStarRule is NoSelectStarRule


def _guard(pii_denylist: PiiDenylist, mode: str) -> SqlGuard:
    return SqlGuard(
        SqlGuardConfig.from_settings(
            pii_denylist=pii_denylist,
            allowed_tables=[],
            pii_mode=mode,  # type: ignore[arg-type]
            enforce_allowed_tables=False,
        ),
    )
