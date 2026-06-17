"""Tests for the public extension points: custom rules, cost models, dialects."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from sql_guard import (
    BigQueryOnDemandCost,
    FlatRateCost,
    GuardDecision,
    GuardOutcome,
    PiiDenylist,
    Rule,
    RuleContext,
    SqlGuard,
    SqlGuardConfig,
    default_rules,
)

# ---------------------------------------------------------------------------
# Dialect support
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "dialect",
    ["bigquery", "snowflake", "postgres", "trino", "duckdb", "clickhouse", "mysql"],
)
def test_simple_select_parses_for_every_supported_dialect(dialect: str) -> None:
    """The same trivial SELECT should pass static checks under any dialect."""
    guard = SqlGuard(
        SqlGuardConfig.from_settings(
            pii_denylist=PiiDenylist.from_mapping({"columns": [], "substrings": []}),
            allowed_tables=["sales.public.orders"],
            dialect=dialect,
        ),
    )
    decision = guard.evaluate_static(
        "SELECT order_id, total FROM sales.public.orders WHERE total > 100",
    )
    assert decision.outcome is not GuardOutcome.DENY, decision.reason


def test_postgres_dialect_accepts_double_colon_cast() -> None:
    """Postgres-specific syntax that BigQuery doesn't support."""
    guard = SqlGuard(
        SqlGuardConfig.from_settings(
            pii_denylist=PiiDenylist.from_mapping({"columns": [], "substrings": []}),
            allowed_tables=["public.users"],
            dialect="postgres",
        ),
    )
    decision = guard.evaluate_static(
        "SELECT user_id::TEXT AS uid FROM public.users",
    )
    assert decision.outcome is not GuardOutcome.DENY


# ---------------------------------------------------------------------------
# Cost models
# ---------------------------------------------------------------------------


def test_bigquery_on_demand_cost_default() -> None:
    cost = BigQueryOnDemandCost()
    # 1 TiB == $5
    assert cost.bytes_to_usd(1024**4) == pytest.approx(5.0)


def test_bigquery_on_demand_cost_custom_rate() -> None:
    # Some Anthos / enterprise SKUs negotiate different per-TiB rates.
    cost = BigQueryOnDemandCost(usd_per_tib=3.0)
    assert cost.bytes_to_usd(1024**4) == pytest.approx(3.0)


def test_flat_rate_cost() -> None:
    cost = FlatRateCost(usd_per_byte=0.001)
    assert cost.bytes_to_usd(1000) == pytest.approx(1.0)


def test_custom_cost_model_swappable() -> None:
    """A user-defined model integrates without subclassing anything."""

    @dataclass(frozen=True)
    class ZeroCost:
        def bytes_to_usd(self, _bytes: int) -> float:
            return 0.0

    guard = SqlGuard(
        SqlGuardConfig.from_settings(
            pii_denylist=PiiDenylist.from_mapping({"columns": [], "substrings": []}),
            allowed_tables=[],
            cost_model=ZeroCost(),
            enforce_allowed_tables=False,
        ),
    )
    # A 10 TiB scan reports $0 — the custom model is being used.
    decision = guard.evaluate_cost(bytes_processed=10 * 1024**4)
    # The bytes-billed cap will still deny because 10 TiB > the default ceiling,
    # but the reported cost_usd should be 0 not $50.
    assert decision.cost_usd == 0.0


# ---------------------------------------------------------------------------
# Pluggable rules
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _ForbidDistinctRule:
    """A trivial custom rule that rejects SELECT DISTINCT."""

    def evaluate(self, ctx: RuleContext) -> GuardDecision | None:
        if "distinct" in ctx.sql.lower():
            return GuardDecision(
                outcome=GuardOutcome.DENY,
                reason="DISTINCT is forbidden by company policy.",
            )
        return None


def test_custom_rule_runs_alongside_defaults() -> None:
    config = SqlGuardConfig.from_settings(
        pii_denylist=PiiDenylist.from_mapping({"columns": [], "substrings": []}),
        allowed_tables=[],
        enforce_allowed_tables=False,
    )
    guard = SqlGuard(config, rules=[_ForbidDistinctRule(), *default_rules(config)])

    # Allowed query passes.
    assert guard.evaluate_static("SELECT col FROM `p.d.t`").outcome is not GuardOutcome.DENY

    # Custom rule fires for DISTINCT.
    decision = guard.evaluate_static("SELECT DISTINCT col FROM `p.d.t`")
    assert decision.outcome is GuardOutcome.DENY
    assert "DISTINCT" in decision.reason


def test_custom_rule_can_replace_defaults_entirely() -> None:
    """Passing rules=[...] alone replaces defaults — useful for pure custom flows."""
    config = SqlGuardConfig.from_settings(
        pii_denylist=PiiDenylist.from_mapping({"columns": [], "substrings": []}),
        allowed_tables=[],
        enforce_allowed_tables=False,
    )
    guard = SqlGuard(config, rules=[])  # no rules at all

    # Without default rules, SELECT * is now allowed (only the orchestrator's
    # parse-success check remains).
    decision = guard.evaluate_static("SELECT * FROM `p.d.t`")
    assert decision.outcome is not GuardOutcome.DENY


def test_rule_protocol_satisfied_by_function_like_object() -> None:
    """A user can write a Rule as any object with an .evaluate method."""

    class _AsClass:
        def evaluate(self, ctx: RuleContext) -> GuardDecision | None:
            return None

    rule: Rule = _AsClass()
    config = SqlGuardConfig.from_settings(
        pii_denylist=PiiDenylist.from_mapping({"columns": [], "substrings": []}),
        allowed_tables=[],
        enforce_allowed_tables=False,
    )
    SqlGuard(config, rules=[rule]).evaluate_static("SELECT 1 AS x")  # smoke
