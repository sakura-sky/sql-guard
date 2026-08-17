"""sql-guard — deterministic policy engine for LLM-generated SQL.

Public API:

    from sql_guard import (
        SqlGuard, SqlGuardConfig, GuardDecision, GuardOutcome,
        PiiDenylist, PiiMode,
        Rule, RuleContext, default_rules,
        # built-in rules
        SelectOnlyRule, NoEmbeddedDmlRule, NoSelectStarRule,
        NoUnresolvableColumnsRule, PiiProjectionRule, AllowedTablesRule,
        SingleStatementRule,
        # cost models
        CostModel, BigQueryOnDemandCost, FlatRateCost,
        # AST helpers for custom rules
        all_selects, all_projection_names, all_referenced_column_names,
        has_select_star, whole_row_references, referenced_tables,
        outer_selects, outermost_projection_names,
        has_top_level_select_star, format_bytes, format_cost,
    )

``NoTopLevelStarRule`` remains importable as an alias of ``NoSelectStarRule``,
which now covers every query scope rather than only the outermost one.
"""

from __future__ import annotations

from .pii import PiiDenylist
from .sql_guard import (
    AllowedTablesRule,
    BigQueryOnDemandCost,
    CostModel,
    FlatRateCost,
    GuardDecision,
    GuardOutcome,
    NoEmbeddedDmlRule,
    NoSelectStarRule,
    NoTopLevelStarRule,
    NoUnresolvableColumnsRule,
    PiiMode,
    PiiProjectionRule,
    Rule,
    RuleContext,
    SelectOnlyRule,
    SingleStatementRule,
    SqlGuard,
    SqlGuardConfig,
    all_projection_names,
    all_referenced_column_names,
    all_selects,
    default_rules,
    format_bytes,
    format_cost,
    has_select_star,
    has_top_level_select_star,
    outer_selects,
    outermost_projection_names,
    referenced_tables,
    whole_row_references,
)

__version__ = "0.2.0"

__all__ = [
    "AllowedTablesRule",
    "BigQueryOnDemandCost",
    "CostModel",
    "FlatRateCost",
    "GuardDecision",
    "GuardOutcome",
    "NoEmbeddedDmlRule",
    "NoSelectStarRule",
    "NoTopLevelStarRule",
    "NoUnresolvableColumnsRule",
    "PiiDenylist",
    "PiiMode",
    "PiiProjectionRule",
    "Rule",
    "RuleContext",
    "SelectOnlyRule",
    "SingleStatementRule",
    "SqlGuard",
    "SqlGuardConfig",
    "__version__",
    "all_projection_names",
    "all_referenced_column_names",
    "all_selects",
    "default_rules",
    "format_bytes",
    "format_cost",
    "has_select_star",
    "has_top_level_select_star",
    "outer_selects",
    "outermost_projection_names",
    "referenced_tables",
    "whole_row_references",
]
