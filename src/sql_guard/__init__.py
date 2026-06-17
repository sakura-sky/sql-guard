"""sql-guard — deterministic policy engine for LLM-generated SQL.

Public API:

    from sql_guard import (
        SqlGuard, SqlGuardConfig, GuardDecision, GuardOutcome,
        PiiDenylist,
        Rule, RuleContext, default_rules,
        # built-in rules
        SelectOnlyRule, NoEmbeddedDmlRule, NoTopLevelStarRule,
        PiiProjectionRule, AllowedTablesRule,
        # cost models
        CostModel, BigQueryOnDemandCost, FlatRateCost,
        # AST helpers for custom rules
        outer_selects, outermost_projection_names, referenced_tables,
        has_top_level_select_star, format_bytes,
    )
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
    NoTopLevelStarRule,
    PiiProjectionRule,
    Rule,
    RuleContext,
    SelectOnlyRule,
    SingleStatementRule,
    SqlGuard,
    SqlGuardConfig,
    default_rules,
    format_bytes,
    has_top_level_select_star,
    outer_selects,
    outermost_projection_names,
    referenced_tables,
)

__version__ = "0.1.0"

__all__ = [
    "AllowedTablesRule",
    "BigQueryOnDemandCost",
    "CostModel",
    "FlatRateCost",
    "GuardDecision",
    "GuardOutcome",
    "NoEmbeddedDmlRule",
    "NoTopLevelStarRule",
    "PiiDenylist",
    "PiiProjectionRule",
    "Rule",
    "RuleContext",
    "SelectOnlyRule",
    "SingleStatementRule",
    "SqlGuard",
    "SqlGuardConfig",
    "__version__",
    "default_rules",
    "format_bytes",
    "has_top_level_select_star",
    "outer_selects",
    "outermost_projection_names",
    "referenced_tables",
]
