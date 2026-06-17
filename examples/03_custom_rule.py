"""Compose a custom rule alongside the defaults.

This example forbids queries that read more than three tables at once — a
proxy for "no complex joins on the LLM path; route those to a human."
"""

from __future__ import annotations

from dataclasses import dataclass

from sql_guard import (
    GuardDecision,
    GuardOutcome,
    PiiDenylist,
    RuleContext,
    SqlGuard,
    SqlGuardConfig,
    default_rules,
)


@dataclass(frozen=True)
class MaxTablesRule:
    """Reject queries that reference more than `limit` distinct tables."""

    limit: int = 3

    def evaluate(self, ctx: RuleContext) -> GuardDecision | None:
        if len(ctx.referenced_tables) > self.limit:
            return GuardDecision(
                outcome=GuardOutcome.DENY,
                reason=(
                    f"Query references {len(ctx.referenced_tables)} tables "
                    f"(limit: {self.limit}). Route complex joins to a human."
                ),
                referenced_tables=tuple(sorted(ctx.referenced_tables)),
            )
        return None


def main() -> None:
    config = SqlGuardConfig.from_settings(
        pii_denylist=PiiDenylist.from_mapping({"columns": [], "substrings": []}),
        allowed_tables=[f"db.public.t{i}" for i in range(10)],
    )
    guard = SqlGuard(config, rules=[MaxTablesRule(limit=2), *default_rules(config)])

    # 2 tables — passes.
    d = guard.evaluate_static(
        "SELECT a.id FROM db.public.t1 a JOIN db.public.t2 b ON a.id = b.id",
    )
    print("2 tables  ->", d.outcome.value)

    # 4 tables — denied by the custom rule.
    d = guard.evaluate_static(
        "SELECT a.id "
        "FROM db.public.t1 a "
        "JOIN db.public.t2 b ON a.id = b.id "
        "JOIN db.public.t3 c ON a.id = c.id "
        "JOIN db.public.t4 d ON a.id = d.id",
    )
    print("4 tables  ->", d.outcome.value, "—", d.reason)


if __name__ == "__main__":
    main()
