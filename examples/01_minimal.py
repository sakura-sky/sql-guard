"""Minimal example: guard a single BigQuery SQL string.

    $ pip install sql-guard
    $ python 01_minimal.py
"""

from __future__ import annotations

from sql_guard import PiiDenylist, SqlGuard, SqlGuardConfig


def main() -> None:
    guard = SqlGuard(
        SqlGuardConfig.from_settings(
            pii_denylist=PiiDenylist.from_mapping(
                {
                    "columns": ["email", "phone_number", "ssn"],
                    "substrings": ["address"],
                },
            ),
            allowed_tables=["my-project.analytics.orders"],
        ),
    )

    # Safe query — passes static checks, awaiting a dry-run cost figure.
    decision = guard.evaluate_static(
        "SELECT customer_id, SUM(total) FROM `my-project.analytics.orders` "
        "GROUP BY customer_id",
    )
    print("safe query  :", decision.outcome.value, "—", decision.reason)

    # PII leak — projection includes `email`.
    decision = guard.evaluate_static(
        "SELECT email FROM `my-project.analytics.orders`",
    )
    print("pii leak    :", decision.outcome.value, "—", decision.reason)

    # Table not on the allowlist.
    decision = guard.evaluate_static(
        "SELECT customer_id FROM `some-other-project.private.users`",
    )
    print("bad table   :", decision.outcome.value, "—", decision.reason)

    # DML disguised inside a SELECT — still rejected.
    decision = guard.evaluate_static(
        "DELETE FROM `my-project.analytics.orders` WHERE customer_id = 1",
    )
    print("dml         :", decision.outcome.value, "—", decision.reason)


if __name__ == "__main__":
    main()
