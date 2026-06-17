"""Use the same guard across BigQuery, Snowflake, and Postgres."""

from __future__ import annotations

from sql_guard import PiiDenylist, SqlGuard, SqlGuardConfig

_PII = PiiDenylist.from_mapping(
    {"columns": ["email", "phone_number"], "substrings": ["address"]},
)


def main() -> None:
    cases = [
        (
            "bigquery",
            "SELECT order_id FROM `proj.analytics.orders` "
            "QUALIFY ROW_NUMBER() OVER (ORDER BY 1) = 1",
        ),
        (
            "snowflake",
            "SELECT order_id FROM analytics.orders "
            "QUALIFY ROW_NUMBER() OVER (ORDER BY 1) = 1",
        ),
        (
            "postgres",
            "SELECT order_id::TEXT AS oid FROM analytics.orders",
        ),
        (
            "duckdb",
            "SELECT order_id FROM analytics.orders LIMIT 10",
        ),
    ]

    for dialect, sql in cases:
        guard = SqlGuard(
            SqlGuardConfig.from_settings(
                pii_denylist=_PII,
                allowed_tables=[
                    "proj.analytics.orders",
                    "analytics.orders",
                ],
                dialect=dialect,
            ),
        )
        decision = guard.evaluate_static(sql)
        print(f"{dialect:<10} -> {decision.outcome.value:<7} {sql[:60]}")


if __name__ == "__main__":
    main()
