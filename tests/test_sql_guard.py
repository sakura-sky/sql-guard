"""Unit tests for the deterministic SQL guard.

These tests cover the rules called out in the PDF test cases:

* Positive Q1-Q4 SQL should pass the static checks.
* Negative N1 ("emails and mobiles") must be DENY.
* Negative N2 ("all transactions") must be DENY (bare ``SELECT *``).
* Cost-cap rules: dry-run bytes drive ALLOW / CONFIRM / DENY.
"""

from __future__ import annotations

import pytest

from sql_guard import GuardOutcome, SqlGuard

# ---------------------------------------------------------------------------
# Positive cases from the PDF
# ---------------------------------------------------------------------------


_Q1 = """
WITH base AS (
    SELECT
        uid,
        LOWER(TRIM(DRC_Email)) AS drc_email_norm,
        RIGHT(REGEXP_REPLACE(DRC_Mobile, r'\\D', ''), 10) AS drc_mobile_norm,
        SevenR_Emails,
        SevenR_Mobiles,
        MeU_Emails,
        MeU_Mobiles
    FROM `agentspaceseagrass.demo_data.ocv`
)
SELECT
    COUNTIF(drc_email_norm IS NOT NULL OR drc_mobile_norm IS NOT NULL) AS drc_member_count,
    COUNTIF(
        (drc_email_norm IS NOT NULL AND EXISTS (
            SELECT 1 FROM UNNEST(SevenR_Emails) e
            WHERE LOWER(TRIM(e)) = drc_email_norm
        ))
        OR (drc_mobile_norm IS NOT NULL AND EXISTS (
            SELECT 1 FROM UNNEST(SevenR_Mobiles) m
            WHERE RIGHT(REGEXP_REPLACE(m, r'\\D', ''), 10) = drc_mobile_norm
        ))
    ) AS drc_in_sevenrooms,
    COUNTIF(
        (drc_email_norm IS NOT NULL AND EXISTS (
            SELECT 1 FROM UNNEST(MeU_Emails) e
            WHERE LOWER(TRIM(e)) = drc_email_norm
        ))
        OR (drc_mobile_norm IS NOT NULL AND EXISTS (
            SELECT 1 FROM UNNEST(MeU_Mobiles) m
            WHERE RIGHT(REGEXP_REPLACE(m, r'\\D', ''), 10) = drc_mobile_norm
        ))
    ) AS drc_in_meu
FROM base
"""


_Q2 = """
SELECT DRC_Tier, COUNT(*) AS customer_count
FROM `prod-loyalty-silver-seagrass.TRANSACTIONS.join_matched_pii_transactions_tb`
WHERE lifetime_spend > 5000
GROUP BY DRC_Tier
"""


_Q3 = """
SELECT DRC_Tier, COUNT(*) AS lapsed_count
FROM `prod-loyalty-silver-seagrass.TRANSACTIONS.join_matched_pii_transactions_tb`
WHERE overall_last_transaction_date < DATE_SUB(CURRENT_DATE(), INTERVAL 6 MONTH)
   OR overall_last_transaction_date IS NULL
GROUP BY DRC_Tier
"""


_Q4 = """
SELECT
    DRC_Tier,
    COUNT(uid) AS customer_count,
    AVG(Lifetime_Spend) AS average_spend,
    AVG(lifetime_transaction_count) AS average_visit_frequency
FROM `prod-loyalty-silver-seagrass.TRANSACTIONS.join_matched_pii_transactions_tb`
GROUP BY DRC_Tier
"""


@pytest.mark.parametrize(
    ("name", "sql"),
    [("Q1", _Q1), ("Q2", _Q2), ("Q3", _Q3), ("Q4", _Q4)],
)
def test_positive_cases_pass_static(sql_guard: SqlGuard, name: str, sql: str) -> None:
    decision = sql_guard.evaluate_static(sql)
    assert decision.outcome is not GuardOutcome.DENY, (
        f"{name} unexpectedly denied: {decision.reason}"
    )
    # Static check should leave us in CONFIRM (awaiting cost data).
    assert decision.outcome is GuardOutcome.CONFIRM


# ---------------------------------------------------------------------------
# Negative cases from the PDF
# ---------------------------------------------------------------------------


def test_n1_pii_query_is_denied(sql_guard: SqlGuard) -> None:
    sql = """
        SELECT DRC_Email, DRC_Mobile
        FROM `agentspaceseagrass.demo_data.ocv`
        WHERE lifetime_spend > 5000
    """
    decision = sql_guard.evaluate_static(sql)
    assert decision.outcome is GuardOutcome.DENY
    assert "PII" in decision.reason or "pii" in decision.reason.lower()
    assert any("email" in c.lower() for c in decision.pii_columns)


def test_n2_select_star_transactions_is_denied(sql_guard: SqlGuard) -> None:
    sql = (
        "SELECT * "
        "FROM `prod-loyalty-silver-seagrass.TRANSACTIONS.join_matched_pii_transactions_tb`"
    )
    decision = sql_guard.evaluate_static(sql)
    assert decision.outcome is GuardOutcome.DENY


def test_select_star_except_is_denied(sql_guard: SqlGuard) -> None:
    """`SELECT * EXCEPT(...)` is no longer a PII-safe escape hatch.

    The previous behaviour trusted EXCEPT to strip PII, but the guard cannot
    prove the EXCEPT list is exhaustive — a future PII column added to the
    table would silently start leaking. Reject it; require explicit columns.
    """
    sql = (
        "SELECT * EXCEPT(DRC_Email, DRC_Mobile) "
        "FROM `agentspaceseagrass.demo_data.ocv`"
    )
    decision = sql_guard.evaluate_static(sql)
    assert decision.outcome is GuardOutcome.DENY
    assert "*" in decision.reason


def test_aliased_pii_column_is_denied(sql_guard: SqlGuard) -> None:
    """`SELECT DRC_Email AS x` must still flag DRC_Email."""
    sql = "SELECT DRC_Email AS x FROM `agentspaceseagrass.demo_data.ocv`"
    decision = sql_guard.evaluate_static(sql)
    assert decision.outcome is GuardOutcome.DENY
    assert any("email" in c.lower() for c in decision.pii_columns)


def test_pii_in_function_call_is_denied(sql_guard: SqlGuard) -> None:
    """`SELECT LOWER(DRC_Email)` reaches through the function to flag PII."""
    sql = "SELECT LOWER(DRC_Email) AS x FROM `agentspaceseagrass.demo_data.ocv`"
    decision = sql_guard.evaluate_static(sql)
    assert decision.outcome is GuardOutcome.DENY


def test_pii_in_union_right_arm_is_denied(sql_guard: SqlGuard) -> None:
    """A clean left arm cannot mask a PII projection in the right arm."""
    sql = (
        "SELECT uid FROM `agentspaceseagrass.demo_data.ocv` "
        "UNION ALL "
        "SELECT DRC_Email FROM `agentspaceseagrass.demo_data.ocv`"
    )
    decision = sql_guard.evaluate_static(sql)
    assert decision.outcome is GuardOutcome.DENY


def test_select_count_star_is_allowed(sql_guard: SqlGuard) -> None:
    """`SELECT COUNT(*)` is a scalar aggregate, not a projection of `*`."""
    sql = "SELECT COUNT(*) FROM `agentspaceseagrass.demo_data.ocv`"
    decision = sql_guard.evaluate_static(sql)
    assert decision.outcome is not GuardOutcome.DENY


def test_pii_in_subquery_where_is_allowed(sql_guard: SqlGuard) -> None:
    """A scalar-returning subquery that *consumes* PII in WHERE is fine.

    The subquery emits a count, not the PII value. The guard must not flag
    DRC_Email referenced inside the subquery's WHERE clause.
    """
    sql = """
    SELECT
      (SELECT COUNT(*) FROM `prod-loyalty-silver-seagrass.IDENTITY.matched_data`
       WHERE DRC_Email IS NOT NULL AND ARRAY_LENGTH(SevenR_Emails) > 0
      ) AS sevenrooms_count,
      (SELECT COUNT(*) FROM `prod-loyalty-silver-seagrass.IDENTITY.matched_data`
       WHERE DRC_Email IS NOT NULL AND ARRAY_LENGTH(MeU_Emails) > 0
      ) AS meu_count
    """
    decision = sql_guard.evaluate_static(sql)
    assert decision.outcome is not GuardOutcome.DENY, decision.reason


def test_pii_actually_projected_by_subquery_is_denied(sql_guard: SqlGuard) -> None:
    """If a subquery *projects* PII, the guard must still catch it."""
    sql = (
        "SELECT (SELECT DRC_Email "
        "FROM `prod-loyalty-silver-seagrass.IDENTITY.matched_data` LIMIT 1) AS leaked"
    )
    decision = sql_guard.evaluate_static(sql)
    assert decision.outcome is GuardOutcome.DENY
    assert any("email" in c.lower() for c in decision.pii_columns)


def test_pii_in_where_of_outer_query_is_allowed(sql_guard: SqlGuard) -> None:
    """Using PII in a WHERE filter while projecting non-PII columns is fine."""
    sql = (
        "SELECT uid, COUNT(*) AS n "
        "FROM `prod-loyalty-silver-seagrass.IDENTITY.matched_data` "
        "WHERE DRC_Email IS NOT NULL "
        "GROUP BY uid"
    )
    decision = sql_guard.evaluate_static(sql)
    assert decision.outcome is not GuardOutcome.DENY, decision.reason


# ---------------------------------------------------------------------------
# Disallowed statements
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "sql",
    [
        "INSERT INTO `agentspaceseagrass.demo_data.ocv` (uid) VALUES ('x')",
        "DELETE FROM `agentspaceseagrass.demo_data.ocv` WHERE uid = 'x'",
        "UPDATE `agentspaceseagrass.demo_data.ocv` SET DRC_Tier = 'VIP'",
        "CREATE TABLE `agentspaceseagrass.demo_data.foo` (x INT64)",
        "DROP TABLE `agentspaceseagrass.demo_data.foo`",
    ],
)
def test_dml_and_ddl_are_denied(sql_guard: SqlGuard, sql: str) -> None:
    decision = sql_guard.evaluate_static(sql)
    assert decision.outcome is GuardOutcome.DENY


def test_multi_statement_script_is_denied(sql_guard: SqlGuard) -> None:
    sql = (
        "SELECT 1; "
        "SELECT 2;"
    )
    decision = sql_guard.evaluate_static(sql)
    assert decision.outcome is GuardOutcome.DENY


def test_unparseable_sql_is_denied(sql_guard: SqlGuard) -> None:
    decision = sql_guard.evaluate_static("this is not sql at all !!! ;;")
    assert decision.outcome is GuardOutcome.DENY


def test_empty_query_is_denied(sql_guard: SqlGuard) -> None:
    decision = sql_guard.evaluate_static("   ")
    assert decision.outcome is GuardOutcome.DENY


# ---------------------------------------------------------------------------
# Table allowlist
# ---------------------------------------------------------------------------


def test_query_outside_allowlist_is_denied(sql_guard: SqlGuard) -> None:
    sql = "SELECT uid FROM `some-other-project.some_dataset.some_table`"
    decision = sql_guard.evaluate_static(sql)
    assert decision.outcome is GuardOutcome.DENY
    assert "allowlist" in decision.reason.lower()


def test_query_on_allowlisted_table_passes(sql_guard: SqlGuard) -> None:
    sql = "SELECT DRC_Tier FROM `agentspaceseagrass.demo_data.ocv`"
    decision = sql_guard.evaluate_static(sql)
    assert decision.outcome is GuardOutcome.CONFIRM


# ---------------------------------------------------------------------------
# Cost guard
# ---------------------------------------------------------------------------


def test_cost_below_auto_threshold_allows(sql_guard: SqlGuard) -> None:
    # 1 MiB at $5/TiB is well under $0.10.
    decision = sql_guard.evaluate_cost(bytes_processed=1024 * 1024)
    assert decision.outcome is GuardOutcome.ALLOW
    assert decision.auto_execute is True


def test_cost_between_auto_and_hard_caps_asks_to_confirm(sql_guard: SqlGuard) -> None:
    # 50 GB processed: ~$0.24 — above $0.10 auto, below $20 hard.
    # But the 10 GiB bytes-billed cap kicks in first, so 5 GiB instead:
    bytes_5gib = 5 * 1024**3  # ~$0.025 -- under auto. Use higher.
    # Choose a size that lands between caps: ~$1.00 → 200 GB.
    # Bytes-billed cap is 10 GiB so we need to also raise it for this test
    # via a one-off guard instance.
    from sql_guard import PiiDenylist, SqlGuardConfig
    custom = SqlGuard(
        SqlGuardConfig.from_settings(
            pii_denylist=PiiDenylist.from_mapping({"columns": [], "substrings": []}),
            allowed_tables=[],
            max_cost_usd_auto=0.10,
            max_cost_usd_hard=20.00,
            max_bytes_billed=1024**4,  # 1 TiB
            enforce_allowed_tables=False,
        ),
    )
    decision = custom.evaluate_cost(bytes_processed=200 * 1024**3)
    assert decision.outcome is GuardOutcome.CONFIRM
    assert decision.auto_execute is False
    _ = bytes_5gib  # appease ruff


def test_cost_above_hard_cap_denies() -> None:
    from sql_guard import PiiDenylist, SqlGuardConfig

    guard = SqlGuard(
        SqlGuardConfig.from_settings(
            pii_denylist=PiiDenylist.from_mapping({"columns": [], "substrings": []}),
            allowed_tables=[],
            max_cost_usd_auto=0.10,
            max_cost_usd_hard=20.00,
            max_bytes_billed=10 * 1024**4,  # 10 TiB so the bytes-billed cap is not what hits
            enforce_allowed_tables=False,
        ),
    )
    # 5 TiB → $25
    decision = guard.evaluate_cost(bytes_processed=5 * 1024**4)
    assert decision.outcome is GuardOutcome.DENY


def test_bytes_billed_cap_denies(sql_guard: SqlGuard) -> None:
    # 20 GiB exceeds the 10 GiB bytes-billed default in the fixture.
    decision = sql_guard.evaluate_cost(bytes_processed=20 * 1024**3)
    assert decision.outcome is GuardOutcome.DENY
    assert "bytes-billed" in decision.reason.lower()


def test_evaluate_combines_static_and_cost(sql_guard: SqlGuard) -> None:
    decision = sql_guard.evaluate(
        "SELECT DRC_Tier FROM `agentspaceseagrass.demo_data.ocv`",
        bytes_processed=1024 * 1024,
    )
    assert decision.outcome is GuardOutcome.ALLOW
