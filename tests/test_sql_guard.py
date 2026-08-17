"""Unit tests for the deterministic SQL guard.

These tests exercise the guard's rules with synthetic ``example-project`` data:

* Positive Q2-Q4 SQL should pass the static checks.
* Q1 (identity resolution over normalised email/mobile) is DENY as of 0.2.0 —
  see :func:`test_q1_identity_resolution_is_denied` for why.
* Negative N1 ("emails and mobiles") must be DENY.
* Negative N2 ("all transactions") must be DENY (bare ``SELECT *``).
* Cost-cap rules: dry-run bytes drive ALLOW / CONFIRM / DENY.

Scope-bypass regressions (CTE / derived-table / UNION-arm aliasing, value
probing via predicates) live in ``test_pii_scopes.py``.
"""

from __future__ import annotations

import pytest

from sql_guard import GuardOutcome, SqlGuard

# ---------------------------------------------------------------------------
# Positive cases
# ---------------------------------------------------------------------------


_Q1 = """
WITH base AS (
    SELECT
        uid,
        LOWER(TRIM(email)) AS email_norm,
        RIGHT(REGEXP_REPLACE(mobile, r'\\D', ''), 10) AS mobile_norm,
        platform_a_emails,
        platform_a_mobiles,
        platform_b_emails,
        platform_b_mobiles
    FROM `example-project.analytics.customers`
)
SELECT
    COUNTIF(email_norm IS NOT NULL OR mobile_norm IS NOT NULL) AS member_count,
    COUNTIF(
        (email_norm IS NOT NULL AND EXISTS (
            SELECT 1 FROM UNNEST(platform_a_emails) e
            WHERE LOWER(TRIM(e)) = email_norm
        ))
        OR (mobile_norm IS NOT NULL AND EXISTS (
            SELECT 1 FROM UNNEST(platform_a_mobiles) m
            WHERE RIGHT(REGEXP_REPLACE(m, r'\\D', ''), 10) = mobile_norm
        ))
    ) AS in_platform_a,
    COUNTIF(
        (email_norm IS NOT NULL AND EXISTS (
            SELECT 1 FROM UNNEST(platform_b_emails) e
            WHERE LOWER(TRIM(e)) = email_norm
        ))
        OR (mobile_norm IS NOT NULL AND EXISTS (
            SELECT 1 FROM UNNEST(platform_b_mobiles) m
            WHERE RIGHT(REGEXP_REPLACE(m, r'\\D', ''), 10) = mobile_norm
        ))
    ) AS in_platform_b
FROM base
"""


_Q2 = """
SELECT tier, COUNT(*) AS customer_count
FROM `example-project.analytics.transactions`
WHERE lifetime_spend > 5000
GROUP BY tier
"""


_Q3 = """
SELECT tier, COUNT(*) AS lapsed_count
FROM `example-project.analytics.transactions`
WHERE overall_last_transaction_date < DATE_SUB(CURRENT_DATE(), INTERVAL 6 MONTH)
   OR overall_last_transaction_date IS NULL
GROUP BY tier
"""


_Q4 = """
SELECT
    tier,
    COUNT(uid) AS customer_count,
    AVG(lifetime_spend) AS average_spend,
    AVG(lifetime_transaction_count) AS average_visit_frequency
FROM `example-project.analytics.transactions`
GROUP BY tier
"""


@pytest.mark.parametrize(
    ("name", "sql"),
    [("Q2", _Q2), ("Q3", _Q3), ("Q4", _Q4)],
)
def test_positive_cases_pass_static(sql_guard: SqlGuard, name: str, sql: str) -> None:
    decision = sql_guard.evaluate_static(sql)
    assert decision.outcome is not GuardOutcome.DENY, (
        f"{name} unexpectedly denied: {decision.reason}"
    )
    # Static check should leave us in CONFIRM (awaiting cost data).
    assert decision.outcome is GuardOutcome.CONFIRM


@pytest.mark.parametrize("mode", ["reference", "project"])
def test_q1_identity_resolution_is_denied(
    pii_denylist: object,
    allowed_tables: object,
    mode: str,
) -> None:
    """Q1 was a positive case until 0.2.0. It is now denied in *both* modes.

    Q1 normalises PII inside a CTE (``LOWER(TRIM(email)) AS email_norm``) and
    projects only ``COUNTIF`` aggregates, so outermost-only checking saw
    nothing but counts. Two independent reasons it must now fail:

    * ``pii_mode="project"``: the CTE scope projects ``email`` and ``mobile``.
      Checking every scope is what stops an alias laundering a denied column,
      and this query is indistinguishable from that attack at parse time.
    * ``pii_mode="reference"``: the aggregates reference the normalised
      columns. ``COUNTIF(email_norm = 'target@example.com')`` is precisely the
      value-probing oracle reference mode exists to close — an aggregate over
      a denied column still answers questions about individual values.

    Callers who need this pattern should normalise PII in a warehouse view the
    guard's denylist does not cover, and point the agent at the view.
    """
    from sql_guard import PiiDenylist, SqlGuardConfig

    assert isinstance(pii_denylist, PiiDenylist)
    guard = SqlGuard(
        SqlGuardConfig.from_settings(
            pii_denylist=pii_denylist,
            allowed_tables=[],
            pii_mode=mode,  # type: ignore[arg-type]
            enforce_allowed_tables=False,
        ),
    )
    decision = guard.evaluate_static(_Q1)
    assert decision.outcome is GuardOutcome.DENY
    assert any("email" in c.lower() for c in decision.pii_columns)


# ---------------------------------------------------------------------------
# Negative cases
# ---------------------------------------------------------------------------


def test_n1_pii_query_is_denied(sql_guard: SqlGuard) -> None:
    sql = """
        SELECT email, mobile
        FROM `example-project.analytics.customers`
        WHERE lifetime_spend > 5000
    """
    decision = sql_guard.evaluate_static(sql)
    assert decision.outcome is GuardOutcome.DENY
    assert "PII" in decision.reason or "pii" in decision.reason.lower()
    assert any("email" in c.lower() for c in decision.pii_columns)


def test_n2_select_star_transactions_is_denied(sql_guard: SqlGuard) -> None:
    sql = "SELECT * FROM `example-project.analytics.transactions`"
    decision = sql_guard.evaluate_static(sql)
    assert decision.outcome is GuardOutcome.DENY


def test_select_star_except_is_denied(sql_guard: SqlGuard) -> None:
    """`SELECT * EXCEPT(...)` is no longer a PII-safe escape hatch.

    The previous behaviour trusted EXCEPT to strip PII, but the guard cannot
    prove the EXCEPT list is exhaustive — a future PII column added to the
    table would silently start leaking. Reject it; require explicit columns.
    """
    sql = "SELECT * EXCEPT(email, mobile) FROM `example-project.analytics.customers`"
    decision = sql_guard.evaluate_static(sql)
    assert decision.outcome is GuardOutcome.DENY
    assert "*" in decision.reason


def test_aliased_pii_column_is_denied(sql_guard: SqlGuard) -> None:
    """`SELECT email AS x` must still flag email."""
    sql = "SELECT email AS x FROM `example-project.analytics.customers`"
    decision = sql_guard.evaluate_static(sql)
    assert decision.outcome is GuardOutcome.DENY
    assert any("email" in c.lower() for c in decision.pii_columns)


def test_pii_in_function_call_is_denied(sql_guard: SqlGuard) -> None:
    """`SELECT LOWER(email)` reaches through the function to flag PII."""
    sql = "SELECT LOWER(email) AS x FROM `example-project.analytics.customers`"
    decision = sql_guard.evaluate_static(sql)
    assert decision.outcome is GuardOutcome.DENY


def test_pii_in_union_right_arm_is_denied(sql_guard: SqlGuard) -> None:
    """A clean left arm cannot mask a PII projection in the right arm."""
    sql = (
        "SELECT uid FROM `example-project.analytics.customers` "
        "UNION ALL "
        "SELECT email FROM `example-project.analytics.customers`"
    )
    decision = sql_guard.evaluate_static(sql)
    assert decision.outcome is GuardOutcome.DENY


def test_select_count_star_is_allowed(sql_guard: SqlGuard) -> None:
    """`SELECT COUNT(*)` is a scalar aggregate, not a projection of `*`."""
    sql = "SELECT COUNT(*) FROM `example-project.analytics.customers`"
    decision = sql_guard.evaluate_static(sql)
    assert decision.outcome is not GuardOutcome.DENY


def test_pii_in_subquery_where_is_allowed_in_project_mode(project_mode_guard: SqlGuard) -> None:
    """A scalar-returning subquery that *consumes* PII in WHERE.

    The subquery emits a count, not the PII value, so ``pii_mode="project"``
    permits it. Under the default ``"reference"`` mode this same query is
    denied — see :func:`test_pii_in_subquery_where_is_denied_in_reference_mode`.
    """
    sql = """
    SELECT
      (SELECT COUNT(*) FROM `example-project.analytics.identity`
       WHERE email IS NOT NULL AND ARRAY_LENGTH(platform_a_emails) > 0
      ) AS platform_a_count,
      (SELECT COUNT(*) FROM `example-project.analytics.identity`
       WHERE email IS NOT NULL AND ARRAY_LENGTH(platform_b_emails) > 0
      ) AS platform_b_count
    """
    decision = project_mode_guard.evaluate_static(sql)
    assert decision.outcome is not GuardOutcome.DENY, decision.reason


def test_pii_in_subquery_where_is_denied_in_reference_mode(sql_guard: SqlGuard) -> None:
    """The same subquery-WHERE pattern is denied under the default mode.

    ``COUNT(*) ... WHERE email IS NOT NULL`` leaks one bit per query, and the
    predicate can be narrowed (``WHERE email LIKE 'a%'``) to walk a value out.
    """
    sql = """
    SELECT
      (SELECT COUNT(*) FROM `example-project.analytics.identity`
       WHERE email IS NOT NULL
      ) AS c
    """
    decision = sql_guard.evaluate_static(sql)
    assert decision.outcome is GuardOutcome.DENY
    assert any("email" in c.lower() for c in decision.pii_columns)


def test_pii_actually_projected_by_subquery_is_denied(sql_guard: SqlGuard) -> None:
    """If a subquery *projects* PII, the guard must still catch it."""
    sql = "SELECT (SELECT email FROM `example-project.analytics.identity` LIMIT 1) AS leaked"
    decision = sql_guard.evaluate_static(sql)
    assert decision.outcome is GuardOutcome.DENY
    assert any("email" in c.lower() for c in decision.pii_columns)


_PII_IN_WHERE = (
    "SELECT uid, COUNT(*) AS n "
    "FROM `example-project.analytics.identity` "
    "WHERE email IS NOT NULL "
    "GROUP BY uid"
)


def test_pii_in_where_is_allowed_in_project_mode(project_mode_guard: SqlGuard) -> None:
    """Filtering on PII while projecting non-PII is permitted under "project"."""
    decision = project_mode_guard.evaluate_static(_PII_IN_WHERE)
    assert decision.outcome is not GuardOutcome.DENY, decision.reason


def test_pii_in_where_is_denied_in_reference_mode(sql_guard: SqlGuard) -> None:
    """...and denied under the default "reference" mode, which is the point.

    A denied column in a WHERE clause is a value oracle even though it is
    never projected.
    """
    decision = sql_guard.evaluate_static(_PII_IN_WHERE)
    assert decision.outcome is GuardOutcome.DENY
    assert any("email" in c.lower() for c in decision.pii_columns)


# ---------------------------------------------------------------------------
# Disallowed statements
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "sql",
    [
        "INSERT INTO `example-project.analytics.customers` (uid) VALUES ('x')",
        "DELETE FROM `example-project.analytics.customers` WHERE uid = 'x'",
        "UPDATE `example-project.analytics.customers` SET tier = 'VIP'",
        "CREATE TABLE `example-project.analytics.foo` (x INT64)",
        "DROP TABLE `example-project.analytics.foo`",
    ],
)
def test_dml_and_ddl_are_denied(sql_guard: SqlGuard, sql: str) -> None:
    decision = sql_guard.evaluate_static(sql)
    assert decision.outcome is GuardOutcome.DENY


def test_multi_statement_script_is_denied(sql_guard: SqlGuard) -> None:
    sql = "SELECT 1; SELECT 2;"
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
    sql = "SELECT tier FROM `example-project.analytics.customers`"
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
    # Land the cost between the $0.10 auto and $20 hard thresholds (~$1.00 →
    # 200 GB). The default 10 GiB bytes-billed cap would DENY first, so this
    # one-off guard raises it to 1 TiB.
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
        "SELECT tier FROM `example-project.analytics.customers`",
        bytes_processed=1024 * 1024,
    )
    assert decision.outcome is GuardOutcome.ALLOW


# ---------------------------------------------------------------------------
# Cost formatter
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("cost", "expected"),
    [
        # Exact zero — collapse to two decimals.
        (0.0, "$0.00"),
        # Sub-cent costs — dynamic precision, always at least two sig figs.
        # A real BigQuery dry-run against a small table lands here; the old
        # `%.2f` formatter rendered this as "$0.00" which lost the story.
        (0.00000019, "$0.00000019"),
        (0.0000005, "$0.00000050"),
        (0.00001, "$0.000010"),
        (0.0001, "$0.00010"),
        (0.005, "$0.0050"),
        (0.0095, "$0.0095"),
        # Cent and above — two decimals is enough.
        (0.01, "$0.01"),
        (0.10, "$0.10"),
        (1.23, "$1.23"),
        (20.00, "$20.00"),
        # Negative values — used as a sentinel to force confirm-on-every-query.
        # Sign goes outside the dollar to read like a normal currency string.
        (-0.01, "-$0.01"),
        (-0.10, "-$0.10"),
    ],
)
def test_format_cost_precision(cost: float, expected: str) -> None:
    from sql_guard import format_cost

    assert format_cost(cost) == expected


def test_confirm_reason_shows_sub_cent_cost() -> None:
    """The reason string must expose sub-cent costs, not round them to $0.00.

    A BigQuery dry-run on a small table returns bytes → a cost well under a
    cent. Users need to see the actual number in the trace panel; ``$0.00``
    hides whether the guard even ran the cost model.
    """
    from sql_guard import PiiDenylist, SqlGuardConfig, format_cost

    guard = SqlGuard(
        SqlGuardConfig.from_settings(
            pii_denylist=PiiDenylist.from_mapping({"columns": [], "substrings": []}),
            allowed_tables=[],
            max_cost_usd_auto=-0.01,  # force CONFIRM regardless of cost
            max_cost_usd_hard=20.00,
            max_bytes_billed=1024**4,
            enforce_allowed_tables=False,
        ),
    )
    # ~10 MiB → ~$0.00005 at $5/TiB — well under a cent, well under the hard cap.
    decision = guard.evaluate_cost(bytes_processed=10 * 1024 * 1024)
    assert decision.outcome is GuardOutcome.CONFIRM
    assert decision.cost_usd is not None
    assert 0 < decision.cost_usd < 0.01
    # The reason must show the *precise* sub-cent cost, not round it to $0.00.
    # (A naive ``"$0.00" not in reason`` check is wrong — "$0.000048" legitimately
    # begins with "$0.00". Assert on the formatted value itself.)
    shown = format_cost(decision.cost_usd)
    assert shown != "$0.00", f"sub-cent cost rounded away in: {decision.reason!r}"
    assert shown in decision.reason


def test_negative_auto_threshold_forces_confirm_for_zero_cost() -> None:
    """A negative auto threshold guarantees confirm even for a cached query.

    Documents the demo-mode trick: setting ``max_cost_usd_auto=-0.01`` makes
    no non-negative cost satisfy ``cost_usd <= threshold``, so every query
    lands on the CONFIRM branch — including cached queries that report
    ``bytes_processed=0``.
    """
    from sql_guard import PiiDenylist, SqlGuardConfig

    guard = SqlGuard(
        SqlGuardConfig.from_settings(
            pii_denylist=PiiDenylist.from_mapping({"columns": [], "substrings": []}),
            allowed_tables=[],
            max_cost_usd_auto=-0.01,
            max_cost_usd_hard=20.00,
            max_bytes_billed=10 * 1024**3,
            enforce_allowed_tables=False,
        ),
    )
    decision = guard.evaluate_cost(bytes_processed=0)
    assert decision.outcome is GuardOutcome.CONFIRM
    assert "-$0.01" in decision.reason
