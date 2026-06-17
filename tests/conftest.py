"""Self-contained fixtures for the sql-guard test suite.

The package is independent of any tenant config — these fixtures use synthetic
data so the tests work for any consumer of the package.
"""

from __future__ import annotations

import pytest

from sql_guard import PiiDenylist, SqlGuard, SqlGuardConfig


@pytest.fixture
def pii_denylist() -> PiiDenylist:
    """Representative denylist used across the test suite.

    Columns and substrings are intentionally generic — the same shape any
    consumer would build from their own warehouse schema.
    """
    return PiiDenylist.from_mapping(
        {
            "columns": [
                "drc_email",
                "drc_mobile",
                "email",
                "email_alt",
                "phone_number",
                "phone_number_alt",
                "mobile",
                "first_name",
                "last_name",
                "date_of_birth",
                "address_line1",
            ],
            "substrings": ["email", "mobile", "phone", "address"],
        },
    )


@pytest.fixture
def allowed_tables() -> frozenset[str]:
    """Three fully-qualified tables used by the test suite.

    These remain to keep the existing test cases (which embed these names in
    sample SQL) passing without rewriting every test. They are not
    meaningful to consumers of the package.
    """
    return frozenset(
        t.lower()
        for t in [
            "agentspaceseagrass.demo_data.ocv",
            "prod-loyalty-silver-seagrass.IDENTITY.matched_data",
            "prod-loyalty-silver-seagrass.TRANSACTIONS.join_matched_pii_transactions_tb",
        ]
    )


@pytest.fixture
def sql_guard(pii_denylist: PiiDenylist, allowed_tables: frozenset[str]) -> SqlGuard:
    return SqlGuard(
        SqlGuardConfig.from_settings(
            pii_denylist=pii_denylist,
            allowed_tables=allowed_tables,
            max_cost_usd_auto=0.10,
            max_cost_usd_hard=20.00,
            max_bytes_billed=10 * 1024**3,
        ),
    )
