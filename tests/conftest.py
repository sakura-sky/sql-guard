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

    Synthetic ``example-project`` names — not tied to any real warehouse. The
    test SQL embeds these same names.
    """
    return frozenset(
        t.lower()
        for t in [
            "example-project.analytics.customers",
            "example-project.analytics.identity",
            "example-project.analytics.transactions",
        ]
    )


@pytest.fixture
def sql_guard(pii_denylist: PiiDenylist, allowed_tables: frozenset[str]) -> SqlGuard:
    """Guard with default settings — i.e. ``pii_mode="reference"``."""
    return SqlGuard(
        SqlGuardConfig.from_settings(
            pii_denylist=pii_denylist,
            allowed_tables=allowed_tables,
            max_cost_usd_auto=0.10,
            max_cost_usd_hard=20.00,
            max_bytes_billed=10 * 1024**3,
        ),
    )


@pytest.fixture
def project_mode_guard(pii_denylist: PiiDenylist, allowed_tables: frozenset[str]) -> SqlGuard:
    """Guard with the looser ``pii_mode="project"`` policy.

    Denylisted columns may appear in predicates; only projections are denied.
    Used to pin the behaviour of the documented loosening path.
    """
    return SqlGuard(
        SqlGuardConfig.from_settings(
            pii_denylist=pii_denylist,
            allowed_tables=allowed_tables,
            pii_mode="project",
            max_cost_usd_auto=0.10,
            max_cost_usd_hard=20.00,
            max_bytes_billed=10 * 1024**3,
        ),
    )
