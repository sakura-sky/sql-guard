"""Unit tests for the PII denylist."""

from __future__ import annotations

import pytest

from sql_guard import PiiDenylist


@pytest.fixture
def denylist() -> PiiDenylist:
    return PiiDenylist.from_mapping(
        {
            "columns": ["DRC_Email", "DRC_Mobile"],
            "substrings": ["phone", "address"],
        },
    )


@pytest.mark.parametrize(
    "col",
    ["DRC_Email", "drc_email", "DRC_EMAIL", "DRC_Mobile"],
)
def test_exact_match_is_case_insensitive(denylist: PiiDenylist, col: str) -> None:
    assert denylist.is_blocked(col)


@pytest.mark.parametrize(
    "col",
    ["phone_number", "PHONE_NUMBER_alt", "address_line1", "shipping_address"],
)
def test_substring_match(denylist: PiiDenylist, col: str) -> None:
    assert denylist.is_blocked(col)


@pytest.mark.parametrize(
    "col",
    ["DRC_Tier", "lifetime_spend", "uid", "drc_join_date"],
)
def test_safe_columns_are_allowed(denylist: PiiDenylist, col: str) -> None:
    assert not denylist.is_blocked(col)


def test_empty_string_is_not_blocked(denylist: PiiDenylist) -> None:
    assert not denylist.is_blocked("")


def test_matching_returns_only_blocked(denylist: PiiDenylist) -> None:
    columns = ["uid", "DRC_Email", "DRC_Tier", "phone_number_alt"]
    assert denylist.matching(columns) == ["DRC_Email", "phone_number_alt"]


def test_fixture_denylist_smoke(pii_denylist: PiiDenylist) -> None:
    """Smoke test against the conftest fixture (representative of real configs)."""
    assert pii_denylist.is_blocked("DRC_Email")
    assert pii_denylist.is_blocked("phone_number")
    assert not pii_denylist.is_blocked("DRC_Tier")
