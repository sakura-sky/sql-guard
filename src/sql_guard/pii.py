"""PII denylist — a deterministic check for columns the agent must never return."""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class PiiDenylist:
    """Case-insensitive set of column names the agent is forbidden to project.

    The denylist is loaded from a JSON file shipped under
    ``prompts/<agent>/pii_denylist.json`` — keeping it in config means we can
    update PII policy without a code change. The file is a flat list of column
    names; substring matches like ``email`` will also catch ``email_alt``.
    """

    columns: frozenset[str]
    substrings: frozenset[str]

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------
    @classmethod
    def from_file(cls, path: Path) -> PiiDenylist:
        if not path.exists():
            raise FileNotFoundError(f"PII denylist not found: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls.from_mapping(data)

    @classmethod
    def from_mapping(cls, data: dict[str, object]) -> PiiDenylist:
        columns = _as_lower_set(data.get("columns", ()))
        substrings = _as_lower_set(data.get("substrings", ()))
        return cls(columns=frozenset(columns), substrings=frozenset(substrings))

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------
    def is_blocked(self, column_name: str) -> bool:
        """Return True if *column_name* is on the denylist.

        Both exact (case-insensitive) matches and substring rules apply.
        """
        if not column_name:
            return False
        key = column_name.lower()
        if key in self.columns:
            return True
        return any(token in key for token in self.substrings)

    def matching(self, column_names: Iterable[str]) -> list[str]:
        """Return the input names that are blocked, preserving the original casing."""
        return [c for c in column_names if self.is_blocked(c)]


def _as_lower_set(items: object) -> set[str]:
    if not isinstance(items, list):
        raise TypeError(f"Expected list, got {type(items).__name__}")
    out: set[str] = set()
    for item in items:
        if not isinstance(item, str):
            raise TypeError(f"PII denylist entries must be strings; got {item!r}")
        if not item.strip():
            continue
        out.add(item.strip().lower())
    return out
