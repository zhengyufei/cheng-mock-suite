"""Fixture loading and plain envelope helpers.

This mock suite intentionally builds plain envelopes only. Real SM2/SM4
encryption is owned by the gate-ministry-entry-contract feature.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "receive"


def list_cases() -> list[str]:
    """Return available receive fixture names."""

    return sorted(path.stem for path in FIXTURES_DIR.glob("*.json"))


def load_case(name: str) -> dict[str, Any]:
    """Load one receive fixture by case name."""

    if "/" in name or "\\" in name:
        raise ValueError("case name must not contain path separators")

    path = FIXTURES_DIR / f"{name}.json"
    if not path.is_file():
        available = ", ".join(list_cases())
        raise FileNotFoundError(f"unknown case {name!r}; available: {available}")

    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def build_plain_envelope(case: dict[str, Any]) -> dict[str, Any]:
    """Build an outer envelope with raw JSON inner data in reqMsgCnt.

    This is a first-stage mock format only. Production-compatible encrypted
    envelopes are implemented by the gate-ministry-entry-contract feature.
    """

    outer = dict(case["outer"])
    inner = dict(case["inner"])
    outer["reqMsgCnt"] = json.dumps(inner, ensure_ascii=False, separators=(",", ":"))
    return outer
