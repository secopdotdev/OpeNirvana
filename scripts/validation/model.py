"""Typed finding model for the validation framework."""

from __future__ import annotations

import enum
from dataclasses import dataclass


class Severity(enum.Enum):
    """A finding either blocks a merge or warns (ratchet candidate)."""

    BLOCK = "BLOCK"
    WARN = "WARN"


class Tier(enum.IntEnum):
    """Blast-radius tier. Lower value == higher risk == more rigor."""

    T0 = 0  # crown jewels — identity & secrets
    T1 = 1  # deployment integrity
    T2 = 2  # operational / generators


@dataclass(frozen=True)
class Finding:
    """One normalized result from any validation tool."""

    tool: str
    severity: Severity
    message: str
    file: str | None = None
    line: int | None = None
    tier: Tier | None = None
    rule: str | None = None
