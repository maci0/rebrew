"""Compiler flag primitives — compatible with decomp.me's flag format.

FlagSet:  mutually exclusive options (pick one or none)
Checkbox: optional toggle (on or off)

These match the data structures in decomp.me's backend/coreapp/flags.py
so we can programmatically sync flag definitions.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class FlagSet:
    """A set of mutually exclusive compiler flags (pick one or none)."""

    id: str
    flags: tuple[str, ...]


@dataclass(frozen=True)
class Checkbox:
    """An optional toggle flag (on or off)."""

    id: str
    flag: str


Flags = list[FlagSet | Checkbox]
