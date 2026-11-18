"""Environment-variable coercion helpers.

The byte-identical ``_get_env`` / ``_get_int`` / ``_get_float`` / ``_get_bool``
helpers each KAG backend hand-rolled in its config module. Names keep their
leading underscore so existing call sites adopt the shared copy with a single
import swap and no edits to the dozens of ``field(default_factory=...)`` sites.
"""

from __future__ import annotations

import os

__all__ = ["_get_bool", "_get_env", "_get_float", "_get_int"]


def _get_env(name: str, default: str) -> str:
    return os.getenv(name, default)


def _get_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _get_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _get_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    lowered = value.strip().lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    return default
