"""Reusable Settings validators shared across the KAG backends.

Pure helpers — NOT a base Settings class. Each service keeps its own
``BaseSettings``/dataclass, its own field set, and its own
``_REQUIRED_IN_PRODUCTION`` tuple; it just calls these so the
``postgresql://`` → ``postgresql+psycopg://`` normalization and the
fail-fast-in-production check live in one tested place.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

__all__ = ["enforce_production_required_fields", "normalize_database_url_scheme"]


def normalize_database_url_scheme(value: Any) -> Any:
    """Coerce a bare ``postgresql://`` DSN to the psycopg-v3 ``postgresql+psycopg://``.

    Safe as a Pydantic ``mode="before"`` field validator: non-string and
    already-qualified values pass through unchanged (idempotent).
    """
    if isinstance(value, str) and value.startswith("postgresql://"):
        return value.replace("postgresql://", "postgresql+psycopg://", 1)
    return value


def enforce_production_required_fields(
    obj: Any,
    required: Sequence[str],
    *,
    service_name: str,
    environment: str | None = None,
) -> None:
    """Fail fast when required fields are empty under ``environment=production``.

    ``environment`` defaults to ``obj.environment``. Only enforced in production
    so dev/test can construct Settings with empty placeholder URLs. Mirrors the
    config-externalization policy: required URLs/secrets come from env vars on
    the Deployment, never from in-code defaults.
    """
    env = environment if environment is not None else getattr(obj, "environment", None)
    if env != "production":
        return
    missing = [name for name in required if not getattr(obj, name)]
    if missing:
        raise RuntimeError(
            f"{service_name} settings missing required fields in production: "
            f"{missing}. Set them via env vars on the Deployment (see gitops-production)."
        )
