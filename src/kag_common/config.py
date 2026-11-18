"""Shared Pydantic ``BaseSettings`` base for the KAG backend services.

Every KAG service hand-rolled the same settings boilerplate: an identical
``SettingsConfigDict``, the empty-env-to-default coercion (GitHub Actions emits
``""`` for skipped-step outputs, which pydantic-settings would otherwise crash
on when parsing an int/float field), the ``postgresql://`` → ``postgresql+psycopg://``
normalizer, and the fail-fast ``_REQUIRED_IN_PRODUCTION`` check. ``BaseServiceSettings``
owns that cross-cutting surface so each service's settings module carries only
its own fields.

Usage:

    from kag_common.config import BaseServiceSettings


    class Settings(BaseServiceSettings):
        service_name: str = "karma-service"

        database_url: str = ""
        worker_management_url: str = ""

        _REQUIRED_IN_PRODUCTION = ("database_url", "worker_management_url")

The base deliberately does NOT declare ``database_url`` or any infra-URL fields
itself — services that don't have a database (e.g. kag_graph_service) must not
inherit one (see ``_normalize_database_url_scheme`` for how the normalizer stays
a no-op for those services).
"""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from kag_common.validators import (
    enforce_production_required_fields,
    normalize_database_url_scheme,
)


class BaseServiceSettings(BaseSettings):
    """Shared settings base for KAG backend services.

    Subclasses override ``service_name`` with their own identity, add their
    service-specific fields, and set ``_REQUIRED_IN_PRODUCTION`` to the tuple of
    field names that must be non-empty when ``environment == "production"``.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        frozen=True,
    )

    # Hyphenated service identity (e.g. "karma-service", not "karma_service") —
    # used verbatim as the metrics/log label. Subclass sets it; no default here.
    service_name: str
    version: str = "1.0.0"
    environment: str = "production"

    # Field names enforced non-empty under ``environment=production``. Empty in
    # the base; subclasses override. The after-validator reads it off ``self`` so
    # the subclass value is honoured.
    _REQUIRED_IN_PRODUCTION: ClassVar[tuple[str, ...]] = ()

    @model_validator(mode="before")
    @classmethod
    def _coerce_empty_env_to_default(cls, data: Any) -> Any:
        """Treat empty-string env vars as unset.

        GitHub Actions evaluates ``${{ steps.<id>.outputs.<x> }}`` to an empty
        string when the producing step was skipped (e.g. ``REDIS_PORT`` when
        ``has_redis: false`` in the python-service archetype). pydantic-settings
        would otherwise try to parse ``""`` as int/float and crash. Stripping
        empty strings here lets defaults apply.
        """
        if isinstance(data, dict):
            return {k: v for k, v in data.items() if v != ""}
        return data

    @field_validator("database_url", mode="before", check_fields=False)
    @classmethod
    def _normalize_database_url_scheme(cls, value: Any) -> Any:
        """Coerce bare ``postgresql://`` to ``postgresql+psycopg://``.

        ``check_fields=False``: no-op for subclasses that don't declare a
        ``database_url`` field; active for those that do.
        """
        return normalize_database_url_scheme(value)

    @model_validator(mode="after")
    def _enforce_production_required_fields(self) -> BaseServiceSettings:
        """Fail fast on missing prod config (no mutation: frozen-safe)."""
        enforce_production_required_fields(
            self, self._REQUIRED_IN_PRODUCTION, service_name=self.service_name
        )
        return self
