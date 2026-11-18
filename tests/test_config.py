"""Tests for the shared BaseServiceSettings base class."""

from __future__ import annotations

import pytest

from kag_common.config import BaseServiceSettings


class _ProbeSettings(BaseServiceSettings):
    """Concrete subclass exercising the base: has a database_url + an int field
    + a non-empty required-in-production tuple."""

    service_name: str = "probe-service"
    database_url: str = ""
    some_port: int = 6379

    _REQUIRED_IN_PRODUCTION = ("database_url",)


class _NoDatabaseSettings(BaseServiceSettings):
    """Subclass WITHOUT a database_url field — mimics kag_graph_service. Proves
    the normalizer's check_fields=False makes it a no-op here."""

    service_name: str = "no-db-service"


def test_defaults_applied_when_env_unset(monkeypatch: pytest.MonkeyPatch):
    for var in ("ENVIRONMENT", "VERSION", "DATABASE_URL", "SOME_PORT"):
        monkeypatch.delenv(var, raising=False)
    s = _ProbeSettings(environment="test")
    assert s.service_name == "probe-service"
    assert s.version == "1.0.0"
    assert s.environment == "test"
    assert s.some_port == 6379


def test_env_override_is_case_insensitive(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("environment", "test")
    monkeypatch.setenv("SOME_PORT", "7000")
    s = _ProbeSettings()
    assert s.environment == "test"
    assert s.some_port == 7000


def test_empty_string_env_coerced_to_default(monkeypatch: pytest.MonkeyPatch):
    # A skipped GitHub Actions step emits "" — must not crash int parsing and
    # must fall back to the field default.
    monkeypatch.setenv("SOME_PORT", "")
    monkeypatch.setenv("DATABASE_URL", "")
    s = _ProbeSettings(environment="test")
    assert s.some_port == 6379
    assert s.database_url == ""


def test_database_url_scheme_normalized(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@h:5432/db")
    s = _ProbeSettings(environment="test")
    assert s.database_url == "postgresql+psycopg://u:p@h:5432/db"


def test_subclass_without_database_url_constructs(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    s = _NoDatabaseSettings(environment="test")
    assert s.service_name == "no-db-service"


def test_prod_required_raises_when_missing(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(RuntimeError, match="missing required fields in production"):
        _ProbeSettings(environment="production")


def test_prod_required_passes_when_present(monkeypatch: pytest.MonkeyPatch):
    s = _ProbeSettings(environment="production", database_url="postgresql+psycopg://h/db")
    assert s.environment == "production"


def test_prod_required_skipped_outside_production(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    s = _ProbeSettings(environment="test")  # required empty, but not prod
    assert s.database_url == ""


def test_coerce_empty_env_passes_through_non_dict():
    # Defensive branch: pydantic can hand the before-validator a non-dict input
    # (e.g. a model instance on revalidation) — it must pass through untouched.
    sentinel = ["unchanged"]
    assert BaseServiceSettings._coerce_empty_env_to_default(sentinel) is sentinel
