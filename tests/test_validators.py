"""Tests for the shared Settings validators."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from kag_common.validators import enforce_production_required_fields, normalize_database_url_scheme


def test_normalize_bare_postgresql_scheme():
    assert (
        normalize_database_url_scheme("postgresql://u:p@h:5432/db")
        == "postgresql+psycopg://u:p@h:5432/db"
    )


def test_normalize_is_idempotent_and_passthrough():
    already = "postgresql+psycopg://u:p@h/db"
    assert normalize_database_url_scheme(already) == already
    # Non-string values pass through untouched (before-validator safety).
    assert normalize_database_url_scheme(None) is None
    assert normalize_database_url_scheme(123) == 123


@dataclass
class _FakeSettings:
    environment: str
    database_url: str = ""
    license_introspect_url: str = ""


def test_enforce_skips_outside_production():
    obj = _FakeSettings(environment="test")  # all required empty, but not prod
    enforce_production_required_fields(
        obj, ("database_url", "license_introspect_url"), service_name="svc"
    )


def test_enforce_raises_on_missing_in_production():
    obj = _FakeSettings(environment="production", database_url="set")
    with pytest.raises(RuntimeError, match="missing required fields in production"):
        enforce_production_required_fields(
            obj, ("database_url", "license_introspect_url"), service_name="svc"
        )


def test_enforce_passes_when_all_present_in_production():
    obj = _FakeSettings(environment="production", database_url="set", license_introspect_url="set")
    enforce_production_required_fields(
        obj, ("database_url", "license_introspect_url"), service_name="svc"
    )


def test_enforce_honours_explicit_environment_override():
    obj = _FakeSettings(environment="test")
    with pytest.raises(RuntimeError):
        enforce_production_required_fields(
            obj, ("database_url",), service_name="svc", environment="production"
        )
