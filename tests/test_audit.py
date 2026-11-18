"""Tests for the shared PHI access-audit helpers (kag_common.database.audit)."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.schema import CreateTable

from kag_common.database import (
    AuditWriteError,
    PhiAccessMixin,
    hash_query,
    record_phi_access,
)
from kag_common.database import audit as audit_mod


class _Base(DeclarativeBase):
    pass


class _PhiAccessLog(_Base, PhiAccessMixin):
    __tablename__ = "phi_access_log"


# --- hash_query -----------------------------------------------------------


def test_hash_query_none_and_empty() -> None:
    assert hash_query(None) is None
    assert hash_query("") is None


def test_hash_query_is_sha256_hex_and_not_plaintext() -> None:
    h = hash_query("patient has diabetes")
    assert h is not None
    assert len(h) == 64  # sha256 hex
    assert all(c in "0123456789abcdef" for c in h)
    assert h != "patient has diabetes"  # never the raw PHI text


def test_hash_query_is_deterministic() -> None:
    assert hash_query("same text") == hash_query("same text")
    assert hash_query("a") != hash_query("b")


# --- PhiAccessMixin column shape ------------------------------------------


def test_mixin_column_set() -> None:
    cols = set(_PhiAccessLog.__table__.columns.keys())
    assert cols == {
        "id",
        "tenant_id",
        "actor_id",
        "actor_name",
        "subject_id",
        "action",
        "resource_kind",
        "result",
        "result_tone",
        "result_count",
        "query_hash",
        "source_ip",
        "status_code",
        "audit_metadata",
        "created_at",
    }


def test_mixin_tenant_id_not_null_so_rls_covers_it() -> None:
    # NOT NULL tenant_id → the rls helper auto-applies the strict policy.
    assert _PhiAccessLog.__table__.columns["tenant_id"].nullable is False
    from kag_common.database import rls

    assert "phi_access_log" in rls.tenant_table_names(_Base.metadata)


def test_mixin_renders_tenant_id_as_postgres_uuid() -> None:
    """The mixin's tenant_id is a native ``uuid`` column (0.24.0), not varchar.

    This is what makes ``rls._predicate`` emit the ``::uuid`` cast for
    ``phi_access_log``, matching both consumers' migrations.
    """
    ddl = str(CreateTable(_PhiAccessLog.__table__).compile(dialect=postgresql.dialect()))
    tenant_line = next(line for line in ddl.splitlines() if "tenant_id" in line)
    assert "UUID" in tenant_line
    assert "VARCHAR" not in tenant_line
    assert "NOT NULL" in tenant_line


def test_mixin_tenant_id_stays_a_python_str() -> None:
    """``as_uuid=False``: consumers keep ``tenant_id: str`` and ``==`` on strings."""
    assert _PhiAccessLog.__table__.columns["tenant_id"].type.as_uuid is False
    # the surrogate PK is server-generated and never string-compared → as_uuid=True
    assert _PhiAccessLog.__table__.columns["id"].type.as_uuid is True


def test_rls_predicate_for_this_table_casts_to_uuid() -> None:
    from kag_common.database import rls

    assert rls._predicate(_Base.metadata, "phi_access_log").endswith("'')::uuid")


def test_mixin_has_audit_indexes() -> None:
    idx = {i.name for i in _PhiAccessLog.__table__.indexes}
    assert idx == {
        "ix_phi_access_log_tenant_created",
        "ix_phi_access_log_actor",
        "ix_phi_access_log_subject",
        "ix_phi_access_log_created",
    }


# --- record_phi_access (best-effort writer) -------------------------------


class _FakeSession:
    """Async-context-manager session capturing add()/commit() and GUC binds."""

    def __init__(self, *, raise_on: str | None = None) -> None:
        self.added: list[Any] = []
        self.committed = False
        self.execute_calls: list[tuple[str, dict]] = []
        self._raise_on = raise_on

    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def execute(self, stmt: object, params: dict | None = None) -> None:
        self.execute_calls.append((str(stmt), params or {}))

    def add(self, obj: Any) -> None:
        if self._raise_on == "add":
            raise RuntimeError("boom in add")
        self.added.append(obj)

    async def commit(self) -> None:
        if self._raise_on == "commit":
            raise RuntimeError("boom in commit")
        self.committed = True


def _factory(session: _FakeSession):  # noqa: ANN202
    def _make() -> _FakeSession:
        return session

    return _make


async def test_record_writes_row_with_fields() -> None:
    s = _FakeSession()
    await record_phi_access(
        _factory(s),  # type: ignore[arg-type]
        _PhiAccessLog,
        tenant_id="tenant-A",
        action="chunks.search.dense",
        actor_id="user-1",
        subject_id="subj-9",
        result_count=19,
        query_hash=hash_query("a query"),
    )
    assert s.committed is True
    assert len(s.added) == 1
    row = s.added[0]
    assert row.tenant_id == "tenant-A"
    assert row.action == "chunks.search.dense"
    assert row.actor_id == "user-1"
    assert row.subject_id == "subj-9"
    assert row.result_count == 19
    assert row.query_hash != "a query"  # hashed, never raw


async def test_record_binds_tenant_when_enforcing(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("TENANT_RLS_MODE", "enforce")
    s = _FakeSession()
    await record_phi_access(
        _factory(s),  # type: ignore[arg-type]
        _PhiAccessLog,
        tenant_id="tenant-A",
        action="chunks.by_ids",
    )
    # bind_session_tenant issued the set_config GUC for the audit INSERT.
    assert any("set_config('app.current_tenant'" in sql for sql, _ in s.execute_calls)


async def test_record_swallows_commit_error() -> None:
    from kag_common.metrics import phi_access_audit_failures_total

    phi_access_audit_failures_total.clear()
    s = _FakeSession(raise_on="commit")
    # Best-effort: a failing audit write must NOT propagate.
    await record_phi_access(
        _factory(s),  # type: ignore[arg-type]
        _PhiAccessLog,
        tenant_id="tenant-A",
        action="chunks.search.dense",
        service="kag_graph_service",
    )
    assert s.committed is False  # commit raised, but no exception escaped
    # ...but the swallowed failure is now visible to Prometheus (HIPAA gap).
    assert (
        phi_access_audit_failures_total.labels(
            service="kag_graph_service", action="chunks.search.dense"
        )._value.get()
        == 1.0
    )


async def test_record_swallows_factory_error() -> None:
    from kag_common.metrics import phi_access_audit_failures_total

    phi_access_audit_failures_total.clear()

    def _boom() -> _FakeSession:
        raise RuntimeError("cannot open session")

    # Even a failure opening the session is swallowed — and counted.
    await record_phi_access(
        _boom,  # type: ignore[arg-type]
        _PhiAccessLog,
        tenant_id="tenant-A",
        action="chunks.search.dense",
    )
    # No service passed → attributed to "unknown".
    assert (
        phi_access_audit_failures_total.labels(
            service="unknown", action="chunks.search.dense"
        )._value.get()
        == 1.0
    )


# --- on_error="raise" (opt-in fail-closed) --------------------------------


async def test_record_raises_auditwriteerror_on_commit_error_when_fail_closed() -> None:
    from kag_common.metrics import phi_access_audit_failures_total

    phi_access_audit_failures_total.clear()
    s = _FakeSession(raise_on="commit")
    # on_error="raise" → fail closed: the failure propagates as AuditWriteError...
    with pytest.raises(AuditWriteError):
        await record_phi_access(
            _factory(s),  # type: ignore[arg-type]
            _PhiAccessLog,
            tenant_id="tenant-A",
            action="chunks.search.dense",
            service="kag_graph_service",
            on_error="raise",
        )
    assert s.committed is False
    # ...and the counter STILL ticks (the HIPAA gap is visible either way).
    assert (
        phi_access_audit_failures_total.labels(
            service="kag_graph_service", action="chunks.search.dense"
        )._value.get()
        == 1.0
    )


async def test_auditwriteerror_chains_original_cause() -> None:
    s = _FakeSession(raise_on="commit")
    with pytest.raises(AuditWriteError) as excinfo:
        await record_phi_access(
            _factory(s),  # type: ignore[arg-type]
            _PhiAccessLog,
            tenant_id="tenant-A",
            action="chunks.by_ids",
            on_error="raise",
        )
    # Chained from the underlying RuntimeError for diagnosability.
    assert isinstance(excinfo.value.__cause__, RuntimeError)


async def test_record_raises_on_add_error_when_fail_closed() -> None:
    s = _FakeSession(raise_on="add")
    with pytest.raises(AuditWriteError):
        await record_phi_access(
            _factory(s),  # type: ignore[arg-type]
            _PhiAccessLog,
            tenant_id="tenant-A",
            action="chunks.by_ids",
            on_error="raise",
        )


async def test_default_on_error_swallows() -> None:
    from kag_common.metrics import phi_access_audit_failures_total

    phi_access_audit_failures_total.clear()
    s = _FakeSession(raise_on="commit")
    # Default on_error="swallow": no exception escapes (backward-compatible)...
    await record_phi_access(
        _factory(s),  # type: ignore[arg-type]
        _PhiAccessLog,
        tenant_id="tenant-A",
        action="chunks.search.dense",
        service="kag_graph_service",
    )
    assert s.committed is False
    # ...but the counter still ticks, exactly as before.
    assert (
        phi_access_audit_failures_total.labels(
            service="kag_graph_service", action="chunks.search.dense"
        )._value.get()
        == 1.0
    )


async def test_explicit_swallow_matches_default() -> None:
    s = _FakeSession(raise_on="commit")
    # Passing on_error="swallow" explicitly must also not raise.
    await record_phi_access(
        _factory(s),  # type: ignore[arg-type]
        _PhiAccessLog,
        tenant_id="tenant-A",
        action="chunks.search.dense",
        on_error="swallow",
    )
    assert s.committed is False


def test_audit_module_exports() -> None:
    assert hasattr(audit_mod, "PhiAccessMixin")
    assert hasattr(audit_mod, "record_phi_access")
    assert hasattr(audit_mod, "hash_query")
    assert hasattr(audit_mod, "AuditWriteError")
