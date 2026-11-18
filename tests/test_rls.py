"""Tests for the shared RLS helpers (kag_common.database.rls)."""

from __future__ import annotations

import pytest
from sqlalchemy import Column, Integer, MetaData, String, Table
from sqlalchemy.dialects.postgresql import UUID

from kag_common.database import rls

_GUC = "NULLIF(current_setting('app.current_tenant', true), '')"


def _metadata() -> MetaData:
    md = MetaData()
    # strict: NOT NULL varchar tenant_id (text-to-text predicate)
    Table(
        "chunks",
        md,
        Column("id", Integer, primary_key=True),
        Column("tenant_id", String(128), nullable=False),
    )
    # global-or-own: NULLABLE uuid tenant_id (cast predicate)
    Table(
        "jobs",
        md,
        Column("id", Integer, primary_key=True),
        Column("tenant_id", UUID(as_uuid=True), nullable=True),
    )
    # strict: NOT NULL uuid tenant_id, as_uuid=False — the shape the shared
    # kag_common mixins ship since 0.24.0 (Python side stays ``str``).
    Table(
        "phi_access_log",
        md,
        Column("id", Integer, primary_key=True),
        Column("tenant_id", UUID(as_uuid=False), nullable=False),
    )
    # operational: carries tenant_id but excluded from RLS
    Table(
        "outbox",
        md,
        Column("id", Integer, primary_key=True),
        Column("tenant_id", String(128), nullable=False),
    )
    # no tenant_id at all → never in scope
    Table("config", md, Column("id", Integer, primary_key=True))
    return md


def test_tenant_table_names_respects_exclude() -> None:
    md = _metadata()
    assert rls.tenant_table_names(md) == ["chunks", "jobs", "outbox", "phi_access_log"]
    assert rls.tenant_table_names(md, exclude={"outbox"}) == [
        "chunks",
        "jobs",
        "phi_access_log",
    ]


def test_upgrade_strict_for_not_null_text() -> None:
    stmts = rls.upgrade_statements(_metadata(), exclude={"outbox", "jobs", "phi_access_log"})
    pred = f"tenant_id = {_GUC}"
    assert stmts == [
        "ALTER TABLE chunks ENABLE ROW LEVEL SECURITY",
        "DROP POLICY IF EXISTS tenant_isolation ON chunks",
        f"CREATE POLICY tenant_isolation ON chunks USING ({pred}) WITH CHECK ({pred})",
    ]
    assert "::uuid" not in " ".join(stmts)  # text column → no cast


def test_upgrade_global_for_nullable_uuid() -> None:
    stmts = rls.upgrade_statements(_metadata(), exclude={"outbox", "chunks", "phi_access_log"})
    joined = " ".join(stmts)
    pred = f"tenant_id = {_GUC}::uuid"  # uuid column → cast
    assert "ENABLE ROW LEVEL SECURITY" in joined
    assert f"FOR SELECT USING (tenant_id IS NULL OR {pred})" in joined
    assert f"FOR INSERT WITH CHECK ({pred})" in joined
    assert f"FOR DELETE USING ({pred})" in joined


def test_excluded_table_never_appears() -> None:
    stmts = rls.upgrade_statements(_metadata(), exclude={"outbox"})
    assert "outbox" not in " ".join(stmts)


def test_downgrade_reverses_and_is_idempotent() -> None:
    stmts = rls.downgrade_statements(_metadata(), exclude={"outbox"})
    assert all(
        s.startswith("DROP POLICY IF EXISTS") or "DISABLE ROW LEVEL SECURITY" in s for s in stmts
    )
    assert any("DISABLE ROW LEVEL SECURITY" in s for s in stmts)


def test_register_rls_ddl_registers_after_create() -> None:
    md = _metadata()
    before = len(md.dispatch.after_create)
    rls.register_rls_ddl(md, exclude={"outbox"})
    # exactly one after_create listener was attached to render the RLS DDL
    assert len(md.dispatch.after_create) == before + 1


def test_mode_default_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TENANT_RLS_MODE", raising=False)
    assert rls.tenant_rls_mode() == "off"


def test_mode_reads_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TENANT_RLS_MODE", " ENFORCE ")
    assert rls.tenant_rls_mode() == "enforce"


# --- bind_session_tenant ---------------------------------------------------


class _FakeSession:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    async def execute(self, stmt: object, params: dict | None = None) -> None:
        self.calls.append((str(stmt), params or {}))


async def test_bind_noop_when_off() -> None:
    s = _FakeSession()
    await rls.bind_session_tenant(s, "tenant-A", mode="off")  # type: ignore[arg-type]
    assert s.calls == []


async def test_bind_noop_when_no_tenant() -> None:
    s = _FakeSession()
    await rls.bind_session_tenant(s, None, mode="enforce")  # type: ignore[arg-type]
    assert s.calls == []  # fail-closed: GUC left unset


async def test_bind_sets_guc_when_enforce() -> None:
    s = _FakeSession()
    await rls.bind_session_tenant(s, "tenant-A", mode="enforce")  # type: ignore[arg-type]
    assert len(s.calls) == 1
    sql, params = s.calls[0]
    assert "set_config('app.current_tenant', :tenant, true)" in sql
    assert params == {"tenant": "tenant-A"}


def test_register_tenant_guc_attaches_begin_listener() -> None:
    from sqlalchemy.ext.asyncio import create_async_engine

    # create_async_engine does not connect until first use → safe in a unit test.
    engine = create_async_engine("postgresql+psycopg://x:x@localhost/x")
    before = len(engine.sync_engine.dispatch.begin)
    rls.register_tenant_guc(engine, lambda: "tenant-A")
    assert len(engine.sync_engine.dispatch.begin) == before + 1


def test_register_tenant_guc_sync_attaches_begin_listener() -> None:
    from sqlalchemy import create_engine

    # create_engine does not connect until first use → safe in a unit test.
    engine = create_engine("postgresql+psycopg://x:x@localhost/x")
    before = len(engine.dispatch.begin)
    rls.register_tenant_guc_sync(engine, lambda: "tenant-A")
    assert len(engine.dispatch.begin) == before + 1


# --- _predicate: BOTH type branches ---------------------------------------
#
# The cast is chosen from the tenant column's TYPE, so both halves must be
# pinned. Only 2 of the 9 KAG consumers use the shared mixins (uuid since
# 0.24.0); the other 7 keep a varchar tenant_id and their policies must NOT
# gain a ``::uuid`` cast — that would raise "operator does not exist:
# character varying = uuid" at policy-creation time.


def _one_table(col_type, *, nullable: bool = False) -> MetaData:
    md = MetaData()
    Table(
        "t",
        md,
        Column("id", Integer, primary_key=True),
        Column("tenant_id", col_type, nullable=nullable),
    )
    return md


def test_predicate_casts_for_uuid_as_uuid_false_column() -> None:
    # The shared-mixin shape: postgres uuid, Python-side str.
    md = _one_table(UUID(as_uuid=False))
    assert rls._predicate(md, "t") == f"tenant_id = {_GUC}::uuid"
    assert "'')::uuid" in rls._predicate(md, "t")


def test_predicate_does_not_cast_for_string_column() -> None:
    # The 7 non-mixin consumers: varchar tenant_id, text-to-text comparison.
    md = _one_table(String(128))
    assert rls._predicate(md, "t") == f"tenant_id = {_GUC}"
    assert "::uuid" not in rls._predicate(md, "t")


def test_upgrade_statements_cast_for_uuid_as_uuid_false_column() -> None:
    stmts = rls.upgrade_statements(_one_table(UUID(as_uuid=False)))
    joined = " ".join(stmts)
    pred = f"tenant_id = {_GUC}::uuid"
    assert "'')::uuid" in joined
    assert f"CREATE POLICY tenant_isolation ON t USING ({pred}) WITH CHECK ({pred})" in joined


def test_upgrade_statements_leave_string_column_uncast() -> None:
    stmts = rls.upgrade_statements(_one_table(String(128)))
    joined = " ".join(stmts)
    pred = f"tenant_id = {_GUC}"
    assert "::uuid" not in joined  # a varchar consumer's policy is unchanged
    assert f"CREATE POLICY tenant_isolation ON t USING ({pred}) WITH CHECK ({pred})" in joined
