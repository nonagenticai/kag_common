"""Tests for the shared ``kag_common.idempotency`` helper.

Helper-unit coverage against a real Postgres (the ``session_factory`` fixture
binds the mixin to a throwaway table). Mirrors the assertions the HiRAG D3
consumer shipped, now exercised against the generic model-agnostic functions.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from conftest import IdempotencyModel
from sqlalchemy import select
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable

from kag_common import idempotency
from kag_common.idempotency import Outcome

TTL = 3600.0
# tenant_id is a postgres uuid column (0.24.0), so the fixtures must use a real
# tenant UUID — the server rejects a free-form slug outright.
TENANT = "3f2b0c8e-6d41-4a7e-9c15-2b8a5d7e1c04"


def _begin(session_factory, key: str, fingerprint: str, tenant_id: str = TENANT):
    return idempotency.begin(
        session_factory,
        IdempotencyModel,
        key=key,
        tenant_id=tenant_id,
        fingerprint=fingerprint,
        ttl_seconds=TTL,
    )


class TestCanonicalFingerprint:
    def test_order_independent_and_distinct(self) -> None:
        a = idempotency.canonical_fingerprint({"x": 1, "y": 2})
        b = idempotency.canonical_fingerprint({"y": 2, "x": 1})
        c = idempotency.canonical_fingerprint({"x": 1, "y": 3})
        assert a == b
        assert a != c
        assert len(a) == 64  # sha256 hex


class TestIdempotencyHelper:
    async def test_first_call_proceeds(self, session_factory) -> None:
        decision = await _begin(session_factory, "k1", "fp-1")
        assert decision.outcome is Outcome.PROCEED

    async def test_replay_after_complete(self, session_factory) -> None:
        await _begin(session_factory, "k2", "fp-2")
        await idempotency.complete(
            session_factory, IdempotencyModel, key="k2", response={"ok": True, "n": 5}
        )
        decision = await _begin(session_factory, "k2", "fp-2")
        assert decision.outcome is Outcome.REPLAY
        assert decision.response == {"ok": True, "n": 5}

    async def test_fingerprint_mismatch(self, session_factory) -> None:
        await _begin(session_factory, "k3", "fp-A")
        decision = await _begin(session_factory, "k3", "fp-B")
        assert decision.outcome is Outcome.MISMATCH

    async def test_in_progress_duplicate(self, session_factory) -> None:
        first = await _begin(session_factory, "k4", "fp-4")
        second = await _begin(session_factory, "k4", "fp-4")
        assert first.outcome is Outcome.PROCEED
        assert second.outcome is Outcome.IN_PROGRESS

    async def test_expired_row_is_reclaimed(self, session_factory) -> None:
        # Seed a stale row with an old fingerprint.
        async with session_factory() as session:
            session.add(
                IdempotencyModel(
                    idempotency_key="k5",
                    tenant_id=TENANT,
                    request_fingerprint="fp-old",
                    status="done",
                    response={"stale": True},
                    expires_at=datetime.now(UTC) - timedelta(hours=1),
                )
            )
            await session.commit()

        # A new claim with a *different* fingerprint must reclaim (not MISMATCH).
        decision = await _begin(session_factory, "k5", "fp-new")
        assert decision.outcome is Outcome.PROCEED

        async with session_factory() as session:
            row = (
                await session.execute(
                    select(IdempotencyModel).where(IdempotencyModel.idempotency_key == "k5")
                )
            ).scalar_one()
            assert row.request_fingerprint == "fp-new"
            assert row.status == "in_progress"

    async def test_abort_releases_claim(self, session_factory) -> None:
        assert (await _begin(session_factory, "k6", "fp-6")).outcome is Outcome.PROCEED
        await idempotency.abort(session_factory, IdempotencyModel, key="k6")
        # Row gone → a fresh claim proceeds again.
        assert (await _begin(session_factory, "k6", "fp-6")).outcome is Outcome.PROCEED

    async def test_abort_keeps_done_row(self, session_factory) -> None:
        await _begin(session_factory, "k7", "fp-7")
        await idempotency.complete(
            session_factory, IdempotencyModel, key="k7", response={"done": 1}
        )
        await idempotency.abort(session_factory, IdempotencyModel, key="k7")  # must be a no-op
        async with session_factory() as session:
            row = (
                await session.execute(
                    select(IdempotencyModel).where(IdempotencyModel.idempotency_key == "k7")
                )
            ).scalar_one()
            assert row.status == "done"
            assert row.response == {"done": 1}


class TestCompleteOnSessionHook:
    """The ``on_session`` callback runs in the completion transaction (Lane C2)."""

    async def test_hook_runs_in_completion_session(self, session_factory) -> None:
        await _begin(session_factory, "k8", "fp-8")

        seen: dict[str, object] = {}

        async def hook(session) -> None:
            # The hook receives the *same* session the done-flip ran on, and the
            # flip is already visible inside the still-open transaction.
            seen["session"] = session
            row = (
                await session.execute(
                    select(IdempotencyModel).where(IdempotencyModel.idempotency_key == "k8")
                )
            ).scalar_one()
            seen["status_mid_tx"] = row.status

        await idempotency.complete(
            session_factory, IdempotencyModel, key="k8", response={"done": 1}, on_session=hook
        )

        assert seen["status_mid_tx"] == "done"
        # The completion committed normally.
        async with session_factory() as session:
            row = (
                await session.execute(
                    select(IdempotencyModel).where(IdempotencyModel.idempotency_key == "k8")
                )
            ).scalar_one()
            assert row.status == "done"

    async def test_hook_raise_rolls_back_done_flip(self, session_factory) -> None:
        await _begin(session_factory, "k9", "fp-9")

        async def boom(session) -> None:
            raise RuntimeError("outbox enqueue failed")

        with pytest.raises(RuntimeError, match="outbox enqueue failed"):
            await idempotency.complete(
                session_factory, IdempotencyModel, key="k9", response={"done": 1}, on_session=boom
            )

        # The done flip rolled back with the hook — the key is still in_progress,
        # so a later identical delivery re-claims and retries.
        async with session_factory() as session:
            row = (
                await session.execute(
                    select(IdempotencyModel).where(IdempotencyModel.idempotency_key == "k9")
                )
            ).scalar_one()
            assert row.status == "in_progress"
            assert row.response is None


# --- rendered DDL ---------------------------------------------------------


def test_mixin_renders_tenant_id_as_postgres_uuid() -> None:
    """The mixin's tenant_id is a native ``uuid`` column (0.24.0), not varchar.

    This is what makes ``rls._predicate`` emit the ``::uuid`` cast, and it is the
    shape both consumers' migrations create.
    """
    ddl = str(CreateTable(IdempotencyModel.__table__).compile(dialect=postgresql.dialect()))
    tenant_line = next(line for line in ddl.splitlines() if "tenant_id" in line)
    assert "UUID" in tenant_line
    assert "VARCHAR" not in tenant_line
    assert "NOT NULL" in tenant_line


def test_mixin_tenant_id_is_indexed_and_not_null() -> None:
    col = IdempotencyModel.__table__.columns["tenant_id"]
    assert col.nullable is False
    assert col.index is True


def test_mixin_tenant_id_stays_a_python_str() -> None:
    """``as_uuid=False``: consumers keep ``tenant_id: str`` and ``==`` on strings."""
    assert IdempotencyModel.__table__.columns["tenant_id"].type.as_uuid is False
