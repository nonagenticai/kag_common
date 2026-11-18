"""Shared Postgres-backed server-side idempotency helper for KAG services (Lane D3).

The orchestrator threads a stable ``Idempotency-Key`` header through every ingest
POST (``{job.id}_{stage}_{attempt}[_{sub_op}]`` — kag_orchestrator adapters).
Because the queue delivers at-least-once, the *same* attempt can arrive twice;
without dedup the service re-runs the (expensive) write and re-publishes its
completion event. This module is the durable guard: one row per key in a
per-service ``ingest_idempotency`` table replays the original response instead.

Note on semantics: the key includes the attempt number, so this dedups
**duplicate delivery of one attempt**, not a logical retry (a fresh attempt is a
new key by design — the orchestrator wants retries to re-run).

Design — model-agnostic, shared across services:
    * :class:`IdempotencyMixin` defines the column shape. Each service binds it
      to *its own* declarative ``Base`` so the table lives on the service's
      metadata (so the service owns its table, migration, and DB/user — the
      per-service blast-radius invariant holds; this library still ships no
      migrations and creates no tables)::

          from kag_common.idempotency import IdempotencyMixin

          class IngestIdempotencyORM(Base, IdempotencyMixin):
              __tablename__ = "ingest_idempotency"

    * :func:`begin` / :func:`complete` / :func:`abort` take the service's
      ``async_sessionmaker`` and its ORM model, so the algorithm lives once here.
      Each call opens its own short-lived async session: idempotency bookkeeping
      therefore commits in a separate transaction from the business write — it is
      a best-effort marker, not a 2PC. The one failure mode (``complete`` never
      lands after a successful write) degrades to a 409 on the next identical
      delivery, which is acceptable.

This is the only DB-touching module in ``kag_common``; it adds a ``sqlalchemy``
runtime dependency but no ``psycopg`` import (the driver lives in each service's
engine).
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, String, delete, func, select, update
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import declared_attr, mapped_column

logger = logging.getLogger(__name__)


class Outcome(StrEnum):
    """What the caller should do for a given ``Idempotency-Key``."""

    PROCEED = "proceed"  # we own this key — run the request, then call complete()
    REPLAY = "replay"  # key already done — return the cached response, do NOT reprocess
    MISMATCH = "mismatch"  # key reused with a different body — 422
    IN_PROGRESS = "in_progress"  # concurrent duplicate still running — 409


@dataclass(frozen=True)
class Decision:
    """Result of :func:`begin`. ``response`` is set only for ``REPLAY``."""

    outcome: Outcome
    response: dict[str, Any] | None = None


def canonical_fingerprint(body: dict[str, Any]) -> str:
    """sha256 hex of the canonical (sorted, compact) request body.

    Guards against an ``Idempotency-Key`` being reused with a different payload:
    same key + different fingerprint → 422 rather than a misleading replay.
    """
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class IdempotencyMixin:
    """Declarative mixin defining the shared ``ingest_idempotency`` column shape.

    Bind it to a service's own declarative ``Base``::

        class IngestIdempotencyORM(Base, IdempotencyMixin):
            __tablename__ = "ingest_idempotency"

    Lifecycle: a request inserts the row ``in_progress`` (INSERT ... ON CONFLICT
    DO NOTHING wins → process), then flips it to ``done`` with the serialized
    response. A concurrent duplicate sees ``in_progress`` (409); a later duplicate
    sees ``done`` and replays ``response``. ``request_fingerprint`` guards key
    reuse with a different body (422). ``expires_at`` enables lazy pruning: an
    expired row is treated as absent and reused.

    The column types, index flags, and the named ``CheckConstraint`` are fixed so
    every consumer's table (and migration) is byte-identical.

    ``tenant_id`` is a Postgres ``uuid`` column (0.24.0; it was ``varchar(128)``
    through 0.23.x). Every live tenant identifier in the fleet is a UUID, and the
    native type is what makes the RLS predicate cast correctly —
    :func:`kag_common.database.rls._predicate` branches on ``isinstance(col.type,
    String)``, so a ``uuid`` column gets ``…::uuid`` while a ``varchar`` column
    would be compared text-to-text.

    ``as_uuid=False`` is deliberate: SQLAlchemy hands Python-side values back as
    ``str``, not :class:`uuid.UUID`. Consumers' ``tenant_id: str`` annotations,
    ``==`` comparisons against request-scoped tenant strings, and JSON
    serialisation therefore keep working unchanged — only the *storage* type
    moved.
    """

    idempotency_key = mapped_column(String(255), primary_key=True)
    tenant_id = mapped_column(PG_UUID(as_uuid=False), nullable=False, index=True)
    # sha256 hex digest of the canonical request body (64 chars).
    request_fingerprint = mapped_column(String(64), nullable=False)
    # The cached response (model_dump(mode="json")); NULL while
    # status='in_progress', populated when status flips to 'done'.
    response = mapped_column(JSONB, nullable=True)
    status = mapped_column(String(16), nullable=False)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    @declared_attr.directive
    def __table_args__(cls) -> tuple[Any, ...]:  # noqa: N805 (declared_attr takes cls)
        # A fresh constraint object per subclass (HiRAG, kag_graph, and the test
        # model all mix this in) — a shared instance would raise "already
        # attached to a Table".
        return (
            CheckConstraint(
                "status IN ('in_progress', 'done')", name="ck_ingest_idempotency_status"
            ),
        )


async def begin(
    session_factory: async_sessionmaker[AsyncSession],
    model: type[Any],
    *,
    key: str,
    tenant_id: str,
    fingerprint: str,
    ttl_seconds: float,
) -> Decision:
    """Claim ``key`` for processing, or report what to do with a duplicate.

    Inserts an ``in_progress`` row ``ON CONFLICT DO NOTHING``. Insert won →
    ``PROCEED``. On conflict, the existing row decides: an expired row is dropped
    and re-claimed (``PROCEED``); a fingerprint mismatch → ``MISMATCH``; a
    ``done`` row → ``REPLAY`` with its cached response; an ``in_progress`` row →
    ``IN_PROGRESS``.

    ``model`` is the service's ORM class mixing in :class:`IdempotencyMixin`;
    ``session_factory`` is the service's ``async_sessionmaker``.
    """
    async with session_factory() as session:
        # At most two passes: the second only runs if we dropped a stale row (or
        # it vanished under us) and need to re-attempt the claim.
        for _ in range(2):
            expires_at = datetime.now(UTC) + timedelta(seconds=ttl_seconds)
            ins = (
                pg_insert(model)
                .values(
                    idempotency_key=key,
                    tenant_id=tenant_id,
                    request_fingerprint=fingerprint,
                    status=Outcome.IN_PROGRESS.value,
                    expires_at=expires_at,
                )
                .on_conflict_do_nothing(index_elements=["idempotency_key"])
                # RETURNING is the reliable signal of whether the INSERT actually
                # happened: a row comes back only when we won the claim; a conflict
                # returns nothing. (rowcount is unreliable for ON CONFLICT here.)
                .returning(model.idempotency_key)
            )
            inserted = (await session.execute(ins)).scalar_one_or_none()
            await session.commit()
            if inserted is not None:
                return Decision(Outcome.PROCEED)

            # Conflict: inspect the incumbent row.
            row = (
                await session.execute(select(model).where(model.idempotency_key == key))
            ).scalar_one_or_none()
            if row is None:
                # Deleted between our failed insert and this read — retry the claim.
                continue
            if row.expires_at <= datetime.now(UTC):
                # Stale row: drop it (only if still stale) and retry the claim.
                await session.execute(
                    delete(model).where(
                        model.idempotency_key == key, model.expires_at <= func.now()
                    )
                )
                await session.commit()
                continue
            if row.request_fingerprint != fingerprint:
                logger.warning(
                    "idempotency key reused with a different body: key=%s tenant=%s",
                    key,
                    tenant_id,
                )
                return Decision(Outcome.MISMATCH)
            if row.status == "done":
                return Decision(Outcome.REPLAY, response=row.response)
            return Decision(Outcome.IN_PROGRESS)

        # Two passes exhausted under contention — treat as a concurrent duplicate.
        return Decision(Outcome.IN_PROGRESS)


async def complete(
    session_factory: async_sessionmaker[AsyncSession],
    model: type[Any],
    *,
    key: str,
    response: dict[str, Any],
    on_session: Callable[[AsyncSession], Awaitable[None]] | None = None,
) -> None:
    """Mark ``key`` done and store the response to replay on future duplicates.

    ``on_session``, when given, is awaited inside this function's session
    **after** the ``done`` flip and **before** the commit, so any work it does
    (e.g. enqueuing a transactional-outbox row) commits *atomically* with the
    idempotency completion. A raise inside it rolls back the ``done`` flip too —
    the key stays ``in_progress`` and a later identical delivery re-claims it.
    This keeps the library decoupled from the caller's tables: the callback owns
    what it writes on the supplied session. ``None`` (the default) preserves the
    original behaviour for every other caller.
    """
    async with session_factory() as session:
        await session.execute(
            update(model)
            .where(model.idempotency_key == key)
            .values(status="done", response=response)
        )
        if on_session is not None:
            await on_session(session)
        await session.commit()


async def abort(
    session_factory: async_sessionmaker[AsyncSession],
    model: type[Any],
    *,
    key: str,
) -> None:
    """Release an ``in_progress`` claim after a failed request.

    Deletes the row only while it is still ``in_progress`` so a genuine retry
    isn't blocked by a stale claim, and a row that already flipped to ``done``
    is never clobbered.
    """
    async with session_factory() as session:
        await session.execute(
            delete(model).where(model.idempotency_key == key, model.status == "in_progress")
        )
        await session.commit()
