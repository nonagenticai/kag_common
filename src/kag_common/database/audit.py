"""Shared HIPAA PHI access-audit helper for the KAG fleet (HIPAA G5).

HIPAA §164.312(b) ("Audit controls") requires a per-(tenant, actor, subject,
resource, time) record of **who read PHI, when**. This module is the shared
substrate for that trail across KAG services: a column-mixin defining the audit
row shape and a best-effort writer. Like every other module here it **ships no
table** — each consuming service binds :class:`PhiAccessMixin` to *its own*
declarative ``Base`` so the table lives on that service's metadata (the
per-service blast-radius / "one service = one DB + migration set" invariant
holds; this library still creates no tables and opens no connection)::

    from kag_common.database import PhiAccessMixin

    class PhiAccessLog(Base, PhiAccessMixin):
        __tablename__ = "phi_access_log"

Design invariants:
  * **The audit log never stores PHI.** Query text is hashed (:func:`hash_query`),
    only *counts* of returned rows are recorded, and ``audit_metadata`` carries
    identifiers / scope flags only — never document content. This is enforced by
    convention at the call sites and reinforced in review.
  * **Best-effort, never blocking.** :func:`record_phi_access` mirrors the
    commonpractice ``recordAudit`` posture: it opens its **own** short-lived
    session (a separate transaction from the PHI read it records) and swallows
    every error. A dropped audit row must never roll back or break the clinical
    read path. (A stronger non-loss guarantee — a transactional outbox — is a
    deferred follow-on, G5.2.)
  * **RLS-consistent.** ``tenant_id`` is NOT NULL, so each service's
    ``phi_access_log`` is auto-covered by :func:`kag_common.database.rls`
    (strict policy: a tenant's audit is isolated from every other tenant). The
    writer binds ``app.current_tenant`` via :func:`bind_session_tenant` so the
    INSERT satisfies the strict ``WITH CHECK`` once a service runs on its
    restricted role + ``TENANT_RLS_MODE=enforce``; it is a no-op while the mode
    is ``off`` (today), so this ships safe.

Like :mod:`kag_common.idempotency`, this adds only a SQLAlchemy Core/ORM
dependency; the ``psycopg`` driver lives in each consumer's engine.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Literal

from sqlalchemy import DateTime, Index, Integer, String, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import declared_attr, mapped_column

from kag_common.database.rls import bind_session_tenant
from kag_common.metrics import record_phi_audit_failure

logger = logging.getLogger(__name__)


class AuditWriteError(Exception):
    """A PHI-access audit write failed and the caller opted to fail closed.

    Only raised by :func:`record_phi_access` when called with
    ``on_error="raise"`` (the default ``"swallow"`` preserves the historic
    best-effort posture). It lets a consumer that wants the HIPAA §164.312(b)
    non-loss guarantee for PHI **reads** fail closed — serve HTTP 503 rather
    than return PHI without a durable audit row — by mapping this exception to a
    503 at its edge. The ``kag_phi_access_audit_failures_total`` counter is
    still incremented before this is raised, so alerting sees the gap either way.
    """


def hash_query(query_text: str | None) -> str | None:
    """sha256 hex of a query string, or ``None`` for empty/absent input.

    Lets the audit trail record *that* a query ran (and dedupe identical queries)
    **without storing the raw text**, which may itself be PHI. Deterministic, so
    the same query produces the same hash across requests.
    """
    if not query_text:
        return None
    return hashlib.sha256(query_text.encode("utf-8")).hexdigest()


class PhiAccessMixin:
    """Declarative mixin defining the shared ``phi_access_log`` column shape.

    Bind it to a service's own declarative ``Base``::

        class PhiAccessLog(Base, PhiAccessMixin):
            __tablename__ = "phi_access_log"

    Every column type and the index set are fixed so each consumer's table (and
    migration) is byte-identical. ``tenant_id`` is NOT NULL so the table is
    auto-covered by the RLS helpers (strict per-tenant isolation of the audit
    trail itself).

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
    moved. (The ``id`` primary key keeps ``as_uuid=True``: it is generated
    server-side and never compared to a request string.)
    """

    # gen_random_uuid() is a Postgres core function (pg13+), so no pgcrypto needed.
    id = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    tenant_id = mapped_column(PG_UUID(as_uuid=False), nullable=False)
    # Who acted: the license/Keycloak subject (user.sub). NULL = system/automated.
    actor_id = mapped_column(String(256), nullable=True)
    actor_name = mapped_column(String(256), nullable=True)
    # The end-user whose PHI was touched: the forwarded X-Subject-Id.
    subject_id = mapped_column(String(256), nullable=True)
    # What happened, e.g. 'chunks.search.dense', 'chunks.by_ids', 'search.semantic'.
    action = mapped_column(String(64), nullable=False)
    resource_kind = mapped_column(String(32), nullable=False, server_default="chunk")
    # 'ok' | 'denied' (and the display tone driving a UI status dot).
    result = mapped_column(String(32), nullable=True)
    result_tone = mapped_column(String(16), nullable=True)
    # Count of rows/chunks returned — a COUNT only, never the content.
    result_count = mapped_column(Integer, nullable=True)
    # sha256 hex of the query text (64 chars). NEVER the raw text (PHI).
    query_hash = mapped_column(String(64), nullable=True)
    source_ip = mapped_column(String(45), nullable=True)
    status_code = mapped_column(Integer, nullable=True)
    # Free-form context (visibility scope used, doc_id, …) — identifiers only, no PHI.
    audit_metadata = mapped_column(JSONB, nullable=True)
    created_at = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    @declared_attr.directive
    def __table_args__(cls) -> tuple[Any, ...]:  # noqa: N805 (declared_attr takes cls)
        # Fresh Index objects per subclass — a shared instance would raise
        # "already attached to a Table" if more than one service mixes this in.
        tn = cls.__tablename__  # ty: ignore[unresolved-attribute]
        return (
            Index(f"ix_{tn}_tenant_created", "tenant_id", "created_at"),
            Index(f"ix_{tn}_actor", "actor_id"),
            Index(f"ix_{tn}_subject", "subject_id"),
            Index(f"ix_{tn}_created", "created_at"),
        )


async def record_phi_access(
    session_factory: async_sessionmaker[AsyncSession],
    model: type[Any],
    *,
    tenant_id: str,
    action: str,
    actor_id: str | None = None,
    actor_name: str | None = None,
    subject_id: str | None = None,
    resource_kind: str = "chunk",
    result: str | None = "ok",
    result_tone: str | None = "ok",
    result_count: int | None = None,
    query_hash: str | None = None,
    source_ip: str | None = None,
    status_code: int | None = None,
    audit_metadata: dict[str, Any] | None = None,
    service: str | None = None,
    on_error: Literal["swallow", "raise"] = "swallow",
) -> None:
    """Write one PHI-access audit row in its own transaction.

    Opens a fresh session (separate from the PHI read it records), binds
    ``app.current_tenant`` so the INSERT satisfies the strict RLS ``WITH CHECK``
    once a service runs on its restricted role + ``enforce`` (a no-op while the
    mode is ``off``), inserts the row, and commits.

    ``model`` is the service's ORM class mixing in :class:`PhiAccessMixin`;
    ``session_factory`` is the service's ``async_sessionmaker``. ``tenant_id`` is
    the request-scoped tenant (auth middleware), never a client-asserted value.
    Pass ``query_hash=hash_query(<text>)`` — never raw query text.

    ``on_error`` chooses the failure posture (a failed write ALWAYS increments
    the ``kag_phi_access_audit_failures_total{service,action}`` counter and logs
    at WARNING, so the HIPAA §164.312(b) gap is visible to Prometheus either
    way; pass ``service`` to attribute the metric — it defaults to ``"unknown"``):

    * ``"swallow"`` (default) — best-effort, backward-compatible: the error is
      swallowed so an audit hiccup never breaks PHI serving.
    * ``"raise"`` — fail closed: re-raise as :class:`AuditWriteError` (chained
      from the original) so the caller can serve HTTP 503 rather than return PHI
      without a durable audit row. Opt-in; the default preserves today's
      behaviour with no consumer change.
    """
    try:
        async with session_factory() as session:
            await bind_session_tenant(session, tenant_id)
            session.add(
                model(
                    tenant_id=tenant_id,
                    action=action,
                    actor_id=actor_id,
                    actor_name=actor_name,
                    subject_id=subject_id,
                    resource_kind=resource_kind,
                    result=result,
                    result_tone=result_tone,
                    result_count=result_count,
                    query_hash=query_hash,
                    source_ip=source_ip,
                    status_code=status_code,
                    audit_metadata=audit_metadata,
                )
            )
            await session.commit()
    except Exception as exc:  # noqa: BLE001 — best-effort default; opt-in fail-closed
        logger.warning("phi_access audit write failed (action=%s)", action, exc_info=True)
        record_phi_audit_failure(service or "unknown", action)
        if on_error == "raise":
            raise AuditWriteError(f"phi_access audit write failed (action={action})") from exc
