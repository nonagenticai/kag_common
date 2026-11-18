"""Shared fixtures for kag_common tests.

Only the idempotency helper needs a database; the rest of the suite is pure-unit.
The idempotency fixtures bind :class:`kag_common.idempotency.IdempotencyMixin` to
a throwaway declarative ``Base`` (a stand-in for a real consumer's ``Base``) and
create/drop its table per test for isolation.

Requires PostgreSQL. Set ``TEST_DATABASE_URL`` to override the default; CI sets
``DATABASE_URL`` via the python-library archetype's "Start ephemeral CI
database" step (``has_postgres: true``).

An unreachable database is therefore a local-dev condition only: in CI it is an
infrastructure failure and is raised as one. See
:func:`_fail_or_skip_without_database`.
"""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator

import pytest
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool

from kag_common.idempotency import IdempotencyMixin

TEST_DATABASE_URL = (
    os.getenv("DATABASE_URL")
    or os.getenv(
        "TEST_DATABASE_URL",
        "postgresql+psycopg://postgres:postgres@localhost:5456/kag_common_test",  # pragma: allowlist secret
    )
)


def _running_in_ci() -> bool:
    """True when executing inside GitHub Actions (or any CI setting ``CI=true``).

    GitHub Actions sets both ``CI`` and ``GITHUB_ACTIONS`` in every job's
    environment automatically, so the fleet's archetypes need no extra wiring
    for this to work. Same helper shape as ``hirag_service`` and
    ``w2v_orchestrator`` — do not invent a new env var.
    """
    return os.environ.get("CI") == "true" or os.environ.get("GITHUB_ACTIONS") == "true"


def _fail_or_skip_without_database(exc: BaseException) -> None:
    """An unreachable test database is a FAILURE in CI, a skip for a local dev.

    This guard used to be an unconditional ``pytest.skip``. ``session_factory``
    is the sole gate for every database-backed test in this library, so one
    unreachable Postgres made the whole idempotency lane vanish while pytest
    still exited 0 — a CI infrastructure failure was byte-for-byte
    indistinguishable from a passing run.

    That is worse here than in a leaf service: ``kag_common`` is the shared
    library. :class:`~kag_common.idempotency.IdempotencyMixin` and
    :class:`~kag_common.audit.PhiAccessMixin` declare the ``tenant_id`` columns
    that ``hirag_service`` and ``kag_graph_service`` inherit, and
    ``kag_common.database.rls`` generates the RLS predicates for the whole
    lane. A broken shared mixin that skips green here ships green to every
    consumer.

    In CI the ephemeral ``postgres:18`` sidecar is a hard prerequisite: if it is
    not reachable the run has proven nothing and must say so. Locally the
    friendly skip is kept so a developer without a test database still gets a
    usable (if reduced) run.
    """
    if _running_in_ci():
        pytest.fail(
            f"Test database unreachable at {TEST_DATABASE_URL}: {exc}\n"
            "\n"
            "Every database-backed test in this library is gated on the\n"
            "`session_factory` fixture, so an unreachable database would\n"
            "silently skip the whole idempotency lane and still exit 0. A run\n"
            "that could not execute must never look like one that passed —\n"
            "failing loudly instead.\n"
            "\n"
            "In CI the ephemeral postgres:18 sidecar (python-library archetype,\n"
            "`has_postgres: true`) exports DATABASE_URL; check the 'Start\n"
            "ephemeral CI database' step.\n",
            pytrace=False,
        )
    pytest.skip(f"PostgreSQL not available at {TEST_DATABASE_URL}: {exc}")


class _Base(DeclarativeBase):
    """Throwaway declarative base — stands in for a consumer service's ``Base``."""


class IdempotencyModel(_Base, IdempotencyMixin):
    """A consumer-shaped idempotency table for exercising the shared helper."""

    __tablename__ = "ingest_idempotency"


@pytest.fixture
async def session_factory() -> AsyncGenerator[async_sessionmaker[AsyncSession]]:
    """Async ``sessionmaker`` over a freshly-created idempotency table.

    If Postgres is unreachable this FAILS under CI and skips only on a local dev
    box — see :func:`_fail_or_skip_without_database`. The skip is a developer
    convenience, never a CI outcome.
    """
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(_Base.metadata.drop_all)
            await conn.run_sync(_Base.metadata.create_all)
    except Exception as exc:  # pragma: no cover - infra-dependent
        await engine.dispose()
        _fail_or_skip_without_database(exc)

    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        yield factory
    finally:
        async with engine.begin() as conn:
            await conn.run_sync(_Base.metadata.drop_all)
        await engine.dispose()
