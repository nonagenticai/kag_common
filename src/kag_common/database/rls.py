"""Generic Postgres Row-Level-Security (RLS) helpers for the KAG fleet (HIPAA G4).

The provable tenant-isolation backstop beneath each service's application-layer
``WHERE tenant_id = …`` predicates: even if a predicate were dropped, Postgres
returns zero foreign-tenant rows and rejects foreign-tenant writes. Mirrors the
proven ``w2v_common.database.rls`` posture; adapted for the KAG services (an
``exclude`` set, since most KAG services carry operational tables — outbox,
idempotency — that are swept cross-tenant by background processors and must NOT
be under RLS).

Each tenant-scoped table (every table with a ``tenant_id`` column, minus
``exclude``) gets RLS ``ENABLE`` + a policy keyed on the per-request GUC
``app.current_tenant``:
  * a **NOT NULL** ``tenant_id`` → strict equality (read + write scoped to the GUC);
  * a **NULLABLE** ``tenant_id`` → "global-or-own": rows with ``tenant_id IS NULL``
    are global/shared (readable by every tenant), writes still GUC-scoped.

Design invariants (match the w2v posture):
  * **ENABLE, never FORCE.** The service DB is owned by the non-superuser
    ``<svc>_user``; the runtime isolates by connecting as a *separate* non-owner
    restricted role, which is bound under ENABLE. Migrations and cross-tenant
    platform processors keep connecting as the owner (owner-bypass under
    ENABLE-not-FORCE). Applying FORCE would 0-row the owner and break them.
  * **Fail-closed GUC.** ``NULLIF(current_setting('app.current_tenant', true), '')``
    — ``current_setting(…, true)`` is missing-ok (unset → NULL); ``NULLIF(…, '')``
    folds the empty string ``set_config(…, is_local=true)`` leaves on a pooled
    PgBouncer connection back to NULL → predicate false → 0 rows (never a cast 500).
  * **Inert until cutover.** Policies change nothing while the app connects as the
    owner; they bind only once the runtime switches to the restricted role +
    ``TENANT_RLS_MODE=enforce`` (an atomic, reversible per-service gitops cutover).
  * **Single source.** The migration (prod) and the ``create_all`` ``after_create``
    event (tests/dev) both render from these helpers, so they cannot drift.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Collection

from sqlalchemy import DDL, Connection, Engine, MetaData, String, event, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

TENANT_COLUMN = "tenant_id"
POLICY_NAME = "tenant_isolation"
_GLOBAL_READ = f"{POLICY_NAME}_read"
_GLOBAL_INS = f"{POLICY_NAME}_ins"
_GLOBAL_UPD = f"{POLICY_NAME}_upd"
_GLOBAL_DEL = f"{POLICY_NAME}_del"
_ALL_POLICY_NAMES = (POLICY_NAME, _GLOBAL_READ, _GLOBAL_INS, _GLOBAL_UPD, _GLOBAL_DEL)

# The transaction-scoped GUC the request path binds, as TEXT. The predicate casts
# to match the column type: ``uuid`` columns cast ``::uuid``; ``varchar``/text
# columns compare text-to-text (casting would raise "operator does not exist:
# character varying = uuid"). Factored once so migration + test event never drift.
_GUC_TEXT = "NULLIF(current_setting('app.current_tenant', true), '')"


def tenant_table_names(metadata: MetaData, *, exclude: Collection[str] = ()) -> list[str]:
    """Names of every table in ``metadata`` carrying a ``tenant_id`` column.

    ``exclude`` drops operational tables (outbox/idempotency/global stats) that
    carry ``tenant_id`` but are intentionally NOT under RLS — they are swept
    cross-tenant by background processors that connect as the owner.
    """
    ex = set(exclude)
    return [
        t.name for t in metadata.sorted_tables if TENANT_COLUMN in t.columns and t.name not in ex
    ]


def _tenant_column(metadata: MetaData, table_name: str):  # noqa: ANN202
    return metadata.tables[table_name].columns[TENANT_COLUMN]


def _is_nullable(metadata: MetaData, table_name: str) -> bool:
    return bool(_tenant_column(metadata, table_name).nullable)


def _predicate(metadata: MetaData, table_name: str) -> str:
    col = _tenant_column(metadata, table_name)
    guc = _GUC_TEXT if isinstance(col.type, String) else f"{_GUC_TEXT}::uuid"
    return f"{TENANT_COLUMN} = {guc}"


def _strict_statements(table: str, predicate: str) -> list[str]:
    return [
        f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY",
        f"DROP POLICY IF EXISTS {POLICY_NAME} ON {table}",
        f"CREATE POLICY {POLICY_NAME} ON {table} USING ({predicate}) WITH CHECK ({predicate})",
    ]


def _global_statements(table: str, predicate: str) -> list[str]:
    # Nullable tenant_id ⇒ NULL rows are shared/global (read by all), writes scoped.
    read = f"{TENANT_COLUMN} IS NULL OR {predicate}"
    return [
        f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY",
        f"DROP POLICY IF EXISTS {_GLOBAL_READ} ON {table}",
        f"DROP POLICY IF EXISTS {_GLOBAL_INS} ON {table}",
        f"DROP POLICY IF EXISTS {_GLOBAL_UPD} ON {table}",
        f"DROP POLICY IF EXISTS {_GLOBAL_DEL} ON {table}",
        f"CREATE POLICY {_GLOBAL_READ} ON {table} FOR SELECT USING ({read})",
        f"CREATE POLICY {_GLOBAL_INS} ON {table} FOR INSERT WITH CHECK ({predicate})",
        f"CREATE POLICY {_GLOBAL_UPD} ON {table} FOR UPDATE "
        f"USING ({predicate}) WITH CHECK ({predicate})",
        f"CREATE POLICY {_GLOBAL_DEL} ON {table} FOR DELETE USING ({predicate})",
    ]


def upgrade_statements(metadata: MetaData, *, exclude: Collection[str] = ()) -> list[str]:
    """DDL applying RLS to every ``tenant_id`` table (use in a migration ``upgrade()``)."""
    out: list[str] = []
    for name in tenant_table_names(metadata, exclude=exclude):
        predicate = _predicate(metadata, name)
        out += (
            _global_statements(name, predicate)
            if _is_nullable(metadata, name)
            else _strict_statements(name, predicate)
        )
    return out


def downgrade_statements(metadata: MetaData, *, exclude: Collection[str] = ()) -> list[str]:
    """Reverse of :func:`upgrade_statements` (fully reversible)."""
    out: list[str] = []
    for name in tenant_table_names(metadata, exclude=exclude):
        for policy in _ALL_POLICY_NAMES:
            out.append(f"DROP POLICY IF EXISTS {policy} ON {name}")
        out.append(f"ALTER TABLE {name} DISABLE ROW LEVEL SECURITY")
    return out


def register_rls_ddl(metadata: MetaData, *, exclude: Collection[str] = ()) -> None:
    """Apply the SAME policies on ``create_all`` (tests/dev build schema without alembic).

    Registers one ``after_create`` listener on ``metadata`` — it runs once all
    tables exist, so every in-scope ``tenant_id`` table gets its policy. Idempotent
    across repeated ``create_all`` (``DROP POLICY IF EXISTS`` precedes each ``CREATE``).
    """

    def _apply(_target: MetaData, connection: Connection, **_kw: object) -> None:
        for stmt in upgrade_statements(metadata, exclude=exclude):
            connection.execute(DDL(stmt))

    event.listen(metadata, "after_create", _apply)


def tenant_rls_mode() -> str:
    """Current enforcement mode from ``TENANT_RLS_MODE`` (``off`` | ``enforce``; default ``off``)."""
    return os.getenv("TENANT_RLS_MODE", "off").strip().lower()


async def bind_session_tenant(
    session: AsyncSession, tenant_id: str | None, *, mode: str | None = None
) -> None:
    """Bind ``app.current_tenant`` for the session's current transaction when enforcing.

    Transaction-scoped (``set_config(…, is_local=true)``) → PgBouncer-safe. A no-op
    unless ``mode`` (default: :func:`tenant_rls_mode`) is ``enforce``. With no
    resolvable ``tenant_id`` the GUC is left unset → RLS fail-closes to 0 rows
    (deliberate). Pass the request-scoped tenant (e.g. ``tenant_id_var.get(None)``);
    never a client-asserted value.
    """
    if (mode or tenant_rls_mode()) != "enforce" or not tenant_id:
        return
    await session.execute(
        text("SELECT set_config('app.current_tenant', :tenant, true)"),
        {"tenant": str(tenant_id)},
    )


def register_tenant_guc(
    engine: AsyncEngine,
    get_tenant: Callable[[], str | None],
    *,
    mode: str | None = None,
) -> None:
    """Bind ``app.current_tenant`` on **every** transaction of ``engine``.

    Registers one ``begin`` listener on the engine, so a single call covers
    *all* session paths — ``get_session`` plus any direct ``sessionmaker()``
    usage — making the binding **correct-by-construction**: a new session site
    can never forget it. Prefer this over per-call :func:`bind_session_tenant`
    for services that open sessions in more than one place.

    ``get_tenant`` is invoked at transaction-begin and should return the
    request-scoped tenant (e.g. ``lambda: tenant_id_var.get(None)``); a
    client-asserted value must never be used. No-op unless enforcing; with no
    resolvable tenant the GUC is left unset → RLS fail-closes to 0 rows.
    ``set_config(…, is_local=true)`` is transaction-scoped → PgBouncer-safe.
    """

    @event.listens_for(engine.sync_engine, "begin")
    def _bind_tenant_guc(conn: Connection) -> None:
        if (mode or tenant_rls_mode()) != "enforce":
            return
        tenant = get_tenant()
        if tenant:
            conn.exec_driver_sql(
                "SELECT set_config('app.current_tenant', %s, true)", (str(tenant),)
            )


def register_tenant_guc_sync(
    engine: Engine,
    get_tenant: Callable[[], str | None],
    *,
    mode: str | None = None,
) -> None:
    """Synchronous-engine sibling of :func:`register_tenant_guc`.

    Some KAG consumers (e.g. ``ingestion_service``) run a synchronous
    ``create_engine`` rather than an ``AsyncEngine``, so there is no
    ``.sync_engine`` to attach to — the ``begin`` listener binds directly to the
    sync ``Engine``. Same fail-closed, inert-until-``enforce``, PgBouncer-safe
    (``is_local=true``) semantics as the async variant.

    ``get_tenant`` is invoked at transaction-begin and should return the
    request-scoped tenant (e.g. ``lambda: tenant_id_var.get(None)``); a
    client-asserted value must never be used.
    """

    @event.listens_for(engine, "begin")
    def _bind_tenant_guc(conn: Connection) -> None:
        if (mode or tenant_rls_mode()) != "enforce":
            return
        tenant = get_tenant()
        if tenant:
            conn.exec_driver_sql(
                "SELECT set_config('app.current_tenant', %s, true)", (str(tenant),)
            )
