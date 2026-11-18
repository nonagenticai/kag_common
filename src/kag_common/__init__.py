"""kag_common — shared infrastructure for KAG backend services.

Carries cross-cutting infrastructure (the ``config.BaseServiceSettings`` settings
base, structured logging, ASGI middleware, telemetry, prom counters, and the
``idempotency`` helper). It ships **no migrations and creates no tables**: the
``idempotency`` module provides a column mixin + query helpers, but each
consuming service still owns its own ``ingest_idempotency`` table, migration, and
DB/user — so the per-service "one service = one database = one user" /
per-service blast-radius invariant is preserved.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("kag-common")
except PackageNotFoundError:
    __version__ = "unknown"
