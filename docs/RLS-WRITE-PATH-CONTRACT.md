# RLS Write-Path Contract (`TENANT_RLS_MODE=enforce`)

> The checklist every service must satisfy to be **safe under Postgres row-level-security
> enforcement**. Written after a 3-bug production incident (2026-06-24) in which the ingestion
> write path was silently down ~23h under enforce while every health check stayed green. The
> root cause was not a single bug — it was that the cutover was verified on the **read path only**.
> This document turns the hard-won invariants into something you can verify against, not re-derive.

Primitives live in this package: `kag_common.database.rls` (`register_tenant_guc`,
`register_tenant_guc_sync`, `bind_session_tenant`) and `kag_common.auth.outbound` (`outbound_headers`).

---

## The mechanism (one sentence)

`X-Tenant-Id` (inbound) → request tenant context → `app.current_tenant` GUC bound **per
transaction** → Postgres RLS policy `tenant_isolation` filters every row.

Services run as the **restricted `<svc>_app` role** with RLS `FORCE`d. The table **owner** bypasses
RLS (`ENABLE` without `FORCE` for owners); the app role does **not**. This asymmetry is why a bug can
hide: anything that still runs as the owner (migrations, celery maintenance sweeps, an owner-engine
worker) keeps working while the app-role request path is broken.

The GUC is read fail-closed:
`NULLIF(current_setting('app.current_tenant', true), '')` (`database/rls.py:55`) — an unset GUC or
the empty string `set_config(…, is_local=true)` leaves on a pooled connection both resolve to a
tenant of `NULL`, which matches **zero** rows. There is no "default tenant" escape hatch.

---

## Invariant 1 — Every DB write runs on a GUC-bound connection

EVERY `INSERT` / `UPDATE` / `DELETE` must execute on a connection that has already run
`set_config('app.current_tenant', <tenant>, true)` for that transaction. Two sanctioned mechanisms:

| Mechanism | Use when | Helper |
|---|---|---|
| GUC-bound SQLAlchemy engine | the service writes through SQLAlchemy | `register_tenant_guc(engine)` / `register_tenant_guc_sync(engine)` (`database/rls.py:172/204`) — binds on **every** transaction via an event hook |
| Raw psycopg pool wrapped per-acquire | the service uses a raw `psycopg` pool, not the engine | a context manager that runs `SELECT set_config('app.current_tenant', %s, true)` on acquire (ingestion `JobRepository._acquire`, kag_graph `tenant_scoped_connection()`); or `bind_session_tenant()` (`database/rls.py:156`) |

`set_config(…, is_local=true)` is **transaction-scoped** → PgBouncer-safe (the GUC does not leak to
the next borrower of a pooled connection).

**Anti-pattern (ingestion Bug-2):** a raw psycopg pool that never binds the GUC. Under enforce, the
app role's every write violates `tenant_isolation` and is rejected. Pre-cutover this was invisible
because the same code ran as the owner. **If a repository does not go through the GUC-bound engine,
it MUST bind the GUC itself — there is no third option.**

## Invariant 2 — Owner does DDL, app does DML

The restricted `<svc>_app` role has **no `CREATE` on schema `public`**. Therefore:

- The `migrate` init-container (running as the **owner**) owns all schema creation/migration.
- Any runtime `create_all()` / `create_tables()` in app startup MUST be guarded **non-fatal** — it
  will raise `InsufficientPrivilege` as the app role, and that is expected, not an error.

**Anti-pattern (ingestion Bug-1):** an unguarded runtime `create_tables()` whose
`InsufficientPrivilege` is swallowed by a broad `except` that *also* skips unrelated initialization
(there: the job-repo init), turning a benign permission error into a total outage. Guard schema DDL
tightly and never let it short-circuit unrelated startup.

## Invariant 3 — Every cross-service hop carries `X-Tenant-Id`

Not just primary request paths. **Callbacks, durable-outbox deliveries, and per-stage callbacks**
all cross a service boundary and all must stamp the tenant. Use `outbound_headers()`
(`auth/outbound.py:29`, the Bearer/bare ladder) on every outbound call, or stamp the bare uuid form
for a downstream's trusted-network middleware.

There is **no `DEFAULT_TENANT_ID` fallback** (A4/A5, 2026-05-27). A hop that omits the header does
not land in some default tenant — the downstream resolves tenant `NULL` and the request fails closed.

**Anti-pattern (orchestrator Bug-3):** the orchestrator→ingestion terminal callback carried no
`X-Tenant-Id`; the ingestion handler resolved `NULL`, its job lookup was RLS-hidden, and it returned
**HTTP 200 with 0 rows** ("job not found") — so the job froze mid-pipeline with no error anywhere.

## Invariant 4 — RLS fails closed *silently*

A wrong or missing tenant yields **HTTP 200 + 0 rows**, never an exception. This is the meta-lesson:

> **"Pod Ready + read-path OK" does NOT prove the service is correct under enforce.**

Readiness probes don't hit the DB as the app role with a real tenant. A `SET ROLE` SQL probe bypasses
the app's own connection wiring. The read path can work while the write path is dead (owner-role
maintenance keeps reads populated). **Verification MUST include a real write E2E and a cross-tenant
probe** — see below.

A corollary for **deletes** (the inverse failure): a `DELETE` is a write, so a delete that runs
*without* the GUC bound silently affects **0 rows** and looks successful — PHI is never purged and
nobody notices. Delete/purge endpoints must **return affected-row counts** and callers must treat a
0-count-where-rows-were-expected as an error.

---

## Per-service conformance (audited 2026-06-24)

| Service | Write-path mechanism | X-Tenant-Id out |
|---|---|---|
| `ingestion_service` | raw psycopg pool + `JobRepository._acquire` binds the GUC | `outbound_headers()` on orchestrator + chunks-bulk hops |
| `kag_graph_service` | SQLAlchemy engine + raw `chunks` pool via `tenant_scoped_connection()` | n/a (terminal store) / callbacks stamp it |
| `karma` | engine `register_tenant_guc` | `outbound_headers()` |
| `hirag` | engine `register_tenant_guc` | `outbound_headers()` |
| `scientific_processor` | engine `register_tenant_guc` | `outbound_headers()` |
| `kag_orchestrator` | owner engine for watchdog/stage workers + `register_tenant_guc` elsewhere | stamps `X-Tenant-Id` on durable + per-stage callbacks |

When onboarding a new service to enforce, add its row here and prove it against the recipe below.

---

## Verification recipe (all three, not just the first)

1. **`SET ROLE` probe** (proves the policy + role grants):
   ```sql
   SET ROLE <svc>_app;
   -- no GUC bound → 0 rows
   SELECT count(*) FROM <table>;
   -- correct tenant → rows
   SELECT set_config('app.current_tenant', '<tenant>', false); SELECT count(*) FROM <table>;
   -- foreign tenant → 0 rows
   SELECT set_config('app.current_tenant', '<other-tenant>', false); SELECT count(*) FROM <table>;
   RESET ROLE;
   ```
2. **A real write E2E** through the service's actual HTTP write endpoint as a real tenant — the only
   thing that exercises the app's own connection wiring (the gap that hid all three 2026-06-24 bugs).
3. **Log grep** across the test window for `SASL`/auth errors → expect none (proves the `<svc>_app`
   role auth holds under load, not just at probe time).

---

## References

- Incident + fixes: memory `hipaa-g4-ingestion-write-path-rls-fix-2026-06-24`;
  fleet cutover: `kag-g4-rls-cutover-5-services-2026-06-23`.
- PRs: ingestion_service #52 (Invariants 1+2), kag_orchestrator #87 (Invariant 3).
- Code: `kag_common/src/kag_common/database/rls.py`, `kag_common/src/kag_common/auth/outbound.py`.
