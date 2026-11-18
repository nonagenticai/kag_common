# kag-common

Shared infrastructure for the KAG backend services (`karma_service`,
`hirag_service`, `kag_orchestrator`, `ingestion_service`).

Carries cross-cutting infrastructure **only**. It deliberately holds **no DB
schema and no alembic**, so the per-service "one service = one database = one
user" / per-service blast-radius invariant is preserved. The gateway service
`kag` is **not** a consumer — its `src/models/*` are the public API contract and
must not couple to backend internals.

## Install

This repository is the source of the `kag-common` distribution. Install it from
the tagged source:

```toml
# pyproject.toml
dependencies = ["kag-common @ git+https://github.com/nonagenticai/kag_common@v0.37.1"]
```

It also depends on `research-contracts`, which is resolved from its public
source at the tag named in `pyproject.toml`; no private index is involved.

## Surfaces

### Logging — `kag_common.logging`

`configure_logging()` / `get_logger()` install the fleet-standard structlog
pipeline (JSON or console via `LOG_FORMAT`, OTel trace correlation, service +
environment context). Per-service divergences are parameters:

```python
from kag_common.logging import configure_logging, get_logger

# kag_orchestrator keeps uvicorn.access but drops /health probe spam:
configure_logging(
    service_name="kag-orchestrator",
    suppress_loggers=("httpx", "httpcore", "urllib3"),
    filter_health_access=True,
)
log = get_logger(__name__, service_name="kag-orchestrator")
```

### Middleware — `kag_common.middleware`

```python
from kag_common.middleware import RequestIdMiddleware

app.add_middleware(RequestIdMiddleware)  # mints/echoes X-Request-ID (uuid7)
```

### Metrics — `kag_common.metrics`

Centralised prom counters shared across the KAG ecosystem. Names + labels
match `gitops-production/clusters/strato/services/alerting/rules/prometheusrule-kag-loudness.yaml`.

```python
from kag_common.metrics import (
    make_metrics_app,
    record_tenant_id_required,
    record_dual_write,
    record_stage_degraded,
)

app.mount("/metrics", make_metrics_app())
record_tenant_id_required("kag_graph_service")
record_dual_write("hirag_service", tenant_id, "succeeded")
record_stage_degraded("kag_orchestrator", tenant_id, "karma")
```

#### New in 0.30.0 — the credential-less tenant-assertion path is no longer silent

`DEFAULT_TRUSTED_CIDRS` ships `10.0.0.0/8`, a superset of the k3s pod CIDR
`10.42.0.0/16`. Seven consumers branch on `is_trusted_network()` alone and then
read the tenant off a bare `X-Tenant-Id`, so any pod in the cluster can assert
any tenant with no credential. Until 0.30.0 that path emitted **no counter, no
log and no alert**, so the size of the affected population was unknown.

Two series now exist. **Neither enforces anything** — no request changes outcome,
there is no new config knob, and a bare version bump is behaviour-identical.

| series | fires today? | labels |
|---|---|---|
| `kag_trusted_network_bypass_total` | **yes**, in all 7 consumers, with no per-repo change — it hangs off `is_trusted_network()`, which they already call | `service`, `peer_class`, `trusted` |
| `kag_tokenless_tenant_assertion_total` | **no** — it hangs off `resolve_tokenless_tenant()`, which zero consumers call yet | `service`, `has_header`, `outcome` |

⚠️ **Read the first one as an upper bound, not a request count.** It counts
predicate *evaluations*. `nlp_service`, `ingestion_service` and
`kag_graph_service` each evaluate it twice per request (once in middleware, once
in a tenant dependency), so take a per-`service` ratio rather than the raw number:

```promql
sum by (service, peer_class) (rate(kag_trusted_network_bypass_total{trusted="true"}[1h]))
```

⚠️ **`peer_class` is a network bucket, not an identity — it cannot name the
calling workload.** It separates the distinct vectors (`lan_192` is the
2026-04-18 SSR-proxy path where an *external* caller presents a private source;
`k8s_pod` is both any workload in the mesh *and* the hostNetwork gateway, which
SNATs to `10.42.0.0`), but attributing a specific caller still requires
ztunnel/Istio access logs joined on time. A per-pod-IP label would close that and
is rejected on cardinality, not on principle. This is the same gap
`worker_management_unauthenticated_tenant_assertion_total` has.

⚠️ **`has_header` — the header-absent/header-present split — exists only on the
second series**, because `is_trusted_network(host)` is handed a host string and
nothing else. The header-absent case is the more dangerous of the two (the
consumer's own `raw_tenant or DEFAULT_TENANT_ID` picks a tenant nobody chose per
request), so a consumer that wants to size *that* population has to migrate to
`resolve_tokenless_tenant()` first.

### Internal-token verification — `kag_common.internal_token`

Verify the short-lived RS256 JWTs `license-authz` mints for no-SPIFFE /
hostNetwork callers (Lane F1). Build one `InternalTokenVerifier` at startup and
reuse it — it caches the JWKS by `kid` (one fetch, re-fetched only on a key
rotation) so steady-state verification does no network I/O. It **fails closed**:
any signature/claim/fetch error raises `InvalidInternalTokenError`, which the caller
must map to a 401. The `jwks_url` is required (no source-side default — wire it
from gitops env, e.g. `http://license-authz.istio-system.svc:<port>/jwks`);
`issuer`/`audience` default to the `license-authz` / `internal` contract.

`audience` is **type-checked at construction** (as it is on `AttestationVerifier`):
a `str`, or a collection of `str`. Anything else raises `ValueError` from the
constructor rather than failing on every later `verify()` — a non-`str` audience
used to make `jwt.decode` raise a bare `TypeError` on every token, and an
iterable-but-wrong one (`b"internal"`, `[]`, `[123]`) to reject every token, so a
one-line wiring mistake became a permanent auth outage that looked like the
callers' fault. Passing a `str` — what every consumer does — is unaffected.

```python
from kag_common.internal_token import InternalTokenVerifier, InvalidInternalTokenError

verifier = InternalTokenVerifier(jwks_url=settings.internal_token_jwks_url)

try:
    verified = await verifier.verify(token)        # X-Internal-Token bearer
except InvalidInternalTokenError:
    return unauthorized_response("invalid internal token")
tenant_id = verified.tenant_id

# on lifespan shutdown:
await verifier.aclose()
```

### Auth — `kag_common.auth`

License tokens travel in `X-Tenant-Id: Bearer <token>`; by default
`Authorization` is reserved for the caller's own auth (see 0.37.0 for the opt-in).

#### New in 0.37.0 — OPT-IN: accept the licence from `Authorization`

**Why.** The istio ingress gateway validates `Authorization: Bearer <licence>`,
strips client identity headers, injects a **plain uuid** `x-tenant-id`, and
leaves `Authorization` in place. A service that reads the licence only from
`X-Tenant-Id: Bearer` sees none on gateway traffic and falls to the
trusted-network path — the path on which **any in-mesh pod can assert any
tenant** with a bare `X-Tenant-Id`. Accepting the licence from `Authorization`
puts gateway traffic on the verified introspection path.

**Inert by default.** Bumping to 0.37.0 changes nothing: `extract_license_token`
is untouched, nothing in this library calls the new helpers, and
`apply_effective_tenant`'s new keyword `requested=` defaults to the old header
read. A service opts in with `AUTH_ACCEPT_AUTHORIZATION_LICENCE=true` (exactly
`"true"` — `True`, `1`, `yes` are **off**) or by passing
`accept_authorization=True`.

| added | does |
|---|---|
| `extract_license_token_with_source(request, *, accept_authorization=None)` | `(token, "x_tenant_id" \| "authorization")` or `(None, None)`. `X-Tenant-Id: Bearer` keeps precedence; scheme case-insensitive; empty bearer ⇒ None. `None` ⇒ env flag. |
| `authorization_bearer(request)` | the `Authorization: Bearer` token, else None |
| `plain_tenant_header(request)` | non-Bearer `X-Tenant-Id` (stripped) or `""`; `"Bearer"`/`"Bearer <tok>"` is auth, `"bearerco"` is a tenant |
| `bind_plain_tenant(request, *, credential_tenant, subject_id, source, resolve=None)` / `bind_licence_tenant_claims(...)` (pure) | non-delegating subject: plain header (when `source="authorization"`) and `X-Effective-Tenant-Id` (any source) must be the licence tenant, else `LicenceTenantMismatch`. Delegating subject: plain header stands in for `X-Effective-Tenant-Id` (explicit wins). Returns the requested effective tenant for `apply_effective_tenant(..., requested=)`. |
| `require_own_tenant(credential_tenant, claimed, *, resolve=None)` | textual (case-insensitive) match, else resolve both via the caller's resolver; no resolver ⇒ mismatch (fail closed) |
| `LicenceTenantMismatch` | render **403** |
| `accept_authorization_licence()`, `ACCEPT_AUTHORIZATION_LICENCE_ENV`, `LicenceSource`, `TenantResolver` | flag + types |

⛔ **George 2026-10-14 — hard 401.** Once a service opts in, a non-licence
token in `Authorization` (e.g. a Keycloak JWT) is introspected like any other:
`active: false` ⇒ **401**. No fallback to the caller's own auth, no fallback to
the trusted-network path. A service that today authenticates its callers with a
JWT in `Authorization` must not opt in until those callers move.

**Adoption recipe** (lifted from requirements_management #222 / #223,
`src/auth/middleware.py`):

```python
from kag_common.auth import (
    LicenceTenantMismatch, apply_effective_tenant, bind_plain_tenant,
    extract_license_token_with_source, introspect_license,
)

token, source = extract_license_token_with_source(request)   # env-gated
if token:
    intro = await introspect_license(token)
    if intro is None:
        return error(503, ...)          # no verdict; not the caller's fault
    if not intro.get("active"):
        return error(401, ...)          # HARD: no fallback (George 2026-10-14)
    credential_tenant = str(intro.get("tenant_id") or intro.get("subject_id") or "")
    subject_id = str(intro.get("subject_id") or "")
    try:
        requested = await bind_plain_tenant(
            request, credential_tenant=credential_tenant, subject_id=subject_id,
            source=source, resolve=resolve_tenant_to_uuid,   # your resolver
        )
    except LicenceTenantMismatch as exc:
        return error(403, str(exc))
    tenant, subject, licence = apply_effective_tenant(
        request, subject_id, credential_tenant, subject_id, intro.get("license_id"),
        requested=requested,
    )
    # a re-scoped (delegated) tenant is caller input: verify it against the registry
```

Also new (report-only): `conformance.report_unseamed_tenant_admission("src")`
— see the conformance section.

#### New in 0.20.0 — an opt-in gate for tokenless in-cluster identity

> **This release does NOT close the cross-tenant forgery hole.** It ships the
> tool and nothing else. The shipped default `TRUSTED_CIDRS` is unchanged, no
> caller in this library uses the new gate, and every consumer still resolves the
> tenant exactly as before. Bumping to 0.20.0 changes a consumer's behaviour in
> exactly one way — see the `testclient` note below. The hole stays open until
> each consumer moves its own identity branch onto `is_trusted_identity_source()`
> **and** the gateway has been armed to send a credential that branch accepts.

**The problem it exists to solve.** The default `TRUSTED_CIDRS` includes
`10.0.0.0/8`, a **superset of the k3s pod CIDR `10.42.0.0/16`**, and consumers
gate a tokenless bypass on `is_trusted_network()` alone before reading the tenant
off a bare `X-Tenant-Id`. Net effect: any pod in the cluster can assert any
tenant with no credential. RLS then binds `app.current_tenant` to the *forged*
tenant and faithfully scopes the query to the victim — a confused deputy, not a
backstop.

| | meaning | gate |
|---|---|---|
| `is_trusted_network(host)` | *"where did this come from"* — membership in `TRUSTED_CIDRS`. Right input for non-identity allowlists (unauthenticated `/metrics`, health probes). | none (unchanged) |
| `is_trusted_identity_source(host)` | *"may this peer name its own tenant with no token"* | membership **and** `AUTH_TRUST_INCLUSTER_IDENTITY=true` (**default false**) |

Also exported: `DEFAULT_TRUSTED_CIDRS` (the shipped default, lifted out of the
`os.getenv` call so it is assertable and greppable — same value as before),
`parse_trusted_cidrs()`, and `trust_incluster_identity()` (reads the env var at
call time, so test fixtures and runtime config are seen without a module
reload). Mirrors `w2v_common` 0.6.9 — same env var name, same default, same
call-time read.

#### Removed in 0.20.0 — the `testclient` name short-circuit

`is_trusted_network()` used to return `True` for any peer literally named
`testclient` — not CIDR-checked, not flag-gated, shipped in every consumer
image. It is not prod-reachable (the name comes from the socket peername and
nothing here reads `X-Forwarded-For`), but it is still a hardcoded
unauthenticated bypass, and `graph_adapter_service` declined to adopt this
function *because* of it. It is gone.

This is the one behaviour change in 0.20.0. If a consumer's tests relied on it,
give the client a real peer: `TestClient(app, client=("127.0.0.1", 50000))` —
loopback is in the default CIDRs, so that is real membership rather than a name
match.

**Consumer migration — sequence this, do not just flip it.** A service that
accepts a bare `X-Tenant-Id` from a trusted peer moves that one branch to:

```python
from kag_common.auth import is_trusted_identity_source

client_host = request.client.host if request.client else None
if is_trusted_identity_source(client_host):        # was: is_trusted_network(...)
    raw_tenant = request.headers.get("X-Tenant-Id", "").strip()
    ...
# flag off -> falls through to normal token auth and fails closed
```

⚠️ That branch is **the API gateway's production path**, not only a legacy
bypass. The gateway (`gitops-production/clusters/strato/policies/envoy-filters/
ext-authz-enforce.yaml`) strips the client's `x-tenant-id`, validates the license
token, then re-injects a **bare** `x-tenant-id`; it runs `hostNetwork` and SNATs
to `10.42.0.0`, i.e. inside `10.0.0.0/8`. Migrating a consumer without first
arming the gateway to send a credential the consumer still accepts will 401 all
authenticated external traffic to it. Narrowing `DEFAULT_TRUSTED_CIDRS` has the
same blast radius, which is why this release does not touch it.

#### Conformance lints — `kag_common.auth.conformance`

`kag_common.auth` ships no ASGI `dispatch` — every consumer owns its own
middleware — so a helper in this library cannot gate anything on its own. The
compensating control is a set of **static AST lints that fail a build**, wired
into the CONSUMER's own test suite. They are source-only (no network, no
cluster), so they run anywhere:

```python
from kag_common.auth.conformance import (
    assert_licence_token_carriage,
    assert_tokenless_identity_is_gated,
)


def test_no_tokenless_identity_bypass():
    assert_tokenless_identity_is_gated("src")


def test_licence_tokens_are_carried_correctly():
    assert_licence_token_carriage("src")
```

| assert | asks | fails with |
|---|---|---|
| `assert_tokenless_identity_is_gated(*paths)` | *"may this peer name a tenant with no token"* — a branch gated on network membership alone whose body binds a bare `X-Tenant-Id` as identity | `TokenlessIdentityBypassError` |
| `assert_licence_token_carriage(*paths)` | *"did the caller actually SEND one"* — R4/R1/R2 below | `LicenceCarriageError` |

`assert_licence_token_carriage` covers three shapes:

* **R4** — a headers dict (or `dict(...)`) that sets `X-Tenant-Id` to a value
  carrying no `Bearer` and does **not** also set `Authorization`. A bare
  `X-Tenant-Id` is an *assertion*, not a credential: the receiver honours it only
  when an allowlisted `Authorization: Bearer <service token>` vouches for it. Use
  `outbound_headers(tenant_id=..., authorization_service_token=...)` rather than
  a hand-rolled dict, so the vouch cannot be dropped one call site at a time.
  ⚠️ R4 reads dict **literals** only — it cannot see headers built by subscript
  assignment (`headers["X-Tenant-Id"] = …`) or carrying a `**spread`, and it says
  nothing about whether a vouch **destination list** covers every hop. A clean
  run is not evidence on either.
* **R1** — a value derived from the `Authorization` header passed into
  `introspect_license`. Licences travel in `X-Tenant-Id: Bearer <token>`; read
  them with `extract_license_token(request)` — or, for a service that opted in to
  the gateway carrier (0.37.0), `extract_license_token_with_source(request)`,
  which R1 does not flag. A hand-rolled `Authorization` read is still flagged.
* **R2** — a `subject_id` bound from an introspection result and then overwritten
  by the caller-supplied `X-Subject-Id`. The sanctioned
  `subject_id = fwd_subject or subject_id` fallback is **not** flagged.

Both scans **raise `VacuousScanError` rather than passing** when they could not
examine what they were asked to: no paths, zero `.py` files, a file that cannot
be read or parsed (an embedded NUL hides a file from `grep` but not from
`ast.parse`), or — for the carriage scan — zero candidate nodes reached. A lint
that reports "clean" because it looked at nothing is the defect these exist to
prevent. Each rule's blind spots are listed in the module docstring and in
`_r2_findings`; read them before treating a clean run as an all-clear.

**Report-only (0.37.0) — `report_unseamed_tenant_admission("src")`.** Flags a
trusted-path branch (gated on network membership **or** the opt-in) that reads a
tenant header by hand instead of via `resolve_tokenless_tenant` or a refusing
vouch — a shape `assert_tokenless_identity_is_gated` clears when the opt-in is in
the test (the 0.20.0 migration example above is exactly it). It **never fails
on a finding**: it returns the list and emits one
`UnseamedTenantAdmissionWarning` each, so the upgrade cannot redden a consumer's
CI. Gate on it explicitly with `assert report_unseamed_tenant_admission("src") ==
[]`. Vacuity still raises `VacuousScanError`.

#### On-behalf-of allowlists — a separate assert, manifests required

`assert_onbehalf_allowlists_are_set(code_root, manifests_root)` cross-checks that
every `*_ONBEHALF_SUBJECTS` env var **read** in code is **set** to a non-empty
literal `value:` in some `deployment.yaml` under the manifests root. An allowlist
no manifest populates is an empty allowlist: the receiver vouches for nobody and
refuses every on-behalf-of call it is supposed to accept.

It recognises **both** read shapes on this fleet — the name as a string literal
(`os.getenv("FOO_ONBEHALF_SUBJECTS")`) and the name as a pydantic-settings field
declaration (`FOO_ONBEHALF_SUBJECTS: str = Field(...)`). ⚠️ The field shape is
matched on the **identifier**: a field carrying `validation_alias`/`alias` to a
different env name is attributed to the wrong variable, so a finding on an
aliased field is a name to verify by hand, not a verdict.

`manifests_root` is a **required** argument with no default, on purpose — this
check needs the gitops tree on disk, which a consumer's CI does not have, so it
must be impossible to call somewhere it would silently find nothing to
contradict it. Keep it out of the consumer suite; run it where the manifests
live:

```python
from kag_common.auth.conformance import assert_onbehalf_allowlists_are_set

assert_onbehalf_allowlists_are_set("src", "…/gitops-production/clusters/strato")
```

It raises `OnBehalfAllowlistError` on a missing allowlist, and `VacuousScanError`
if the code root has no `.py` files, the manifests root has no Deployments, or
the code names no `*_ONBEHALF_SUBJECTS` at all. A `valueFrom:` (secret ref)
counts as **unset**: this lint cannot open a Secret, so it must not claim the
value is non-empty.

## Scope (roadmap)

Migrated incrementally, lowest-coupling first. Logging + request-id are the
first surfaces. Candidate follow-ups (each its own consumer-adoption PR):
license-introspect HTTP client, request-logging middleware, env/Settings
helpers, DB engine/session factory (engine only — never schema), telemetry init.

## Licensing

This is a shared library, not a licence-enforcing product. It ships helpers that
*verify* licence tokens minted by the platform's licence service; it never mints
them, and no helper runs unless a consumer configures one. Importing `kag_common`
requires no licence key and makes no licensing network call.

## License

Apache 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
