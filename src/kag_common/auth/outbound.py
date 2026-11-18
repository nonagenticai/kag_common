"""Outbound HTTP header builder for KAG inter-service hops.

Single source of truth for the three-branch ``X-Tenant-Id`` priority ladder
that every KAG backend's outbound call must obey:

1. ``tenant_token`` — caller-supplied per-request token. JWT-shaped (>=2 dots)
   is sent ``Bearer``-prefixed so the downstream's license-introspect can
   validate it; opaque values are sent bare so the downstream's trusted-network
   bypass uses them as a tenant identifier directly.
2. ``service_token`` — process-wide service identity (each caller reads its own
   ``settings.KAG_SERVICE_TOKEN`` / equivalent and passes it in). Always sent
   ``Bearer``-prefixed: license introspect succeeds on the opaque token. The
   heuristic in (1) would mis-classify the zero-dot opaque form and send it
   unprefixed, which would 401.
3. ``tenant_id`` — bare UUID fallback. Unprefixed; only satisfies auth when the
   downstream's trusted-network bypass fires (RFC1918 peer + ``X-Tenant-Id``
   present is the post-A4/A5 contract).

``kag_common`` is settings-free by design; the caller injects its own
``service_token`` rather than this module reading any env var. Matches the
posture of ``config.BaseServiceSettings`` and ``auth.introspect_license``.

Licence attribution
-------------------
``license_id`` propagates the caller's *resolved* licence to the downstream as
a bare ``X-License-Id`` header. This is attribution data, never a credential:
the downstream must still authenticate via the ``X-Tenant-Id`` ladder above,
and ``kag_common.auth.apply_effective_tenant`` only honours a forwarded licence
for an explicitly-allowlisted delegating subject. Without it, a downstream that
authenticates on a *service* token has no way to know which customer licence
the work belongs to, and its cost events land unattributable — measured at 100%
of karma, hirag and kag-graph events on prod (2026-08-11). The receive side has
existed since the delegation work; only the send side was missing.

Application attribution
-----------------------
``app_id`` propagates the caller's *resolved* application to the downstream as a
bare ``X-App-Id`` header. Like ``license_id`` this is attribution data, never a
credential. ``X-License-Id`` names which customer licence the work belongs to;
``X-App-Id`` names which application asked for it — the two are independent and
billing stores them in separate columns.

Until this parameter existed no KAG-family caller could assert one at all: the
only escape was hand-rolling ``extra={"X-App-Id": ...}`` at every call site,
which no caller did. Measured on the wire 2026-09-10, **68.3% of inference calls
carried no app_id**. The ledger looked far healthier than that (0.26% missing in
``billing_cost_events``) only because ``billing_service``'s ``cost_flusher``
*derives* the app from the licence when the emitter asserted nothing — 42-83% of
attributed dollars per day were derived, not asserted. So a low missing-rate in
the ledger is the SYMPTOM of this gap, not evidence against it.

⛔ **There is deliberately no default, no service self-naming and no "unknown"
sentinel.** A service stamping its own app_id collapses every distinct upstream
origin into one bucket while reading as 100% coverage — strictly worse than an
absence, because an absence can be counted and chased and a collapsed bucket
cannot be un-collapsed. The header is therefore either relayed/asserted or sent
not at all. ``mlx_backend``'s ``_resolve_app_id`` is the live example of the
failure mode: finding no inbound header it substitutes its OWN identity, which
is indistinguishable in the billing record from a real caller.

Who reads it: the receive side is NOT in this library. ``karma_service``
(``src/auth/dependencies.py``, ``get_app_id`` — licence-introspection ``app.id``
if proven, else the inbound ``X-App-Id``) and ``nlp_service``
(``src/auth/identity_context.py``, ``APP_ID_HEADER`` / ``relayable_app_id``)
consume the header; both then pass the value into
:func:`kag_common.metering.emit_cost_event`'s existing ``app_id`` field, which
this library already ships on the cost bus for ``billing_service`` to read. This
change closes the producer half of a contract whose consumers already exist.

On-behalf-of (WS-4)
-------------------
The three-branch ladder above jams a *service* token into ``X-Tenant-Id``,
which clobbers the data tenant — correct only when the target tenant is NOT
carried in the header (e.g. the reconciler, whose tenant is in the payload).
For the on-behalf-of path a caller must assert a *variable customer tenant*
(bare ``X-Tenant-Id``) while proving its *own* service identity separately.
``authorization_service_token`` does exactly that: it sets
``Authorization: Bearer <token>`` and leaves the ``X-Tenant-Id`` ladder
untouched, so the downstream trusts the asserted plain tenant iff the
Authorization subject is on its on-behalf-of allowlist. This is the one
sanctioned use of ``Authorization`` between KAG services.
"""

from __future__ import annotations

__all__ = ["outbound_headers"]


def outbound_headers(
    tenant_id: str | None = None,
    *,
    tenant_token: str | None = None,
    service_token: str | None = None,
    authorization_service_token: str | None = None,
    subject_id: str | None = None,
    license_id: str | None = None,
    app_id: str | None = None,
    tenant_name: str | None = None,
    idempotency_key: str | None = None,
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    """Build standard outbound headers for KAG inter-service hops.

    Always sets ``Content-Type: application/json``. Sets ``X-Tenant-Id`` via the
    three-branch priority ladder (``tenant_token`` → ``service_token`` →
    bare ``tenant_id``). Optional fields are included only when truthy.

    ``authorization_service_token`` (WS-4 on-behalf-of) sets
    ``Authorization: Bearer <token>`` WITHOUT touching the ``X-Tenant-Id``
    ladder — so a caller can assert a variable customer tenant in a bare
    ``X-Tenant-Id`` while proving its own service identity. The downstream
    trusts the asserted tenant iff the Authorization subject is allowlisted.

    ``license_id`` and ``app_id`` are bare attribution headers (``X-License-Id``,
    ``X-App-Id``), never credentials and never ``Bearer``-prefixed. Both follow
    the truthy rule strictly: an empty string sends NO header, because billing
    distinguishes "not provided" from "provided as the empty string" and only
    the former is an honest NULL. Neither is ever defaulted or self-named — see
    the module docstring's "Application attribution" section for why a
    self-named app_id is worse than an absent one.

    ``extra`` is merged last and wins on key conflict — use for one-off headers
    a caller needs that aren't in this shape (e.g. ``Authorization`` for a
    non-KAG downstream that legitimately needs it). Within the KAG mesh,
    ``Authorization`` is reserved for the caller's own auth and should not be
    forwarded between services.
    """
    headers: dict[str, str] = {"Content-Type": "application/json"}

    if tenant_token:
        headers["X-Tenant-Id"] = (
            f"Bearer {tenant_token}" if tenant_token.count(".") >= 2 else tenant_token
        )
    elif service_token:
        headers["X-Tenant-Id"] = f"Bearer {service_token}"
    elif tenant_id:
        headers["X-Tenant-Id"] = tenant_id

    if authorization_service_token:
        headers["Authorization"] = f"Bearer {authorization_service_token}"

    if tenant_name:
        headers["X-Tenant-Name"] = tenant_name
    if subject_id:
        headers["X-Subject-Id"] = subject_id
    if license_id:
        headers["X-License-Id"] = license_id
    if app_id:
        headers["X-App-Id"] = app_id
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key
    if extra:
        headers.update(extra)

    return headers
