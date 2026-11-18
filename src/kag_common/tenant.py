"""Tenant identity primitives — the seam where "no usable tenant" becomes an error.

Product-owner ruling (2026-08-26): **a ``tenant_id`` may NEVER hold a
sentinel.** Every metered row carries a real tenant, forwarded from the actual
requestor.

Before this module, ``kag_common.metering`` violated that in the most damaging
way available: when the caller's tenant was missing it SUBSTITUTED the all-zeros
UUID (``00000000-0000-0000-0000-000000000000``). That value is a *valid* UUID, so
it passed every type check and every dirty-row audit, and it is registered in
``licenses.tenants`` as ``default-anon``, so it also looked legitimate — while
silently mis-attributing cost. A fabricated identity is strictly worse than a
missing one: it reads 100% green on every attribution metric, forever.

Nor did the substitution buy anything. billing_service classifies the nil uuid as
``nil_tenant_id`` and DEAD-LETTERS it (``src/services/_cost_schema.py:115``), so
a nil-tenant emit was never billed — it was quarantined in the DLQ where nobody
was looking. Raising here surfaces the same caller bug at the call site instead.

The replacement is not a better sentinel. It is failing loud:

* :class:`MissingTenantError` — no tenant at all where one is mandatory.
* :class:`InvalidTenantIdError` — a tenant that is present but is not usable.

Both subclass :class:`TenantError` (a :class:`ValueError`), so a caller that
wants to treat "no usable tenant" as one condition can catch the base. This
mirrors ``w2v_common.tenant``, the sibling metering client, so the two lineages
agree on the exception grammar as well as on the wire format.

TWO CHECKS w2v_common MAKES THAT THIS MODULE DELIBERATELY DOES NOT
------------------------------------------------------------------

⚠️ **UUID-format validation.** ``w2v_common.parse_tenant_id`` requires a UUID and
returns a ``uuid.UUID``. Not ported: the kag lineage still emits slug tenants
(``tenant-1``, ``n8n-dev``), so rejecting non-UUID values here would refuse live
traffic from all five consumers. That migration is a separate, coordinated
change.

⚠️ **Rejecting the nil uuid BY VALUE.** w2v_common raises on it. This module
accepts it, and that gap is deliberate and measured, not an oversight.
``ingestion_service`` uses the nil uuid as an intentional, documented,
Prometheus-counted UNATTRIBUTED SINK — ``src/config.py:46``
``UNATTRIBUTED_TENANT_ID`` → ``src/tenancy.py:58`` ``unattributed_tenant()`` →
``src/routes/ingest_routes.py:135`` — so a write whose real owner cannot be
determined "lands somewhere that belongs to NOBODY, so it can be found, counted
and re-tenanted later instead of silently becoming someone's data". It reaches
this library's emitter through ``scrape_metering.py:200``, called from
``submit.py:404``, which is **not wrapped in a try/except**: rejecting nil here
would turn an already-successful, already-persisted scrape into an HTTP 500.

Closing that gap is right, but it is a CROSS-REPO decision — the product-owner
"no sentinel" ruling against ingestion_service's sink design — and it must land
in ingestion_service FIRST, not be imposed from a library that cannot see the
call site. Until then the nil uuid passes through, and billing dead-letters it as
``nil_tenant_id`` exactly as it does today. ⛔ Do not add the check here without
fixing ``ingestion_service`` in the same change.

What this module removes is the FABRICATION: this library inventing a tenant the
caller never supplied. A caller that chooses the sink explicitly, and counts it,
is making a different (and visible) claim.

No dependencies on ``auth``, ``config`` or ``metering`` so every layer can import
it without a cycle.
"""

from __future__ import annotations

__all__ = [
    "InvalidTenantIdError",
    "MissingTenantError",
    "TenantError",
    "require_tenant_id",
]


class TenantError(ValueError):
    """Base for "this request has no usable tenant identity"."""


class MissingTenantError(TenantError):
    """No tenant id was supplied where a real tenant is mandatory.

    Raised INSTEAD OF substituting a default. There is no fallback tenant by
    design — see the module docstring.
    """


class InvalidTenantIdError(TenantError):
    """A tenant id was supplied but is not a usable tenant.

    Currently raised only for a non-``str`` tenant. It also exists so the
    grammar matches ``w2v_common.tenant`` and so the nil-uuid rejection has a
    type to land on once ``ingestion_service``'s sink is fixed — see the module
    docstring.
    """


def require_tenant_id(value: str | None, *, source: str = "tenant_id") -> str:
    """Return ``value`` as a usable tenant id, or raise.

    ``source`` names the origin (``"cost event (ingestion/self_hosted)"``) and
    appears in the exception message so an operator can tell WHICH lane produced
    an unusable tenant.

    Never returns ``None`` or ``""``, and never INVENTS a value. Surrounding
    whitespace is stripped — a tenant forwarded through a header can arrive
    padded, and ``"   "`` is "no tenant", not a tenant whose name is spaces.
    Whitespace-only is the one shape the five consumers' own ``if not tenant_id``
    guards cannot catch, because it is truthy in Python.

    ⚠️ Does NOT reject the nil uuid, and does NOT require a UUID at all. Both
    omissions are deliberate and are argued in the module docstring; read it
    before adding either check.

    :raises MissingTenantError: ``value`` is ``None``, empty, or whitespace-only.
    :raises InvalidTenantIdError: ``value`` is not a ``str``.
    """
    if value is None:
        raise MissingTenantError(f"{source}: no tenant id present")
    if not isinstance(value, str):
        raise InvalidTenantIdError(f"{source}: tenant id has type {type(value).__name__}, not str")
    text = value.strip()
    if not text:
        raise MissingTenantError(f"{source}: tenant id is empty")
    return text
