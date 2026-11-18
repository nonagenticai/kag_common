"""Request-scoped cost attribution: WHICH project / job a unit of work belongs to.

⛔ Owner ruling 2026-10-07: a cost row's ``project_id`` is the **calling app's own
project**, passed explicitly by the caller. Shared services (every kag backend)
do not own projects — they FORWARD the one their caller named. Only when nothing
was named does the cost bus fall back to the tenant-level project
(:func:`tenant_level_project_id`), and that fallback is counted.

This module is the forwarding half:

1. Inbound — :func:`bind_attribution_from_headers` (or
   :class:`AttributionContextMiddleware`, which calls it per request and resets
   afterwards) reads ``X-Project-Id`` / ``X-Job-Id`` and the w2v spellings
   ``X-W2V-Project-Id`` / ``X-W2V-Job-Id``. A valid ``X-W2V-*`` value WINS over
   the generic one: a w2v caller sets the W2V header to its own project and may
   relay an unrelated fr ``X-Project-Id`` alongside it.
2. Ambient — :func:`kag_common.metering.emit_cost_event` reads the bound values
   when its caller passed no explicit ``project_id`` / ``job_id``.
3. Outbound — :func:`attribution_event_hook` (httpx ``event_hooks``) or
   :func:`get_attribution_headers` (for ``outbound_headers(extra=...)``) stamps
   them on the next hop as ``X-Project-Id`` / ``X-Job-Id``.

The same three steps carry WHO ACTED and WHICH APP ASKED:

* ``X-Actor-Id`` — the Keycloak ``sub`` (UUID) of the human who acted, or of the
  calling service's own service account when no human did. Validated strictly
  as a canonical non-nil UUID; a malformed value is treated as ABSENT and counted
  on ``kag_common_actor_header_malformed_total{service}``. ``emit_cost_event``
  stamps the bound actor into ``metadata.actor_id``, falling back to this
  service's own ``SERVICE_ACTOR_ID`` — so a human sub relayed from upstream
  always wins over the service's own sub. Outbound, an unbound actor is
  likewise sent as ``SERVICE_ACTOR_ID`` (0.35.0), so the next hop records the
  CALLING service as actor rather than itself.

  ⛔ 0.36.0: ``SERVICE_ACTOR_ID`` is used ONLY for work the service originates
  itself (no inbound request: celery/background workers, schedulers). While
  handling an inbound request that arrived WITHOUT a valid ``X-Actor-Id`` the
  actor stays ABSENT — on the cost event and outbound — and is counted on
  ``kag_common_actor_missing_total{reason="inbound_without_actor"}``. Filling in
  the service's own id there would hide the caller's gap from billing coverage
  and router enforcement. :class:`AttributionContextMiddleware` (and
  :func:`bind_attribution_from_headers`) mark the context as inbound.
* ``X-App-Id`` — the licences-registry key of the calling application. Relayed
  verbatim after a header-safety screen (printable ASCII, bounded); never
  defaulted, never self-named. Forwarded only — the emitter's ``app_id`` stays
  an explicit argument.

API names mirror ``w2v_common.auth.identity_context`` (0.85.0) where the concept
is the same: ``tenant_level_project_id``, ``parse_attribution_uuid``,
``bind_attribution_from_headers``, ``get_project_id_from_context``.

Values are validated strictly and an invalid one is IGNORED (DEBUG line), never
coerced: an absent project is counted and chased, a fabricated one is billed to
somebody. ``""`` on a ContextVar means UNBOUND.
"""

from __future__ import annotations

import logging
import os
import re
import uuid
from contextvars import ContextVar, Token
from typing import TYPE_CHECKING, Any

from kag_common.metrics import (
    record_actor_header_malformed,
    record_actor_missing,
    resolve_service_label,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    import httpx
    from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger(__name__)

__all__ = [
    "ACTOR_ID_HEADER",
    "APP_ID_HEADER",
    "JOB_ID_HEADER",
    "PROJECT_ID_HEADER",
    "SERVICE_ACTOR_ID_ENV",
    "W2V_JOB_ID_HEADER",
    "W2V_PROJECT_ID_HEADER",
    "AttributionContextMiddleware",
    "attribution_event_hook",
    "bind_attribution_from_headers",
    "clear_attribution_context",
    "get_actor_id_from_context",
    "get_app_id_from_context",
    "get_attribution_headers",
    "get_job_id_from_context",
    "get_project_id_from_context",
    "get_service_actor_id",
    "is_inbound_request_context",
    "resolve_actor",
    "set_inbound_request_context",
    "parse_app_id",
    "parse_attribution_uuid",
    "parse_job_id",
    "set_actor_context",
    "set_app_id_context",
    "set_job_context",
    "set_project_context",
    "tenant_level_project_id",
]

#: Generic wire header naming the calling app's project. Canonical non-nil UUID;
#: OMITTED when unbound — never ``""`` and never a placeholder.
PROJECT_ID_HEADER = "X-Project-Id"
#: Generic wire header naming the job/run the work belongs to. Opaque, bounded.
JOB_ID_HEADER = "X-Job-Id"
#: w2v's spelling of the project header (``w2v_common`` 0.85). Wins when valid.
W2V_PROJECT_ID_HEADER = "X-W2V-Project-Id"
#: w2v's spelling of the job header (``w2v_common`` 0.85). Wins when valid.
W2V_JOB_ID_HEADER = "X-W2V-Job-Id"
#: WHO ACTED: a Keycloak ``sub`` (canonical non-nil UUID) — the human's, else the
#: calling service's own service-account sub. OMITTED when unbound.
ACTOR_ID_HEADER = "X-Actor-Id"
#: WHICH APP ASKED: the licences-registry key. Relayed verbatim; OMITTED when unbound.
APP_ID_HEADER = "X-App-Id"

#: Env var naming THIS service's own Keycloak service-account ``sub`` (a UUID).
#: The actor of record — on the cost event AND on outbound calls — when no
#: inbound/human actor is bound.
SERVICE_ACTOR_ID_ENV = "SERVICE_ACTOR_ID"

#: Upper bound on a relayed app id. Registry keys are short slugs; anything
#: longer is not one, and an unbounded caller value must not ride every hop.
_APP_ID_MAX_LEN = 128

#: Same alphabet as ``w2v_common``'s job id: it rides a header and lands in
#: billing metadata, so no whitespace / control chars / injection surface.
_JOB_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

_project_id_var: ContextVar[str] = ContextVar("kag_attribution_project_id", default="")
_job_id_var: ContextVar[str] = ContextVar("kag_attribution_job_id", default="")
_actor_id_var: ContextVar[str] = ContextVar("kag_attribution_actor_id", default="")
_app_id_var: ContextVar[str] = ContextVar("kag_attribution_app_id", default="")
#: True while handling an inbound request (set by the middleware / header bind).
#: Gates the ``SERVICE_ACTOR_ID`` fallback: service-originated work only.
_inbound_request_var: ContextVar[bool] = ContextVar("kag_attribution_inbound", default=False)

#: ``kag_common_actor_missing_total`` reason values (mirrors ``metrics``).
ACTOR_MISSING_INBOUND = "inbound_without_actor"
ACTOR_MISSING_NO_SERVICE_ACTOR = "no_service_actor"


def parse_attribution_uuid(raw: object) -> str | None:
    """Strictly parse a project UUID; ``None`` for anything else.

    Accepts a :class:`uuid.UUID` or the CANONICAL 36-char hyphenated string (any
    case; returned lower-cased). ``{...}``, ``urn:uuid:`` and bare 32-hex forms
    are refused so every hop compares one spelling. The nil UUID is refused: it
    is the placeholder the attribution contract forbids.
    """
    if isinstance(raw, uuid.UUID):
        return None if raw.int == 0 else str(raw)
    if not isinstance(raw, str):
        return None
    value = raw.strip()
    if not value:
        return None
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return None
    canonical = str(parsed)
    if canonical != value.lower() or parsed.int == 0:
        return None
    return canonical


def parse_job_id(raw: object) -> str | None:
    """Strictly parse a job id; ``None`` for anything else.

    Opaque but bounded: 1-128 chars of ``[A-Za-z0-9._:-]``, starting
    alphanumeric. A :class:`uuid.UUID` is accepted and rendered canonically.
    Surrounding whitespace is stripped; nothing else is coerced.
    """
    if isinstance(raw, uuid.UUID):
        return str(raw)
    if not isinstance(raw, str):
        return None
    value = raw.strip()
    if not value or not _JOB_ID_RE.match(value):
        return None
    return value


def parse_app_id(raw: object) -> str | None:
    """Screen a relayable app id; ``None`` for anything that cannot be relayed.

    Same rule as ``nlp_service``'s ``relayable_app_id``: spaces/tabs at the edges
    are stripped (never a bare ``.strip()``, which would REPAIR a trailing CR/LF
    into a clean value), then the whole value must be printable ASCII and at
    most 128 chars. No default, no repair: an unrelayable value is an absence.
    """
    if not isinstance(raw, str):
        return None
    value = raw.strip(" \t")
    if not value or len(value) > _APP_ID_MAX_LEN:
        return None
    if not all(" " <= char <= "~" for char in value):
        return None
    return value


def tenant_level_project_id(tenant_id: object) -> str | None:
    """The tenant-level project id for a project-less caller (owner ruling 2026-10-07).

    The tenant uuid's 32 hex digits REVERSED, re-formatted 8-4-4-4-12 — byte for
    byte ``billing_service`` ``tenancy.tenant_level_project_id`` and
    ``w2v_common``'s helper of the same name (fixed vector
    ``0195f48b-d000-7000-8000-000000000100`` ->
    ``00100000-0000-0008-0007-000db84f5910``). Deliberately never the raw tenant
    id: billing refuses ``project_id == tenant_id`` as a forged project.

    ``None`` for a missing, non-UUID (kag still has legacy string tenants such as
    ``n8n-dev``) or nil tenant — a project derived from a non-tenant books spend
    to a project nobody owns, which is worse than sending none.
    """
    if isinstance(tenant_id, uuid.UUID):
        parsed = tenant_id
    elif isinstance(tenant_id, str):
        try:
            parsed = uuid.UUID(tenant_id.strip())
        except ValueError:
            return None
    else:
        return None
    if parsed.int == 0:
        return None
    rev = parsed.hex[::-1]
    return f"{rev[:8]}-{rev[8:12]}-{rev[12:16]}-{rev[16:20]}-{rev[20:]}"


def set_project_context(project_id: uuid.UUID | str | None) -> None:
    """Bind (or with ``None`` clear) the project for this execution context.

    Strict: a non-canonical or nil UUID raises ``ValueError`` — a caller holding
    a bad project id has a bug, and dropping it silently would bill the
    tenant-level project instead.
    """
    if project_id is None:
        _project_id_var.set("")
        return
    canonical = parse_attribution_uuid(project_id)
    if canonical is None:
        raise ValueError(f"not a canonical non-nil project uuid: {project_id!r}")
    _project_id_var.set(canonical)


def set_job_context(job_id: uuid.UUID | str | None) -> None:
    """Bind (or with ``None`` clear) the job for this execution context. Strict."""
    if job_id is None:
        _job_id_var.set("")
        return
    parsed = parse_job_id(job_id)
    if parsed is None:
        raise ValueError(f"not a valid job id: {job_id!r}")
    _job_id_var.set(parsed)


def set_actor_context(actor_id: uuid.UUID | str | None) -> None:
    """Bind (or with ``None`` clear) the acting Keycloak sub. Strict.

    A non-canonical or nil UUID raises ``ValueError``: a caller holding a bad sub
    has a bug, and a dropped human sub would be silently replaced by the
    service's own ``SERVICE_ACTOR_ID`` at emit time.
    """
    if actor_id is None:
        _actor_id_var.set("")
        return
    canonical = parse_attribution_uuid(actor_id)
    if canonical is None:
        raise ValueError(f"not a canonical non-nil actor uuid: {actor_id!r}")
    _actor_id_var.set(canonical)


def set_app_id_context(app_id: str | None) -> None:
    """Bind (or with ``None`` clear) the calling app's registry key. Strict."""
    if app_id is None:
        _app_id_var.set("")
        return
    parsed = parse_app_id(app_id)
    if parsed is None:
        raise ValueError(f"not a relayable app id: {app_id!r}")
    _app_id_var.set(parsed)


def get_service_actor_id() -> str | None:
    """``SERVICE_ACTOR_ID`` as a canonical non-nil UUID, else ``None``.

    Read at CALL time (package env convention). A set-but-malformed value is a
    deployment bug: WARNING, and treated as absent — never shipped, never coerced.
    """
    raw = os.getenv(SERVICE_ACTOR_ID_ENV, "").strip()
    if not raw:
        return None
    parsed = parse_attribution_uuid(raw)
    if parsed is None:
        logger.warning(
            "%s is set but is not a canonical non-nil UUID; ignoring it", SERVICE_ACTOR_ID_ENV
        )
    return parsed


def set_inbound_request_context(inbound: bool) -> None:
    """Mark (or unmark) this context as handling an inbound request.

    Set by :class:`AttributionContextMiddleware` and
    :func:`bind_attribution_from_headers`; exposed for non-ASGI request entry
    points (e.g. a hand-rolled consumer that binds headers itself).
    """
    _inbound_request_var.set(bool(inbound))


def is_inbound_request_context() -> bool:
    """True while handling an inbound request."""
    return _inbound_request_var.get()


def resolve_actor() -> tuple[str | None, str | None]:
    """WHO ACTED for this context: ``(actor_id, missing_reason)``.

    1. The bound actor (inbound ``X-Actor-Id`` / :func:`set_actor_context`).
    2. Inbound request with no valid actor -> ``(None, "inbound_without_actor")``.
       ``SERVICE_ACTOR_ID`` is NOT substituted: the gap is the caller's.
    3. Service-originated work -> ``SERVICE_ACTOR_ID``.
    4. Neither -> ``(None, "no_service_actor")``.

    Does not count; callers record ``missing_reason`` with their own label.
    """
    bound = _actor_id_var.get()
    if bound:
        return bound, None
    if _inbound_request_var.get():
        return None, ACTOR_MISSING_INBOUND
    service_actor = get_service_actor_id()
    if service_actor:
        return service_actor, None
    return None, ACTOR_MISSING_NO_SERVICE_ACTOR


def get_actor_id_from_context() -> str:
    """The bound actor sub (canonical UUID string), or ``""`` when unbound."""
    return _actor_id_var.get()


def get_app_id_from_context() -> str:
    """The bound app id, or ``""`` when unbound."""
    return _app_id_var.get()


def get_project_id_from_context() -> str:
    """The bound project id (canonical UUID string), or ``""`` when unbound."""
    return _project_id_var.get()


def get_job_id_from_context() -> str:
    """The bound job id, or ``""`` when unbound."""
    return _job_id_var.get()


def clear_attribution_context() -> None:
    """Unbind project, job, actor and app (tests; workers between units of work)."""
    _project_id_var.set("")
    _job_id_var.set("")
    _actor_id_var.set("")
    _app_id_var.set("")
    _inbound_request_var.set(False)


def _header(headers: Mapping[str, str], name: str) -> str:
    """Case-tolerant header read for Starlette ``Headers`` and plain dicts."""
    value = headers.get(name)
    if value is None:
        value = headers.get(name.lower())
    return (value or "").strip()


def _first_valid(headers: Mapping[str, str], names: tuple[str, ...], parse: Any) -> str:
    """First header in ``names`` whose value parses; ``""`` when none does."""
    for name in names:
        raw = _header(headers, name)
        if not raw:
            continue
        parsed = parse(raw)
        if parsed is not None:
            return parsed
        logger.debug("attribution: ignoring malformed %s", name)
    return ""


def _resolve_from_headers(headers: Mapping[str, str]) -> tuple[str, str, str, str]:
    """``(project, job, actor, app)`` from inbound headers; ``""`` = absent."""
    project = _first_valid(
        headers, (W2V_PROJECT_ID_HEADER, PROJECT_ID_HEADER), parse_attribution_uuid
    )
    job = _first_valid(headers, (W2V_JOB_ID_HEADER, JOB_ID_HEADER), parse_job_id)
    actor = ""
    raw_actor = _header(headers, ACTOR_ID_HEADER)
    if raw_actor:
        actor = parse_attribution_uuid(raw_actor) or ""
        if not actor:
            # Present but malformed: treated as ABSENT (emit falls back to the
            # service's own sub) and COUNTED, so the sending caller can be chased.
            logger.debug("attribution: ignoring malformed %s", ACTOR_ID_HEADER)
            record_actor_header_malformed()
    app = _first_valid(headers, (APP_ID_HEADER,), parse_app_id)
    return project, job, actor, app


def bind_attribution_from_headers(headers: Mapping[str, str]) -> tuple[str, str]:
    """Bind project/job for this execution context from an inbound request.

    ``X-W2V-Project-Id`` / ``X-W2V-Job-Id`` win over ``X-Project-Id`` /
    ``X-Job-Id`` when present AND valid; a malformed value is ignored (DEBUG),
    never coerced, and the next spelling is tried. The headers DEFINE the
    request's attribution: a value absent from every spelling binds ``""``
    (unbound) rather than inheriting whatever an earlier unit of work left.

    ``X-Actor-Id`` and ``X-App-Id`` are bound the same way (a malformed actor is
    dropped and counted); they are not part of the return value, which keeps
    its original two-tuple shape for existing callers. The context is marked as
    an inbound request, so ``SERVICE_ACTOR_ID`` is not substituted for a missing
    actor (see :func:`resolve_actor`).

    Honoured from any caller that reached this point: a project names a scope
    within the tenant the request already authenticated as, not a principal,
    and billing independently refuses a project that encodes another tenant.

    :returns: ``(project_id, job_id)`` as bound (``""`` = unbound).
    """
    project, job, actor, app = _resolve_from_headers(headers)
    _project_id_var.set(project)
    _job_id_var.set(job)
    _actor_id_var.set(actor)
    _app_id_var.set(app)
    _inbound_request_var.set(True)
    return project, job


def _outbound_actor() -> str | None:
    """Actor for an outbound hop per :func:`resolve_actor`; counts an absence."""
    actor, missing = resolve_actor()
    if missing is not None:
        record_actor_missing(resolve_service_label(), missing)
    return actor


def _non_actor_headers() -> dict[str, str]:
    out: dict[str, str] = {}
    project = _project_id_var.get()
    if project:
        out[PROJECT_ID_HEADER] = project
    job = _job_id_var.get()
    if job:
        out[JOB_ID_HEADER] = job
    app = _app_id_var.get()
    if app:
        out[APP_ID_HEADER] = app
    return out


def get_attribution_headers() -> dict[str, str]:
    """``X-Project-Id`` / ``X-Job-Id`` / ``X-Actor-Id`` / ``X-App-Id`` for the bound
    values; unbound keys OMITTED.

    ``X-Actor-Id`` follows :func:`resolve_actor`: the bound actor; else, for
    service-originated work only, ``SERVICE_ACTOR_ID``; else omitted and counted
    on ``kag_common_actor_missing_total`` (``inbound_without_actor`` while
    handling an inbound request — never papered over with the service's own id).

    For hand-built header dicts, e.g.
    ``outbound_headers(..., extra=get_attribution_headers())``.
    """
    out = _non_actor_headers()
    actor = _outbound_actor()
    if actor:
        out[ACTOR_ID_HEADER] = actor
    return out


async def attribution_event_hook(request: httpx.Request) -> None:
    """httpx ``event_hooks={"request": [attribution_event_hook]}`` handler.

    Stamps the bound project/job/actor/app onto each outbound request, read PER REQUEST
    from the ContextVars — so a cached, shared ``AsyncClient`` attributes every
    call to the request that made it, not to whoever warmed the cache. A header
    the caller already set on the request wins (an explicit per-call project is
    the caller's to state). Unbound values add no header. ``X-Actor-Id``
    follows :func:`resolve_actor` (``SERVICE_ACTOR_ID`` for service-originated
    work only); a caller-set ``X-Actor-Id`` is neither overridden nor counted.
    """
    for name, value in _non_actor_headers().items():
        if name not in request.headers:
            request.headers[name] = value
    if ACTOR_ID_HEADER not in request.headers:
        actor = _outbound_actor()
        if actor:
            request.headers[ACTOR_ID_HEADER] = actor


class AttributionContextMiddleware:
    """Pure-ASGI middleware: bind project/job/actor/app from inbound headers per request.

    Binds via :func:`bind_attribution_from_headers` before the app runs and
    RESETS the ContextVars afterwards, so nothing leaks into the next request
    served on the same task. Pure ASGI (not ``BaseHTTPMiddleware``) so the
    binding is visible to the endpoint and to any task it spawns.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        headers = {
            k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])
        }
        project, job, actor, app = _resolve_from_headers(headers)
        project_token: Token[str] = _project_id_var.set(project)
        job_token: Token[str] = _job_id_var.set(job)
        actor_token: Token[str] = _actor_id_var.set(actor)
        app_token: Token[str] = _app_id_var.set(app)
        inbound_token: Token[bool] = _inbound_request_var.set(True)
        try:
            await self.app(scope, receive, send)
        finally:
            _project_id_var.reset(project_token)
            _job_id_var.reset(job_token)
            _actor_id_var.reset(actor_token)
            _app_id_var.reset(app_token)
            _inbound_request_var.reset(inbound_token)
