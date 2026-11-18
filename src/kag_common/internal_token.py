"""Verify license-authz internal tokens (Lane F1) — the consumer side.

license-authz mints short-lived RS256 JWTs for no-SPIFFE / hostNetwork callers
(the ``alloy`` DaemonSet today, on-host agents tomorrow) and serves the matching
public key at ``GET /jwks``. Every consuming service must verify those tokens
*locally* — no hot-path network call on the happy path — which is what this
module provides: a process-scoped verifier that caches the JWKS by ``kid`` and
re-fetches once on a cache miss (a key rotation).

This is the verify side of ``license-authz/src/internal_token.py``; the exact
checks are pinned by that repo's ``test_verify_contract_roundtrip``: fetch JWKS →
pick the key by ``kid`` → decode with ``RS256`` + issuer + audience, requiring
``exp`` and ``iss``. Mirrors ``license-authz/src/jwt_mode.py`` (``JwksCache`` +
``verify_jwt``) but is async-native (httpx + cachetools, kag_common's idiom)
instead of PyJWKClient's blocking urllib fetch, so it never stalls a consumer's
event loop. It **fails closed**: any signature/claim/fetch error raises
``InvalidInternalTokenError`` and the caller must treat that as a 401.

Usage (build one verifier at startup, reuse it so the JWKS cache survives):

    from kag_common.internal_token import InternalTokenVerifier

    verifier = InternalTokenVerifier(jwks_url=settings.internal_token_jwks_url)
    try:
        verified = await verifier.verify(token)
    except InvalidInternalTokenError:
        return unauthorized_response("invalid internal token")
    tenant_id = verified.tenant_id
    # ... on lifespan shutdown:
    await verifier.aclose()
"""

from __future__ import annotations

import logging
from collections.abc import Collection
from dataclasses import dataclass
from typing import Any

import httpx
import jwt
from cachetools import TTLCache

from kag_common._audience import checked_audience
from kag_common._jwks import JWS_ALGORITHM, usable_keys_by_kid

logger = logging.getLogger(__name__)

__all__ = [
    "InternalTokenVerifier",
    "InvalidInternalTokenError",
    "VerifiedInternalToken",
]

# Default contract constants from license-authz's issuer settings. These are
# fixed protocol values (not environment-specific URLs), so they default here;
# ``jwks_url`` has no default — the consumer supplies it from gitops env, per the
# config-externalization policy (see jwt_mode.py: "URLs from env, no fallback").
_DEFAULT_ISSUER = "license-authz"
_DEFAULT_AUDIENCE = "internal"
_DEFAULT_CACHE_TTL = 600

# Tight timeouts mirror kag_common.auth's introspect client: the JWKS fetch is
# off the happy path (cache miss only) but must never hang a request.
_JWKS_TIMEOUT = httpx.Timeout(2.0, connect=1.0, read=2.0, write=2.0, pool=1.0)
_JWKS_LIMITS = httpx.Limits(max_keepalive_connections=10, max_connections=20, keepalive_expiry=30.0)


@dataclass
class VerifiedInternalToken:
    """A successfully verified internal token. Mirrors ``jwt_mode.VerifiedClaims``."""

    sub: str
    tenant_id: str | None
    raw: dict[str, Any]


class InvalidInternalTokenError(Exception):
    """Signature invalid, expired, wrong iss/aud, unknown kid, or JWKS unreachable.

    The verifier fails closed: callers MUST map this to a 401.
    """


class InternalTokenVerifier:
    """Verify license-authz internal tokens against a cached JWKS.

    Build one per process at startup and reuse it — the by-``kid`` key cache
    survives across requests, so steady-state verification does no network I/O.
    A cache miss (unknown / rotated ``kid``) triggers exactly one JWKS re-fetch.
    """

    def __init__(
        self,
        jwks_url: str,
        *,
        issuer: str = _DEFAULT_ISSUER,
        audience: str | Collection[str] = _DEFAULT_AUDIENCE,
        cache_ttl: int = _DEFAULT_CACHE_TTL,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not jwks_url:
            raise ValueError("InternalTokenVerifier requires a jwks_url (no source-side default)")
        self.jwks_url = jwks_url
        self.issuer = issuer
        # TYPE-checked, and previously not checked AT ALL -- not even for truthiness, which
        # ``AttestationVerifier`` at least had. Every bad shape was a permanent, silent auth
        # outage on every token: measured here, ``audience=123`` raised a bare ``TypeError``
        # out of ``verify()`` (past the never-raises contract in this class's docstring),
        # ``audience=""`` and ``audience=b"internal"`` gave "Audience doesn't match", and
        # ``audience=None`` gave "Invalid audience" -- the last one silently DISABLING the
        # audience check for a token that carries no ``aud`` at all, which is not a mode this
        # verifier should be able to be wired into by accident. It is also the precondition
        # the ``except TypeError`` arm below depends on; see :mod:`kag_common._audience`.
        self.audience = checked_audience(audience, owner="InternalTokenVerifier")
        # kid -> signing key object (the public key built from the served JWK).
        self._keys: TTLCache[str, Any] = TTLCache(maxsize=16, ttl=cache_ttl)
        # An injected client is borrowed (caller owns it); a lazily-built one is ours.
        self._client = client
        self._owns_client = client is None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=_JWKS_TIMEOUT, limits=_JWKS_LIMITS)
            self._owns_client = True
        return self._client

    async def _refresh_keys(self) -> None:
        """Fetch the JWKS and rebuild the by-kid key cache.

        Raises only what ``verify()``'s caught tuple already handles: ``httpx.HTTPError`` on
        transport/status, ``ValueError`` on a body that is not a usable JWKS. An individual
        key ENTRY never raises out of here — admission is
        :func:`kag_common._jwks.usable_keys_by_kid`, which is where the six ways a JWKS entry
        used to escape this module's "raise ``InvalidInternalTokenError`` on any failure"
        contract are documented and closed. The same six escaped ``attestation.verify()``
        through the same one-line loop; sharing the admission rule is what stops the next
        verifier having to rediscover them.
        """
        resp = await self._get_client().get(self.jwks_url)
        resp.raise_for_status()
        # Merged, not replaced: an entry that has become unusable stops being served rather
        # than evicting the keys that are still good, and the TTLCache expires it on its own.
        for kid, key in usable_keys_by_kid(
            resp.json(), source="internal-token", log=logger
        ).items():
            self._keys[kid] = key

    async def verify(self, token: str) -> VerifiedInternalToken:
        """Verify signature + iss + aud + exp. Raise ``InvalidInternalTokenError`` on any failure."""
        try:
            kid = jwt.get_unverified_header(token).get("kid")
            if not kid:
                raise InvalidInternalTokenError("token header has no kid")
            key = self._keys.get(kid)
            if key is None:
                # Unknown kid: refresh once (handles key rotation), then retry.
                await self._refresh_keys()
                key = self._keys.get(kid)
            if key is None:
                raise InvalidInternalTokenError(f"no signing key for kid {kid!r}")
            try:
                claims = jwt.decode(
                    token,
                    key,
                    # The SAME constant admission screens against, so the cache invariant and
                    # the decode rule cannot drift apart into "cached a key decode will not
                    # accept".
                    algorithms=[JWS_ALGORITHM],
                    issuer=self.issuer,
                    audience=self.audience,
                    options={"require": ["exp", "iss"]},
                )
            # PAYLOAD-DRIVEN and NOT a ``PyJWTError``, so the outer tuple never matched it:
            # PyJWT's ``_validate_exp``/``_validate_nbf``/``_validate_iat`` each do
            # ``int(claim)`` catching only ``ValueError``, so a non-numeric NON-STRING time
            # claim escapes as a bare ``TypeError``. Measured on pyjwt 2.13 through a
            # correctly-signed token: ``exp``/``nbf``/``iat`` of ``[1]`` or ``{}``, and
            # ``nbf``/``iat`` of ``null``, all raised ``TypeError: int() argument must be...``
            # out of this method -- past a docstring that says it raises
            # ``InvalidInternalTokenError`` on ANY failure.
            #
            # SCOPED TO THE DECODE, not added to the outer tuple, and that is the point rather
            # than tidiness. ``jwt.decode`` raises the same bare ``TypeError`` for a bad
            # ``audience`` ARGUMENT (checked before any claim), so an unscoped arm would
            # convert one mis-wired verifier into "every internal token is invalid" forever.
            # ``checked_audience`` in ``__init__`` removes that cause; this narrow placement
            # keeps the arm from also swallowing a ``TypeError`` raised by
            # ``get_unverified_header`` or the JWKS refresh above, which are this module's own
            # code and must stay loud.
            except TypeError as e:
                raise InvalidInternalTokenError(str(e)) from e
        except InvalidInternalTokenError:
            raise
        except (jwt.PyJWTError, httpx.HTTPError, OSError, ValueError, KeyError) as e:
            # Bad signature/claims, JWKS unreachable/malformed, socket error — all fail closed.
            raise InvalidInternalTokenError(str(e)) from e

        return VerifiedInternalToken(
            sub=claims.get("sub", ""),
            tenant_id=claims.get("tenant_id"),
            raw=claims,
        )

    async def aclose(self) -> None:
        """Close the owned httpx client (call from lifespan shutdown). No-op for a borrowed one."""
        if self._owns_client and self._client is not None and not self._client.is_closed:
            await self._client.aclose()
        if self._owns_client:
            self._client = None
