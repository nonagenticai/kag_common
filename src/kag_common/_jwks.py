"""Shared JWKS admission for this package's two RS256 verifiers.

``attestation.AttestationVerifier`` and ``internal_token.InternalTokenVerifier`` are
independent verifiers of independent token families, but they resolve their signing keys the
same way: fetch a JWKS document over httpx, build a ``kid -> key`` cache from it, and decode
with ``algorithms=["RS256"]``. Both document the same contract about failure — attestation's
``verify()`` "always returns a ``VerificationResult``", internal_token's "raises
``InvalidInternalTokenError`` on any failure" — and both used to break it in the *same six
ways*, through the one line that turned a JWKS entry into a cached key.

The two were fixed a week apart, the second time by copying the first. This module exists so
the third verifier does not have to be fixed a third time: the admission rule lives here once,
and both callers get it by construction rather than by remembering to.

What each caller keeps for itself is what actually differs — the fetch, the refresh cooldown,
the cache object, the reason code an unusable key ends up producing — because those are
policy, not admission.
"""

from __future__ import annotations

import logging
from typing import Any

import jwt
from jwt.algorithms import get_default_algorithms

#: Signature algorithm. RS256 only — no HMAC family, to keep an algorithm-confusion attack
#: (a public key presented back as an HMAC secret) structurally unavailable.
JWS_ALGORITHM = "RS256"

#: PyJWT's OWN acceptance test for "is this key material usable for :data:`JWS_ALGORITHM`",
#: reused verbatim rather than reimplemented as an ``isinstance(key, RSAPublicKey)`` check.
#: ``jwt.decode`` calls exactly this function on the key it is handed, so borrowing it here
#: makes the cache-admission rule and the decode-time rule the same rule by construction —
#: an ``isinstance`` check would be a second opinion that can drift from PyJWT's. It is the
#: identity function on a key RS256 can use (measured: ``prepare_key(rsa_pub) is rsa_pub``),
#: so admitting through it changes nothing on the happy path.
_JWS_KEY_PREPARER = get_default_algorithms()[JWS_ALGORITHM].prepare_key


def usable_keys_by_kid(doc: Any, *, source: str, log: logging.Logger) -> dict[str, Any]:
    """Turn a parsed JWKS body into the ``kid -> key`` entries usable for :data:`JWS_ALGORITHM`.

    Raises **only** ``ValueError``, and only for a document that is not a JWKS at all. Every
    per-ENTRY failure is skipped, never raised: see SKIP, not abort below. Both callers already
    handle ``ValueError`` (attestation maps it to a ``VerificationResult``, internal_token to
    ``InvalidInternalTokenError``), so this function cannot break either one's contract.

    ``source`` names the caller in the operator-facing warning; ``log`` is the caller's own
    logger, so the warning still arrives under ``kag_common.attestation`` /
    ``kag_common.internal_token`` rather than under this private module.

    THE SIX ESCAPES THIS CLOSES. Each was measured against the naive loop both callers used
    to run (``for jwk in doc.get("keys", []): kid = jwk.get("kid") ...
    self._keys[kid] = jwt.PyJWK.from_dict(jwk).key``), and none of the six raises a
    ``PyJWTError`` — which is why widening a downstream ``except`` would not have caught them:

      1. A JWKS body served as a JSON **array** (or scalar) makes ``doc.get`` an
         ``AttributeError``.
      2. ``{"keys": 42}`` — a non-iterable ``keys`` — makes the ``for`` a ``TypeError:
         'int' object is not iterable``.
      3. ``{"keys": [42]}`` — a non-object ENTRY — makes ``jwk.get`` an ``AttributeError``.
      4. An UNHASHABLE ``kid`` (``{"kid": {"a": 1}}`` or ``{"kid": ["a"]}``) is truthy, so it
         passes a ``if not kid`` screen; the entry is a perfectly valid RSA key, so it also
         clears the key-parse guard without that guard ever firing — and then the CACHE
         ASSIGNMENT raises ``TypeError: cannot use 'dict' as a dict key``. This is the one
         that hides one line past the guard, and it is why the check below is
         ``isinstance(kid, str)`` and not merely a truthiness test.
      5. A well-formed entry of the WRONG ALGORITHM FAMILY — a ``kty: EC`` P-256 key, i.e.
         exactly what an ES256 rotation produces — parses, is cached, and then makes
         ``RSAAlgorithm.prepare_key`` raise a bare ``TypeError`` ("Expecting a PEM-formatted
         key") from inside ``jwt.decode``. Nothing about that JWKS is malformed, so no amount
         of validating the DOCUMENT would have caught it.
      6. (attestation only, but structural) an entry whose ``kty`` is unsupported or whose
         parameters do not parse raises ``InvalidKeyError``/``PyJWKError``; those ARE
         ``PyJWTError``s and internal_token's ladder did catch them — but by ABORTING the
         whole refresh. See SKIP, not abort.

    RFC 7517 §4.5 defines ``kid`` as a string, so dropping a non-string one loses nothing: a
    token header's ``kid`` could never match it. Verified against PyJWT rather than assumed —
    PyJWT rejects a non-string ``kid`` on both mint and read (``InvalidTokenError: Key ID
    header parameter must be a string``), so no reachable token can name such an entry.

    BREADTH. The per-entry ``except`` catches four NAMED types, not bare ``Exception``.
    ``Exception`` would also swallow ``AttributeError``, ``NameError`` and ``ImportError``,
    i.e. exactly the programming errors in this module that must stay loud, and would make a
    future defect here invisible (it would present as "unknown key" forever). The four are
    each a way ATTACKER-ADJACENT INPUT — a key entry we did not write — fails to become a
    usable RS256 key, and nothing else: ``PyJWTError`` (unsupported/invalid ``kty``),
    ``ValueError`` (bad base64 / parameter values; ``binascii.Error`` subclasses it),
    ``TypeError`` (right JWKS, wrong algorithm family), ``KeyError`` (a required JWK member
    such as ``k`` or ``e`` absent). The breadth is SCOPED to the single expression, which is
    what keeps it honest — it cannot swallow anything else this function does.

    SKIP, not abort. The behaviour both callers had was to abort the whole refresh on the
    first bad entry, so one ES256 key added beside the RS256 one would take every ``kid`` down
    at once. Skipping keeps every USABLE key loadable and leaves the unusable ``kid`` resolving
    to ``None``, which fails closed identically — UNKNOWN_KEY for attestation, "no signing key
    for kid" for internal_token.

    WHAT THIS DOES NOT DO. It closes the KEY-DRIVEN raises and only those. It does not make
    either caller's decode ladder correct: those had a PAYLOAD-DRIVEN hole no key-side guard
    can reach — a non-numeric, non-string ``exp``/``nbf``/``iat`` escaping ``jwt.decode`` as a
    bare ``TypeError``. That hole is now closed in both callers, by an ``except TypeError``
    arm scoped to the decode plus the ``audience`` precondition that arm requires to be
    honest (:mod:`kag_common._audience`) — see ``attestation.AttestationVerifier.verify``.
    """
    # A JWKS served as a JSON array (or scalar) would make ``doc.get`` an AttributeError,
    # which neither caller's except-ladder handles. Raised as ValueError, which both do.
    if not isinstance(doc, dict):
        raise ValueError(f"JWKS endpoint returned {type(doc).__name__}, expected an object")
    entries = doc.get("keys", [])
    if not isinstance(entries, list):
        raise ValueError(f"JWKS 'keys' is {type(entries).__name__}, expected an array")

    keys: dict[str, Any] = {}
    for jwk in entries:
        if not isinstance(jwk, dict):
            continue
        kid = jwk.get("kid")
        if not isinstance(kid, str) or not kid:
            continue
        try:
            key = _JWS_KEY_PREPARER(jwt.PyJWK.from_dict(jwk).key)
        except (jwt.PyJWTError, ValueError, TypeError, KeyError) as exc:
            # WARNING, not debug: this is a configured JWKS serving a key the verifier cannot
            # use. It is an operator-actionable misconfiguration, and the only signal that a
            # kid is about to start reporting "no signing key".
            log.warning(
                "%s JWKS entry is not a usable %s key; skipping",
                source,
                JWS_ALGORITHM,
                extra={"kid": kid, "kty": jwk.get("kty"), "error": str(exc)},
            )
            continue
        keys[kid] = key
    return keys
