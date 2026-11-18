"""Tests for the Lane F1 internal-token verifier (RS256 + cached JWKS).

Pure-unit: an ephemeral RS256 keypair signs tokens exactly the way
``license-authz/src/internal_token.py::issue_internal_token`` does, and an
``httpx.MockTransport`` serves the matching JWKS (built like its ``build_jwks``).
That locks the verify contract pinned by license-authz's
``test_verify_contract_roundtrip`` by construction — no live issuer needed.
"""

from __future__ import annotations

import json
import time
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from kag_common.internal_token import (
    InternalTokenVerifier,
    InvalidInternalTokenError,
    VerifiedInternalToken,
)

ISSUER = "license-authz"
AUDIENCE = "internal"
KID = "internal-test-1"
JWKS_URL = "http://license-authz.istio-system.svc/jwks"


@pytest.fixture(scope="module")
def keypair():
    """An ephemeral RS256 keypair (the issuer's signing key)."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def other_key():
    """A second, unrelated keypair — for the bad-signature case."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwks_doc(public_key, kid: str = KID) -> dict[str, Any]:
    """Public JWKS document, shaped exactly like license-authz build_jwks()."""
    jwk = json.loads(RSAAlgorithm.to_jwk(public_key))
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return {"keys": [jwk]}


def _issue(
    private_key,
    *,
    kid: str = KID,
    issuer: str = ISSUER,
    audience: str = AUDIENCE,
    sub: str = "alloy-sa",
    tenant_id: str | None = None,
    ttl: int = 300,
    now: int | None = None,
    drop: tuple[str, ...] = (),
) -> str:
    """Sign a token like issue_internal_token(); ``drop`` omits required claims."""
    iat = int(time.time()) if now is None else now
    claims: dict[str, Any] = {
        "iss": issuer,
        "aud": audience,
        "sub": sub,
        "iat": iat,
        "exp": iat + ttl,
    }
    if tenant_id:
        claims["tenant_id"] = tenant_id
    for k in drop:
        claims.pop(k, None)
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": kid})


def _verifier(
    public_key,
    *,
    kid: str = KID,
    fail: bool = False,
) -> tuple[InternalTokenVerifier, list[httpx.Request]]:
    """Build a verifier wired to a MockTransport JWKS; return (verifier, request log)."""
    seen: list[httpx.Request] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if fail:
            raise httpx.ConnectError("jwks unreachable")
        return httpx.Response(200, json=_jwks_doc(public_key, kid))

    client = httpx.AsyncClient(transport=httpx.MockTransport(_handler))
    return InternalTokenVerifier(JWKS_URL, client=client), seen


def _verifier_serving(doc: Any) -> InternalTokenVerifier:
    """A verifier whose JWKS endpoint serves ``doc`` verbatim — including non-JWKS shapes."""
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=doc))
    )
    return InternalTokenVerifier(JWKS_URL, client=client)


# --------------------------------------------------------------------------- #
# construction
# --------------------------------------------------------------------------- #
def test_requires_jwks_url():
    with pytest.raises(ValueError, match="jwks_url"):
        InternalTokenVerifier("")


# ``expect`` pins the MESSAGE, not merely "a ValueError" — see the sibling table
# in ``test_attestation.py`` for the mutation that survived a looser match.
@pytest.mark.parametrize(
    ("audience", "expect"),
    [
        pytest.param(123, r"jwt\.decode raises TypeError", id="int"),
        pytest.param(3.5, r"jwt\.decode raises TypeError", id="float"),
        pytest.param(b"internal", r"bytes is iterable", id="bytes"),
        pytest.param("", r"non-empty audience", id="empty-str"),
        pytest.param(None, r"jwt\.decode raises TypeError", id="none"),
        pytest.param([], r"non-empty audience", id="empty-list"),
        pytest.param([123], r"every audience member", id="list-of-int"),
    ],
)
def test_a_bad_audience_is_refused_at_construction(audience, expect):
    """This constructor screened ``audience`` for NOTHING before this change.

    Not even truthiness — ``AttestationVerifier`` at least had that. Every
    parameter here was measured through ``verify()`` with a correctly-signed,
    otherwise-valid token and produced a PERMANENT outage on every token rather
    than a rejection of the offending one: ``123``/``3.5`` a bare ``TypeError``
    escaping the "raises ``InvalidInternalTokenError`` on any failure" contract
    outright, ``b"internal"``/``""``/``[]``/``[123]`` "Audience doesn't match",
    and ``None`` "Invalid audience" (or, for a token with no ``aud`` at all, no
    audience check whatsoever — a security-relevant mode that must not be
    reachable by a typo in a settings file).

    It is also the precondition that makes the ``except TypeError`` arm around
    ``jwt.decode`` honest instead of a trap; see that arm's comment.
    """
    with pytest.raises(ValueError, match=expect):
        InternalTokenVerifier(JWKS_URL, audience=audience)


async def test_a_generator_audience_is_materialised_not_consumed(keypair):
    """REPAIRED rather than refused, because its damage is DELAYED.

    A generator satisfies PyJWT's ``isinstance(audience, (str, Iterable))`` test
    and is then CONSUMED by the first ``jwt.decode``. Measured pre-fix: the first
    token verified and every token after it was refused. A verifier is built once
    per process at startup, so that is a service that works until its second
    request. Unlike the shapes in the table above it carries an unambiguous
    intent, so the precondition materialises it once instead of rejecting it.

    The assertion is the SECOND verify — a single-call test would have passed
    against the pre-fix code, which is precisely the shape of this bug.
    """
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json=_jwks_doc(keypair.public_key()))
        )
    )
    verifier = InternalTokenVerifier(JWKS_URL, audience=(a for a in [AUDIENCE]), client=client)

    assert (await verifier.verify(_issue(keypair))).sub == "alloy-sa"
    assert (await verifier.verify(_issue(keypair))).sub == "alloy-sa"  # pre-fix: refused
    await verifier.aclose()


@pytest.mark.parametrize(
    "audience",
    [
        pytest.param(AUDIENCE, id="str"),
        pytest.param([AUDIENCE], id="list"),
        pytest.param((AUDIENCE,), id="tuple"),
        pytest.param({AUDIENCE}, id="set"),
    ],
)
async def test_the_audience_precondition_does_not_break_a_valid_token(keypair, audience):
    """THE CONTROL: every shape that worked before this change still works.

    A precondition that refused everything would "close" the trap by causing the
    outage it exists to prevent, and every negative test above would still pass.
    Verified twice per shape, because the precondition materialises an iterable
    and the second call is what proves the stored value is still readable.
    """
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json=_jwks_doc(keypair.public_key()))
        )
    )
    verifier = InternalTokenVerifier(JWKS_URL, audience=audience, client=client)

    assert (await verifier.verify(_issue(keypair))).sub == "alloy-sa"
    assert (await verifier.verify(_issue(keypair))).sub == "alloy-sa"
    await verifier.aclose()


def test_the_audience_precondition_is_the_shared_rule_not_a_second_copy():
    """Both verifiers screen ``audience`` with the SAME function, not two copies.

    The sibling of ``test_admission_is_the_shared_rule_not_a_second_copy`` at the
    bottom of this file, and for the same reason: these two modules have now
    broken the same contract in the same way twice, each time because each held
    its own copy of a rule.
    """
    from kag_common import _audience, attestation, internal_token

    assert internal_token.checked_audience is _audience.checked_audience
    assert attestation.checked_audience is _audience.checked_audience


# --------------------------------------------------------------------------- #
# happy path + claim extraction
# --------------------------------------------------------------------------- #
async def test_valid_token_returns_claims(keypair):
    verifier, seen = _verifier(keypair.public_key())
    token = _issue(keypair, tenant_id="tenant-x")

    verified = await verifier.verify(token)

    assert isinstance(verified, VerifiedInternalToken)
    assert verified.sub == "alloy-sa"
    assert verified.tenant_id == "tenant-x"
    assert verified.raw["iss"] == ISSUER
    assert len(seen) == 1  # one JWKS fetch on first (cache-empty) verify


async def test_tenant_id_absent_is_none(keypair):
    verifier, _ = _verifier(keypair.public_key())
    verified = await verifier.verify(_issue(keypair, tenant_id=None))
    assert verified.tenant_id is None


async def test_cache_hit_skips_second_fetch(keypair):
    verifier, seen = _verifier(keypair.public_key())
    await verifier.verify(_issue(keypair))
    await verifier.verify(_issue(keypair))
    assert len(seen) == 1  # second verify served from the by-kid cache


# --------------------------------------------------------------------------- #
# fail-closed paths
# --------------------------------------------------------------------------- #
async def test_wrong_issuer_rejected(keypair):
    verifier, _ = _verifier(keypair.public_key())
    with pytest.raises(InvalidInternalTokenError):
        await verifier.verify(_issue(keypair, issuer="someone-else"))


async def test_wrong_audience_rejected(keypair):
    verifier, _ = _verifier(keypair.public_key())
    with pytest.raises(InvalidInternalTokenError):
        await verifier.verify(_issue(keypair, audience="not-internal"))


async def test_expired_token_rejected(keypair):
    verifier, _ = _verifier(keypair.public_key())
    with pytest.raises(InvalidInternalTokenError):
        await verifier.verify(_issue(keypair, now=int(time.time()) - 1000))


async def test_missing_exp_rejected(keypair):
    verifier, _ = _verifier(keypair.public_key())
    with pytest.raises(InvalidInternalTokenError):
        await verifier.verify(_issue(keypair, drop=("exp",)))


async def test_missing_iss_rejected(keypair):
    verifier, _ = _verifier(keypair.public_key())
    with pytest.raises(InvalidInternalTokenError):
        await verifier.verify(_issue(keypair, drop=("iss",)))


async def test_bad_signature_rejected(keypair, other_key):
    # JWKS serves keypair's public key, but the token is signed by other_key.
    verifier, _ = _verifier(keypair.public_key())
    token = _issue(other_key)
    with pytest.raises(InvalidInternalTokenError):
        await verifier.verify(token)


async def test_no_kid_header_rejected(keypair):
    verifier, seen = _verifier(keypair.public_key())
    token = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "x", "exp": int(time.time()) + 60},
        keypair,
        algorithm="RS256",
    )  # no kid header
    with pytest.raises(InvalidInternalTokenError):
        await verifier.verify(token)
    assert len(seen) == 0  # never fetched JWKS — rejected before any network


async def test_malformed_token_rejected(keypair):
    verifier, _ = _verifier(keypair.public_key())
    with pytest.raises(InvalidInternalTokenError):
        await verifier.verify("not-a-jwt")


# --------------------------------------------------------------------------- #
# kid miss → one refresh
# --------------------------------------------------------------------------- #
async def test_unknown_kid_refreshes_then_still_absent(keypair):
    # JWKS is served under KID, but the token is signed under a different kid.
    verifier, seen = _verifier(keypair.public_key(), kid=KID)
    token = _issue(keypair, kid="rotated-kid")
    with pytest.raises(InvalidInternalTokenError):
        await verifier.verify(token)
    assert len(seen) == 1  # one refresh attempt on the kid miss


async def test_rotated_kid_picked_up_on_refresh(keypair):
    # The served JWKS uses the same kid the token was signed with; an initially
    # empty cache means the first verify fetches and finds it.
    verifier, seen = _verifier(keypair.public_key(), kid="rotated-kid")
    verified = await verifier.verify(_issue(keypair, kid="rotated-kid"))
    assert verified.sub == "alloy-sa"
    assert len(seen) == 1


# --------------------------------------------------------------------------- #
# JWKS fetch failure → fail closed
# --------------------------------------------------------------------------- #
async def test_jwks_fetch_failure_rejected(keypair):
    verifier, _ = _verifier(keypair.public_key(), fail=True)
    with pytest.raises(InvalidInternalTokenError):
        await verifier.verify(_issue(keypair))


# --------------------------------------------------------------------------- #
# client ownership
# --------------------------------------------------------------------------- #
async def test_aclose_leaves_borrowed_client_open(keypair):
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))
    )
    verifier = InternalTokenVerifier(JWKS_URL, client=client)
    await verifier.aclose()
    assert not client.is_closed  # borrowed client is the caller's to close
    await client.aclose()


async def test_aclose_closes_owned_client():
    verifier = InternalTokenVerifier(JWKS_URL)
    owned = verifier._get_client()
    await verifier.aclose()
    assert owned.is_closed


# --------------------------------------------------------------------------- #
# JWKS entries this verifier cannot use -> InvalidInternalTokenError, never a
# bare exception
#
# The module docstring's contract is "any signature/claim/fetch error raises
# ``InvalidInternalTokenError``", and ``verify()``'s own docstring repeats it as
# "Raise ``InvalidInternalTokenError`` on any failure". Six JWKS shapes broke
# that, all of them through the single line ``_refresh_keys`` used to cache a key
# with, and NONE of them raising a ``PyJWTError`` — so widening the decode ladder
# would not have caught any of them either. Measured on the pre-fix module,
# quoting the exception that escaped ``verify()`` in each case.
#
# This is the same defect ``attestation.py`` carried; the fix is now the one
# shared admission rule in ``kag_common._jwks``, which is why these tests and
# ``test_attestation.py``'s equivalents assert the same six shapes.
# --------------------------------------------------------------------------- #
async def test_jwks_served_as_a_json_array_does_not_raise(keypair):
    """A JWKS body that is an array, not an object.

    Pre-fix: ``AttributeError: 'list' object has no attribute 'get'`` out of
    ``doc.get("keys", [])``. ``AttributeError`` is not in ``verify()``'s caught
    tuple ``(PyJWTError, httpx.HTTPError, OSError, ValueError, KeyError)``.
    """
    verifier = _verifier_serving(["not", "an", "object"])
    with pytest.raises(InvalidInternalTokenError):
        await verifier.verify(_issue(keypair))
    await verifier.aclose()


async def test_jwks_keys_member_that_is_not_an_array_does_not_raise(keypair):
    """``{"keys": 42}`` — a ``keys`` member that cannot be iterated.

    Pre-fix: ``TypeError: 'int' object is not iterable`` out of the ``for``.
    Distinct from the case above: the document IS an object, so a
    ``isinstance(doc, dict)`` guard alone would not have closed it.
    """
    verifier = _verifier_serving({"keys": 42})
    with pytest.raises(InvalidInternalTokenError):
        await verifier.verify(_issue(keypair))
    await verifier.aclose()


async def test_jwks_entry_that_is_not_an_object_does_not_raise(keypair):
    """``{"keys": [42]}`` — a well-shaped document holding a scalar ENTRY.

    Pre-fix: ``AttributeError: 'int' object has no attribute 'get'`` out of
    ``jwk.get("kid")``. Both document-level guards pass; the entry is the problem.
    """
    verifier = _verifier_serving({"keys": [42]})
    with pytest.raises(InvalidInternalTokenError):
        await verifier.verify(_issue(keypair))
    await verifier.aclose()


@pytest.mark.parametrize(
    "bad_kid",
    [
        pytest.param({"a": 1}, id="object"),
        pytest.param(["a"], id="array"),
    ],
)
async def test_jwks_entry_with_an_unhashable_kid_does_not_raise(keypair, bad_kid):
    """A VALID RSA key whose ``kid`` is not a string — the escape one line past the guard.

    The entry is a perfectly good RSA key, so ``PyJWK.from_dict`` succeeds and no
    key-parse guard ever fires. ``if not kid`` does NOT screen it either: a
    non-empty dict and a non-empty list are both truthy. The exception comes from
    the CACHE ASSIGNMENT that follows:

        self._keys[kid] = ...  ->  TypeError: cannot use 'dict' as a dict key

    Pre-fix, measured: ``TypeError: cannot use 'dict' as a dict key (unhashable
    type: 'dict')`` and the ``list`` equivalent, both straight out of ``verify()``.

    Dropping the entry loses nothing: RFC 7517 s4.5 defines ``kid`` as a string,
    and PyJWT rejects a non-string ``kid`` on both mint and read
    (``InvalidTokenError: Key ID header parameter must be a string``), so no
    reachable token header could ever have matched it.
    """
    jwk = json.loads(RSAAlgorithm.to_jwk(keypair.public_key()))
    jwk.update({"kid": bad_kid, "use": "sig", "alg": "RS256"})
    verifier = _verifier_serving({"keys": [jwk]})
    with pytest.raises(InvalidInternalTokenError):
        await verifier.verify(_issue(keypair))
    await verifier.aclose()


async def test_jwks_entry_of_the_wrong_algorithm_family_does_not_raise(keypair):
    """A well-formed EC P-256 key served under the kid the token names.

    The nastiest of the six: nothing about this JWKS is malformed, so no amount
    of validating the DOCUMENT would have caught it. It is exactly what an ES256
    rotation produces. The entry parsed, was cached, and then
    ``RSAAlgorithm.prepare_key`` raised inside ``jwt.decode`` — pre-fix, measured:
    ``TypeError: Expecting a PEM-formatted key``. ``TypeError`` is not a
    ``PyJWTError``, so it fell through the entire decode except-ladder.
    """
    ec_key = ec.generate_private_key(ec.SECP256R1())
    jwk = json.loads(ECAlgorithm.to_jwk(ec_key.public_key()))
    jwk.update({"kid": KID, "use": "sig", "alg": "ES256"})
    verifier = _verifier_serving({"keys": [jwk]})
    with pytest.raises(InvalidInternalTokenError):
        await verifier.verify(_issue(keypair))
    await verifier.aclose()


async def test_one_unusable_jwks_entry_does_not_evict_the_usable_ones(keypair):
    """Anti-vacuity for the SKIP-don't-abort half of the fix.

    Every test above would pass just as well against a fix that let one bad entry
    abort the whole refresh — the outcome is ``InvalidInternalTokenError`` either
    way, so those five cannot tell the two implementations apart. This one can,
    because its observable is SUCCESS rather than a shared failure: a JWKS
    carrying an unusable entry FIRST must still load the good key that follows it.

    It is not hypothetical, and it is the case the pre-fix module got wrong in the
    OTHER direction from the six above: ``PyJWK.from_dict`` on ``kty:
    OKP-not-a-real-kty`` raises ``InvalidKeyError``, which IS a ``PyJWTError`` and
    so WAS caught — by aborting the refresh, leaving the good RSA key that
    follows it uncached. Pre-fix this token is rejected with
    ``InvalidInternalTokenError("Unsupported kty: OKP-not-a-real-kty")``, i.e. the
    issuer adding a single ES256 key beside its RS256 one takes every kid down at
    once. That is an outage, not a fail-closed.
    """
    good = json.loads(RSAAlgorithm.to_jwk(keypair.public_key()))
    good.update({"kid": KID, "use": "sig", "alg": "RS256"})
    verifier = _verifier_serving(
        {
            "keys": [
                {"kty": "OKP-not-a-real-kty", "kid": "internal-rotating-in", "use": "sig"},
                good,
            ]
        }
    )

    verified = await verifier.verify(_issue(keypair))

    assert verified.sub == "alloy-sa"
    await verifier.aclose()


async def test_admission_is_the_shared_rule_not_a_second_copy(keypair):
    """The two verifiers screen JWKS entries with the SAME function, not two copies.

    ``attestation.py`` and ``internal_token.py`` broke their (differently worded)
    never-raises contracts in the identical six ways, through identical code, and
    were fixed a week apart by copying. Pinning the sharing is what stops the copy
    from being reintroduced and drifting: a future edit that reinstates a private
    admission loop in either module reds here rather than silently reopening the
    other module's half of the defect.
    """
    from kag_common import _jwks, attestation, internal_token

    assert internal_token.usable_keys_by_kid is _jwks.usable_keys_by_kid
    assert attestation.usable_keys_by_kid is _jwks.usable_keys_by_kid
    # ...and the algorithm admission screens against is the one decode is handed.
    assert internal_token.JWS_ALGORITHM == attestation.JWS_ALGORITHM == "RS256"


# --------------------------------------------------------------------------- #
# The PAYLOAD-DRIVEN escape from the never-raises contract — the sibling of
# ``test_payload_time_claim_type_confusion_is_a_typed_rejection`` in
# ``test_attestation.py``.
#
# #45/#46 closed six KEY-DRIVEN escapes in both modules through one shared
# admission rule, and recorded in ``attestation.py`` that a PAYLOAD-DRIVEN one
# survived in BOTH: PyJWT's ``_validate_exp``/``_validate_nbf``/``_validate_iat``
# each do ``int(claim)`` catching only ``ValueError``, so a non-numeric
# NON-STRING time claim escapes as a bare ``TypeError``. Not a ``PyJWTError``,
# so this module's ``except`` tuple never matched it. Both halves are closed in
# the same pass, because they are one defect with two copies — which is the
# whole lesson of ``_jwks.py``.
# --------------------------------------------------------------------------- #
def _issue_with_time_claim(private_key, claim: str, value: Any) -> str:
    """Sign an otherwise-valid token whose ``claim`` carries ``value`` verbatim.

    Not ``_issue``: that computes ``iat``/``exp`` itself and so cannot express a
    non-numeric one, which is the entire point of the cases below.
    """
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "alloy-sa",
        "iat": now,
        "exp": now + 300,
    }
    claims[claim] = value
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": KID})


@pytest.mark.parametrize(
    ("claim", "value"),
    [
        pytest.param("exp", [1], id="exp-array"),
        pytest.param("nbf", {}, id="nbf-object"),
        # ``iat: null`` raises, but ``exp: null`` does NOT — ``options={"require":
        # ["exp", ...]}`` treats a null-valued required claim as missing and rejects
        # it before any ``int()`` runs. Not interchangeable.
        pytest.param("iat", None, id="iat-null"),
    ],
)
async def test_payload_time_claim_type_confusion_is_a_typed_rejection(
    keypair, other_key, claim, value
):
    """A CORRECTLY-SIGNED token whose ``exp``/``nbf``/``iat`` is not a number.

    Pre-fix, measured on pyjwt 2.13, each of these raised ``TypeError: int()
    argument must be a string, a bytes-like object or a real number`` straight
    out of ``verify()`` — past a docstring promising ``InvalidInternalTokenError``
    on ANY failure. A caller following that contract catches
    ``InvalidInternalTokenError`` and returns 401; a bare ``TypeError`` instead
    reaches the framework as a 500, which is a different and worse answer to the
    same untrusted input.

    The second half is the control that makes "post-signature" an executable
    claim rather than an assertion: the byte-identical payload signed by a key
    the JWKS does not carry never reaches ``int()`` at all. Both halves raise
    ``InvalidInternalTokenError`` here (this module has one exception type, not
    a reason enum), so the control asserts on the MESSAGE — otherwise it would
    pass no matter which path produced the raise.

    The message differs by pyjwt version, so the match names the CLAIM, not the
    wording: pyjwt <2.15 leaks the ``TypeError`` text (``int() argument must
    be...``) which the module re-raises; pyjwt >=2.15 validates the type itself
    and raises ``DecodeError``/``InvalidIssuedAtError`` with ``"... claim (exp)
    must be an integer."``. Either way it must be THIS claim's type rejection,
    and the control below must still produce a different message.
    """
    verifier, _ = _verifier(keypair.public_key())

    with pytest.raises(
        InvalidInternalTokenError,
        match=rf"int\(\) argument must be|\({claim}\) must be an integer",
    ):
        await verifier.verify(_issue_with_time_claim(keypair, claim, value))

    # CONTROL: same payload, wrong signer -> a DIFFERENT failure, proving the
    # case above is post-signature and not simply "everything fails now".
    with pytest.raises(InvalidInternalTokenError, match="Signature verification failed"):
        await verifier.verify(_issue_with_time_claim(other_key, claim, value))


async def test_a_stringly_typed_time_claim_is_already_handled(keypair):
    """The boundary of the case above — a ``str`` is NOT part of it.

    ``int("x")`` raises ``ValueError``, which PyJWT DOES catch and re-raise as a
    ``PyJWTError``, so the outer ladder has always converted it. Without this
    control the defect reads as "any bad ``nbf`` escaped", which is wrong and
    would over-scope the fix: only the non-string types needed new handling.
    """
    verifier, _ = _verifier(keypair.public_key())

    with pytest.raises(InvalidInternalTokenError, match="Not Before claim"):
        await verifier.verify(_issue_with_time_claim(keypair, "nbf", "x"))
