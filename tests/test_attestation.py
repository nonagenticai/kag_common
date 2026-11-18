"""Tests for the FND-008I attestation verifier (RS256 + cached JWKS + released grammar).

Pure-unit, same house style as ``test_internal_token.py``: an ephemeral RS256 keypair signs
attestations shaped like ``urn:datacompany:approval-attestation:1``, and an
``httpx.MockTransport`` serves the matching JWKS (and, where exercised, the revocation
status endpoint) — no live FR issuer needed.

Document 13 section 10.3 names exactly eighteen negative cases: "wrong audience, signature,
key, approval/task ID, target, command hash, input revision, profile/policy, approval round,
approver subject, role, decision, count, self-approval, expiry, replay, revocation, and an
aggregate changed between approval and application." One test below is named after each,
plus ``test_a_correct_attestation_verifies`` as the positive control every negative case is
a mutation of.

Two of the eighteen are NOT this module's to test and are marked as such below rather than
faked:

* **replay** needs a dedup store keyed on ``attestation_id`` — that store is section 10.2's
  applier, per-service, and does not exist here. ``test_replay`` asserts only what the
  verifier contributes: a successful result carries ``attestation_id``, which is what an
  applier dedupes on.
* **an aggregate changed between approval and application** needs a live read of the
  aggregate's current revision — also the applier's, also absent here.
  ``test_an_aggregate_changed_between_approval_and_application`` asserts only that a
  successful result carries ``target`` (including ``aggregate_version``), which is what an
  applier compares against the aggregate's current state at apply time.

A test that pretended to cover either case — e.g. by hand-rolling an in-process dedup dict —
would be worse than leaving the gap explicit: it would assert kag_common owns a check that
document 13 section 10.2 places in every owning domain service, individually.
"""

from __future__ import annotations

import hashlib
import json
import time
import unicodedata
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from kag_common.attestation import (
    CLOCK_LEEWAY_SECONDS,
    JWKS_REFRESH_COOLDOWN_SECONDS,
    JWS_ALGORITHM,
    SUBJECT_REMOVED_CATEGORIES,
    SUBJECT_TRIMMED_CHARACTERS,
    AttestationVerifier,
    ExpectedApplication,
    PinnedRef,
    VerificationReason,
    VerificationResult,
    _normalise_subject,
)

ISSUER = "fr-attestation"
AUDIENCE = "evidence-review"
KID = "fr-attestation-test-1"
JWKS_URL = "http://fr.istio-system.svc/attestation/jwks"

AGGREGATE_ID = "7c67fcdf-c60e-45d8-9d46-a35189c0ea11"
ATTESTATION_ID = "0198f3a1-4b2c-7d3e-8f40-51a6b7c8d9e0"
APPROVAL_ID = "5c1e9a70-2b44-4f18-b6d2-9a0c7e3f1b52"
APPROVER_SUBJECT = "32969c16-0000-0000-0000-000000000000"
PROPOSER_SUBJECT = "aad9fff9-fcd6-4a02-83f3-cf133f15d384"
COMMAND_HASH = "sha256:" + "ab" * 32

#: Sentinel for "this test did not ask for a custom revocation body" — ``None`` cannot be it,
#: because ``{"revoked": null}`` is one of the bodies under test.
_UNSET = object()


@pytest.fixture(scope="module")
def keypair():
    """An ephemeral RS256 keypair (FR's attestation signing key)."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def other_key():
    """A second, unrelated keypair — for the bad-signature case."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwks_doc(public_key, kid: str = KID) -> dict[str, Any]:
    jwk = json.loads(RSAAlgorithm.to_jwk(public_key))
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return {"keys": [jwk]}


def _attestation_body(**overrides: Any) -> dict[str, Any]:
    """One whole ApprovalAttestation payload, global-scoped to avoid needing a tenant id.

    A function, not a constant, so every mutation in the tests below starts from an
    unmutated body. ``overrides`` replaces top-level members; nested mutation (``target``,
    ``approvers``) is done by the caller before passing the override in.

    ``issued_at``/``expires_at`` are computed relative to *now* (not a fixed 2026-09-02
    literal) and kept inside the IMP-DEC-002 300s TTL ceiling: the verifier now checks both
    payload timestamps independently of the envelope, so a stale hardcoded pair would make
    every positive-path test fail as EXPIRED regardless of when the suite runs.
    """
    _issued = datetime.now(UTC) - timedelta(seconds=5)
    _expires = _issued + timedelta(seconds=200)  # well inside the 300s ceiling
    body: dict[str, Any] = {
        "schema_ref": "urn:datacompany:approval-attestation:1",
        "attestation_id": ATTESTATION_ID,
        "approval_id": APPROVAL_ID,
        "approval_round": 1,
        "resource_scope": "global",
        "target": {
            "service": "evidence-review",
            "aggregate_type": "review",
            "aggregate_id": AGGREGATE_ID,
            "aggregate_version": 12,
            "input_revision": "sha256:" + "11" * 32,
        },
        "command_operation": "seal_evidence_snapshot",
        "command_hash": COMMAND_HASH,
        "approvers": [
            {
                "subject": APPROVER_SUBJECT,
                "role": "review_lead",
                "decision": "approve",
                "decided_at": "2026-09-02T11:14:07Z",
            }
        ],
        "required_approvals": 1,
        "issued_at": _issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": _expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    body.update(overrides)
    return body


def _issue(
    private_key,
    *,
    kid: str = KID,
    issuer: str = ISSUER,
    audience: str = AUDIENCE,
    ttl: int = 300,
    now: int | None = None,
    drop: tuple[str, ...] = (),
    attestation: dict[str, Any] | None = None,
) -> str:
    """Sign an attestation JWS. ``drop`` omits envelope claims; ``attestation`` overrides the
    payload body wholesale (defaults to :func:`_attestation_body`)."""
    iat = int(time.time()) if now is None else now
    claims: dict[str, Any] = dict(attestation if attestation is not None else _attestation_body())
    claims["iss"] = issuer
    claims["aud"] = audience
    claims["iat"] = iat
    claims["exp"] = iat + ttl
    for k in drop:
        claims.pop(k, None)
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": kid})


def _expected(**overrides: Any) -> ExpectedApplication:
    base: dict[str, Any] = dict(
        target_service="evidence-review",
        aggregate_type="review",
        aggregate_id=AGGREGATE_ID,
        aggregate_version=12,
        input_revision="sha256:" + "11" * 32,
        command_operation="seal_evidence_snapshot",
        command_hash=COMMAND_HASH,
        acting_subject=PROPOSER_SUBJECT,
        profile_ref=None,
        policy_ref=None,
    )
    base.update(overrides)
    return ExpectedApplication(**base)


def _verifier(
    public_key,
    *,
    kid: str = KID,
    # ``Any``, not ``str``: the audience-precondition tests below build verifiers through this
    # same helper with the shapes a caller might mis-wire, and must exercise the REAL
    # constructor rather than reaching past it.
    audience: Any = AUDIENCE,
    fail: bool = False,
    revoked: bool | None = None,
    revocation_status: Any = _UNSET,
    revocation_allowed_origins: frozenset[str] = frozenset(),
    refresh_cooldown: float = JWKS_REFRESH_COOLDOWN_SECONDS,
    # ``list[Any]``, not ``list[dict]``: one test below serves a JWKS body that is a JSON
    # ARRAY rather than an object, which is the shape under test.
    jwks_docs: list[Any] | None = None,
) -> tuple[AttestationVerifier, list[httpx.Request]]:
    """Build a verifier wired to a MockTransport JWKS (+ optional revocation endpoint).

    ``revocation_allowed_origins`` defaults to empty — matching the module default — so a
    test that does not care about revocation never accidentally exercises the SSRF allow-list.
    Tests that DO exercise revocation must opt in explicitly.
    """
    seen: list[httpx.Request] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if fail:
            raise httpx.ConnectError("jwks unreachable")
        if request.url.path.endswith("/revocation-status"):
            if revocation_status is not _UNSET:
                # A verbatim status BODY, not a bool — the point of several tests below is
                # what happens on a 200 that does not actually answer the question.
                return httpx.Response(200, json=revocation_status)
            return httpx.Response(200, json={"revoked": bool(revoked)})
        if jwks_docs is not None:
            # Successive JWKS responses, for the rotation/cooldown tests; the last one repeats.
            return httpx.Response(200, json=jwks_docs[min(_jwks_calls[0], len(jwks_docs) - 1)])
        return httpx.Response(200, json=_jwks_doc(public_key, kid))

    _jwks_calls = [0]
    _outer_handler = _handler

    def _counting_handler(request: httpx.Request) -> httpx.Response:
        response = _outer_handler(request)
        if not request.url.path.endswith("/revocation-status"):
            _jwks_calls[0] += 1
        return response

    client = httpx.AsyncClient(transport=httpx.MockTransport(_counting_handler))
    return (
        AttestationVerifier(
            JWKS_URL,
            issuer=ISSUER,
            audience=audience,
            client=client,
            refresh_cooldown=refresh_cooldown,
            revocation_allowed_origins=revocation_allowed_origins,
        ),
        seen,
    )


# --------------------------------------------------------------------------- #
# construction
# --------------------------------------------------------------------------- #
def test_requires_jwks_url():
    with pytest.raises(ValueError, match="jwks_url"):
        AttestationVerifier("", issuer=ISSUER, audience=AUDIENCE)


def test_requires_issuer():
    with pytest.raises(ValueError, match="issuer"):
        AttestationVerifier(JWKS_URL, issuer="", audience=AUDIENCE)


def test_requires_audience():
    with pytest.raises(ValueError, match="audience"):
        AttestationVerifier(JWKS_URL, issuer=ISSUER, audience="")


# --------------------------------------------------------------------------- #
# positive control
# --------------------------------------------------------------------------- #
async def test_a_correct_attestation_verifies(keypair):
    verifier, seen = _verifier(keypair.public_key())
    token = _issue(keypair)

    result = await verifier.verify(token, expected=_expected())

    assert isinstance(result, VerificationResult)
    assert result.ok is True
    assert result.reason is VerificationReason.VERIFIED
    assert result.attestation_id == ATTESTATION_ID
    assert result.approval_id == APPROVAL_ID
    assert result.command_hash == COMMAND_HASH
    assert result.target["aggregate_version"] == 12
    assert len(seen) == 1  # one JWKS fetch on first (cache-empty) verify


# --------------------------------------------------------------------------- #
# 1. wrong audience
# --------------------------------------------------------------------------- #
async def test_wrong_audience(keypair):
    verifier, _ = _verifier(keypair.public_key())
    token = _issue(keypair, audience="not-evidence-review")
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is False
    assert result.reason is VerificationReason.WRONG_AUDIENCE


# --------------------------------------------------------------------------- #
# wrong issuer — not named separately among document 13 section 10.3's eighteen cases (it
# groups "wrong audience, signature, key, ..." without a distinct issuer entry), but the
# module docstring lists issuer among what is checked, ``jwt.decode`` is passed
# ``issuer=self.issuer`` for exactly this, and there was no test pinning it. Also the guard
# for a mutant that deletes that argument.
# --------------------------------------------------------------------------- #
async def test_wrong_issuer(keypair):
    verifier, _ = _verifier(keypair.public_key())
    token = _issue(keypair, issuer="not-fr-attestation")
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is False
    assert result.reason is VerificationReason.WRONG_ISSUER


# --------------------------------------------------------------------------- #
# 2. signature
# --------------------------------------------------------------------------- #
async def test_signature(keypair, other_key):
    # JWKS serves keypair's public key, but the token is signed by other_key.
    verifier, _ = _verifier(keypair.public_key())
    token = _issue(other_key)
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is False
    assert result.reason is VerificationReason.BAD_SIGNATURE


# --------------------------------------------------------------------------- #
# 3. key
# --------------------------------------------------------------------------- #
async def test_key(keypair):
    # JWKS is served under KID, but the token is signed under a different, unknown kid.
    verifier, seen = _verifier(keypair.public_key(), kid=KID)
    token = _issue(keypair, kid="an-unpublished-kid")
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is False
    assert result.reason is VerificationReason.UNKNOWN_KEY
    assert len(seen) == 1  # exactly one forced refresh on the kid miss


# --------------------------------------------------------------------------- #
# 4. approval/task ID
# --------------------------------------------------------------------------- #
async def test_approval_task_id(keypair):
    verifier, _ = _verifier(keypair.public_key())
    token = _issue(keypair, attestation=_attestation_body(approval_id="not-a-uuid"))
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is False
    assert result.reason is VerificationReason.MALFORMED_ATTESTATION


# --------------------------------------------------------------------------- #
# 5. target
# --------------------------------------------------------------------------- #
async def test_target(keypair):
    verifier, _ = _verifier(keypair.public_key())
    token = _issue(keypair)
    result = await verifier.verify(
        token, expected=_expected(aggregate_id="99999999-9999-9999-9999-999999999999")
    )
    assert result.ok is False
    assert result.reason is VerificationReason.WRONG_TARGET
    # identity fields are still populated: schema validation already trusted the body.
    assert result.attestation_id == ATTESTATION_ID


async def test_target_wrong_aggregate_version(keypair):
    """Isolates the ``aggregate_version`` half of the target comparison — service and
    aggregate_id both match exactly, only the version differs. Guards against a mutant that
    deletes the ``aggregate_version`` comparison from the ``target`` check."""
    verifier, _ = _verifier(keypair.public_key())
    token = _issue(keypair)
    result = await verifier.verify(token, expected=_expected(aggregate_version=13))
    assert result.ok is False
    assert result.reason is VerificationReason.WRONG_TARGET


# --------------------------------------------------------------------------- #
# 6. command hash
# --------------------------------------------------------------------------- #
async def test_command_hash(keypair):
    verifier, _ = _verifier(keypair.public_key())
    token = _issue(keypair)
    result = await verifier.verify(token, expected=_expected(command_hash="sha256:" + "ff" * 32))
    assert result.ok is False
    assert result.reason is VerificationReason.WRONG_COMMAND_HASH


# --------------------------------------------------------------------------- #
# 7. input revision
# --------------------------------------------------------------------------- #
async def test_input_revision(keypair):
    verifier, _ = _verifier(keypair.public_key())
    token = _issue(keypair)
    result = await verifier.verify(token, expected=_expected(input_revision="sha256:" + "22" * 32))
    assert result.ok is False
    assert result.reason is VerificationReason.WRONG_INPUT_REVISION


# --------------------------------------------------------------------------- #
# 8. profile/policy
# --------------------------------------------------------------------------- #
async def test_profile_policy(keypair):
    verifier, _ = _verifier(keypair.public_key())
    attestation = _attestation_body(
        profile_ref={
            "owner_context": "evidence-review",
            "entity_type": "profile_release",
            "entity_id": "11111111-1111-1111-1111-111111111111",
            "resource_scope": "global",
            "version_id": "22222222-2222-2222-2222-222222222222",
            "version_number": 1,
            "schema_ref": "urn:datacompany:profile-release:1",
            "content_hash": "sha256:" + "33" * 32,
            "resolved_at": "2026-09-02T11:14:08Z",
        }
    )
    token = _issue(keypair, attestation=attestation)
    # Caller expects a DIFFERENT profile version than the one the attestation was approved under.
    result = await verifier.verify(
        token,
        expected=_expected(
            profile_ref=PinnedRef("99999999-9999-9999-9999-999999999999", "sha256:" + "33" * 32)
        ),
    )
    assert result.ok is False
    assert result.reason is VerificationReason.WRONG_PROFILE_OR_POLICY


# --------------------------------------------------------------------------- #
# 9. approval round
# --------------------------------------------------------------------------- #
async def test_approval_round(keypair):
    """``approval_round: 0`` is caught by the released schema's own ``minimum: 1`` — that
    exercises research_contracts, not this verifier's own round comparison. The actual
    negative case document 13 section 10.3 asks for is a caller applying a DIFFERENT round
    than the one attested, which must be schema-valid on both sides to isolate the verifier's
    own check from the schema's."""
    verifier, _ = _verifier(keypair.public_key())
    token = _issue(keypair, attestation=_attestation_body(approval_round=1))
    result = await verifier.verify(token, expected=_expected(approval_round=2))
    assert result.ok is False
    assert result.reason is VerificationReason.WRONG_APPROVAL_ROUND


async def test_approval_round_not_checked_when_caller_does_not_supply_one(keypair):
    """``ExpectedApplication.approval_round`` is optional — a caller that does not track
    rounds must not be forced to guess one."""
    verifier, _ = _verifier(keypair.public_key())
    token = _issue(keypair, attestation=_attestation_body(approval_round=3))
    result = await verifier.verify(token, expected=_expected())  # approval_round=None
    assert result.ok is True


async def test_approval_round_zero_rejected_structurally(keypair):
    """The released schema's own floor: ``approval_round: 0`` never reaches the verifier's
    semantic round comparison at all."""
    verifier, _ = _verifier(keypair.public_key())
    token = _issue(keypair, attestation=_attestation_body(approval_round=0))
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is False
    assert result.reason is VerificationReason.MALFORMED_ATTESTATION


# --------------------------------------------------------------------------- #
# 10. approver subject
# --------------------------------------------------------------------------- #
async def test_approver_subject(keypair):
    verifier, _ = _verifier(keypair.public_key())
    body = _attestation_body()
    body["approvers"][0]["subject"] = ""  # below actor_subject's minLength: 1
    token = _issue(keypair, attestation=body)
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is False
    assert result.reason is VerificationReason.MALFORMED_ATTESTATION


# --------------------------------------------------------------------------- #
# 11. role
# --------------------------------------------------------------------------- #
async def test_role(keypair):
    verifier, _ = _verifier(keypair.public_key())
    body = _attestation_body()
    body["approvers"][0]["role"] = "Not A Valid Canonical Token!"
    token = _issue(keypair, attestation=body)
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is False
    assert result.reason is VerificationReason.MALFORMED_ATTESTATION


# --------------------------------------------------------------------------- #
# 12. decision
# --------------------------------------------------------------------------- #
async def test_decision(keypair):
    verifier, _ = _verifier(keypair.public_key())
    body = _attestation_body()
    body["approvers"][0]["decision"] = "abstain"  # not in {"approve", "reject"}
    token = _issue(keypair, attestation=body)
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is False
    assert result.reason is VerificationReason.MALFORMED_ATTESTATION


# --------------------------------------------------------------------------- #
# 13. count
# --------------------------------------------------------------------------- #
async def test_count(keypair):
    verifier, _ = _verifier(keypair.public_key())
    # required_approvals says 2; only one approver actually recorded "approve".
    body = _attestation_body(required_approvals=2)
    token = _issue(keypair, attestation=body)
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is False
    assert result.reason is VerificationReason.INSUFFICIENT_APPROVALS


async def test_duplicate_subject_in_two_roles_does_not_satisfy_required_approvals(keypair):
    """CRITICAL: the same person recorded as an approver under two different roles must not
    satisfy a 2-of-N floor alone. The schema's ``uniqueItems: true`` cannot catch this — it
    compares whole approver objects, so one subject appearing under two roles is two distinct
    items, both structurally valid. The count must be de-duplicated on ``subject``."""
    verifier, _ = _verifier(keypair.public_key())
    body = _attestation_body(
        required_approvals=2,
        approvers=[
            {
                "subject": APPROVER_SUBJECT,
                "role": "review_lead",
                "decision": "approve",
                "decided_at": "2026-09-02T11:14:07Z",
            },
            {
                "subject": APPROVER_SUBJECT,
                "role": "reviewer",
                "decision": "approve",
                "decided_at": "2026-09-02T11:14:07Z",
            },
        ],
    )
    token = _issue(keypair, attestation=body)
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is False
    assert result.reason is VerificationReason.INSUFFICIENT_APPROVALS


async def test_count_excludes_rejections_mutant_guard(keypair):
    """Guards against a mutant that widens the count to ``len(approvers)``: one approval plus
    one rejection (two DISTINCT subjects, two array items) must not satisfy
    ``required_approvals: 2`` — only the approving subject counts."""
    verifier, _ = _verifier(keypair.public_key())
    other_subject = "11111111-1111-1111-1111-111111111111"
    body = _attestation_body(
        required_approvals=2,
        approvers=[
            {
                "subject": APPROVER_SUBJECT,
                "role": "review_lead",
                "decision": "approve",
                "decided_at": "2026-09-02T11:14:07Z",
            },
            {
                "subject": other_subject,
                "role": "reviewer",
                "decision": "reject",
                "decided_at": "2026-09-02T11:14:07Z",
            },
        ],
    )
    token = _issue(keypair, attestation=body)
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is False
    assert result.reason is VerificationReason.INSUFFICIENT_APPROVALS


async def test_required_approvals_zero_rejected(keypair):
    """``required_approvals`` must be an integer >= 1 — checked explicitly by this module, not
    only relied on from the released schema's own ``minimum: 1`` (research-contracts is only
    floored, ``>=0.9.0``, not pinned, in ``pyproject.toml``). Zero would make the count check
    vacuously true and let a reject-only (or approver-less-of-that-decision) attestation
    through."""
    verifier, _ = _verifier(keypair.public_key())
    body = _attestation_body(required_approvals=0)
    token = _issue(keypair, attestation=body)
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is False
    # The released schema also enforces minimum: 1, so this is currently caught structurally
    # (MALFORMED_ATTESTATION via assert_valid_instance) before this module's own explicit
    # check is ever reached — this test pins the observed behaviour rather than assuming it.
    assert result.reason is VerificationReason.MALFORMED_ATTESTATION


# --------------------------------------------------------------------------- #
# 14. self-approval
# --------------------------------------------------------------------------- #
async def test_self_approval(keypair):
    verifier, _ = _verifier(keypair.public_key())
    token = _issue(keypair)  # approver subject == APPROVER_SUBJECT
    # The caller's acting subject (the proposer) is the SAME person who approved it.
    result = await verifier.verify(token, expected=_expected(acting_subject=APPROVER_SUBJECT))
    assert result.ok is False
    assert result.reason is VerificationReason.SELF_APPROVAL


# --------------------------------------------------------------------------- #
# 15. expiry
# --------------------------------------------------------------------------- #
async def test_expiry(keypair):
    verifier, _ = _verifier(keypair.public_key())
    token = _issue(keypair, now=int(time.time()) - 10_000, ttl=60)
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is False
    assert result.reason is VerificationReason.EXPIRED


async def test_payload_expires_at_in_the_past_rejected_despite_a_fresh_envelope(keypair):
    """HIGH: the envelope ``exp`` alone was previously the only expiry check — the payload's
    own ``expires_at``/``issued_at`` were never read, even though the module docstring's
    ``CLOCK_LEEWAY_SECONDS`` comment claimed leeway "by extension" covered them. A stale
    ``expires_at`` (2020-01-01) with a fresh envelope ``exp`` must still be rejected."""
    verifier, _ = _verifier(keypair.public_key())
    body = _attestation_body(
        issued_at="2019-12-31T23:55:00Z",
        expires_at="2020-01-01T00:00:00Z",
    )
    token = _issue(keypair, attestation=body)  # envelope exp is fresh (default ttl=300, now)
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is False
    assert result.reason is VerificationReason.EXPIRED


async def test_payload_ttl_ceiling_exceeded_rejected(keypair):
    """HIGH: IMP-DEC-002's 300s TTL ceiling on the attestation's own validity window
    (``expires_at - issued_at``), enforced independently of the envelope ``exp`` — a
    compromised or buggy issuer must not be able to mint a long-lived attestation merely by
    setting a far-future ``expires_at``, even with a matching, still-fresh envelope ``exp``."""
    verifier, _ = _verifier(keypair.public_key())
    now = datetime.now(UTC)
    issued = now - timedelta(seconds=5)
    expires = issued + timedelta(hours=6)  # far past the 300s IMP-DEC-002 ceiling
    body = _attestation_body(
        issued_at=issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
        expires_at=expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    token = _issue(keypair, attestation=body, ttl=6 * 3600 + 60)  # envelope exp also generous
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is False
    assert result.reason is VerificationReason.EXPIRED


async def test_missing_exp_claim_rejected(keypair):
    """Guards against a mutant that widens ``options={"require": [...]}"`` down to ``[]``:
    PyJWT only enforces presence of ``exp`` (and every other envelope claim) via that require
    list — an envelope carrying no ``exp`` at all must still be rejected, not silently treated
    as non-expiring."""
    verifier, _ = _verifier(keypair.public_key())
    token = _issue(keypair, drop=("exp",))
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is False
    assert result.reason is VerificationReason.MALFORMED_TOKEN


async def test_algorithm_confusion_hs256_rejected(keypair):
    """Guards against a mutant that widens ``algorithms=`` to include ``HS256``/``none``: this
    verifier only ever accepts a token whose header names the single ratified algorithm
    (``JWS_ALGORITHM`` = RS256 — IMP-DEC-002). A token forged with HS256 under the SAME
    published ``kid`` (an attacker does not need a valid HMAC signature to probe whether the
    algorithm restriction holds — PyJWT rejects on the algorithm mismatch before it would ever
    attempt to verify the signature) must be rejected outright, not fall through to a
    signature-verification failure that implies the algorithm itself was accepted."""
    verifier, _ = _verifier(keypair.public_key())
    now = int(time.time())
    forged_claims = dict(_attestation_body())
    forged_claims.update(iss=ISSUER, aud=AUDIENCE, iat=now, exp=now + 300)
    forged = jwt.encode(
        forged_claims,
        "attacker-does-not-need-a-real-secret",
        algorithm="HS256",
        headers={"kid": KID},
    )
    result = await verifier.verify(forged, expected=_expected())
    assert result.ok is False
    assert result.reason is VerificationReason.MALFORMED_TOKEN


async def test_algorithm_confusion_alg_none_rejected(keypair):
    """``alg: none`` specifically, not by proxy through the HS256 case above.

    ⚠️ READ THE SECOND HALF BEFORE TRUSTING THIS TEST. It was written expecting
    to kill the mutant that widens ``algorithms=[JWS_ALGORITHM]`` to
    ``[JWS_ALGORITHM, "none"]``. **It does not — that mutant SURVIVES it**, and
    the survival is measured, not assumed. Recording it here rather than deleting
    the test, because *why* it survives is the useful part.

    The HS256 and ``none`` cases are commonly described as sharing one code path
    (the ``algorithms=`` allow-list). Measured, they do not share the control that
    actually stops them:

    * **HS256** is stopped by the allow-list, and only by it. Widen the list and
      the forgery is accepted, because ``HMACAlgorithm.prepare_key`` is perfectly
      happy to take an RSA *public* key as an HMAC secret — that IS the
      algorithm-confusion attack. ``test_algorithm_confusion_hs256_rejected``
      kills that mutant; this test does not.
    * **``none``** is stopped a second time, one layer down, by PyJWT's
      ``NoneAlgorithm.prepare_key``: "When alg = ``none``, key value must be
      None." This verifier always resolves a real RSA public key from the JWKS
      before it decodes, so it can never present the ``None`` key an ``alg: none``
      token needs — even with the allow-list widened. The allow-list is therefore
      not the load-bearing defence for this case; the non-None key is.

    So the honest scope of this test is (a) the behaviour contract — an
    ``alg: none`` token is refused, with a typed reason, and does not raise — and
    (b) a tripwire on the DEPENDENCY fact that carries (a). If a future PyJWT
    relaxed the non-None key rule, the second assertion below goes red and tells
    us this case has silently become dependent on the allow-list alone. That is a
    dependency pin, not a mutant kill, and is labelled as one rather than dressed
    up as coverage this file does not have.

    Constructible with PyJWT's own API — measured, ``jwt.encode(..., key=None,
    algorithm="none")`` succeeds and emits a real three-part token with an EMPTY
    signature segment, so nothing here is hand-rolled. Asserted, because if a
    future PyJWT refuses to MINT one this test would otherwise decay into "PyJWT
    raised during setup" and stop testing anything.
    """
    now = int(time.time())
    forged_claims = dict(_attestation_body())
    forged_claims.update(iss=ISSUER, aud=AUDIENCE, iat=now, exp=now + 300)
    # The inline suppression below is deliberate: typeshed types `key` as a real
    # key, but `algorithm="none"` REQUIRES None at runtime (PyJWT: 'When alg =
    # "none", key value must be None') — which is the whole point of this fixture.
    # Measured to encode successfully; the two asserts after it prove the token.
    forged = jwt.encode(forged_claims, None, algorithm="none", headers={"kid": KID})  # ty: ignore[invalid-argument-type]

    # The fixture is what we think it is: alg none, and NO signature to verify.
    assert jwt.get_unverified_header(forged)["alg"] == "none"
    assert forged.split(".")[2] == ""

    # (b) the dependency fact this case actually rests on: even with "none"
    # explicitly allowed, PyJWT refuses it against the non-None key this verifier
    # always holds. This is the layer that makes the allow-list non-load-bearing
    # here — if it ever stops holding, the allow-list becomes the only defence.
    with pytest.raises(jwt.InvalidKeyError, match="key value must be None"):
        jwt.decode(forged, keypair.public_key(), algorithms=[JWS_ALGORITHM, "none"])

    # (a) the behaviour contract, through the real entry point.
    verifier, _ = _verifier(keypair.public_key())
    result = await verifier.verify(forged, expected=_expected())

    assert result.ok is False
    assert result.reason is VerificationReason.MALFORMED_TOKEN


# --------------------------------------------------------------------------- #
# 3b. kid — the header member that names the key, before any key is resolved
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("headers", "case"),
    [
        (None, "absent"),
        ({"kid": ""}, "empty string"),
    ],
    ids=["kid-absent", "kid-empty-string"],
)
async def test_token_without_a_usable_kid_rejected(keypair, headers, case):
    """A token header carrying no usable ``kid`` is MALFORMED_TOKEN, not UNKNOWN_KEY.

    ``kid`` is what names the key the signature will be checked with; without one
    there is no key to look up, so this is rejected on the token's SHAPE before
    ``_resolve_key`` is ever reached — and, importantly, before any JWKS fetch,
    which is what stops a kid-less token from buying an outbound request.

    Both spellings are pinned deliberately: ``kid`` absent, and ``kid: ""``.
    PyJWT will happily MINT the empty-string one (measured — it type-checks
    ``kid`` as ``str`` but does not require it to be non-empty), and it is the
    case that separates the module's ``if not kid`` from an
    ``if "kid" not in header`` that would let ``""`` through to a guaranteed
    cache miss and a JWKS fetch. ``kid: None`` is NOT pinned: PyJWT refuses to
    encode it ("Key ID header parameter must be a string"), so a token in that
    shape cannot reach this verifier through any PyJWT-issued path.
    """
    token = jwt.encode(
        {**_attestation_body(), "iss": ISSUER, "aud": AUDIENCE, "exp": int(time.time()) + 300},
        keypair,
        algorithm="RS256",
        **({} if headers is None else {"headers": headers}),
    )
    assert jwt.get_unverified_header(token).get("kid", "") == "", case

    verifier, seen = _verifier(keypair.public_key())
    result = await verifier.verify(token, expected=_expected())

    assert result.ok is False
    assert result.reason is VerificationReason.MALFORMED_TOKEN
    assert seen == []  # rejected before any JWKS fetch


# --------------------------------------------------------------------------- #
# 16. replay — applier-owned; the verifier's only job is to hand the applier a dedup key
# --------------------------------------------------------------------------- #
async def test_replay(keypair):
    """Replay dedup is document 13 section 10.2 step 1's job, run by the owning domain
    service's transaction against its own ``approval_applications`` table — a process-local
    verifier has no store to dedupe against. What this module DOES contribute: verifying the
    SAME token twice both succeeds (the verifier itself is not the dedup boundary — nothing
    here remembers "seen before") and both results carry the identical ``attestation_id`` an
    applier would key its dedup on. This is a contract check, not replay-protection coverage.
    """
    verifier, _ = _verifier(keypair.public_key())
    token = _issue(keypair)

    first = await verifier.verify(token, expected=_expected())
    second = await verifier.verify(token, expected=_expected())

    assert first.ok is True
    assert second.ok is True  # the verifier alone does not block a replay
    assert first.attestation_id == second.attestation_id == ATTESTATION_ID


# --------------------------------------------------------------------------- #
# 17. revocation
# --------------------------------------------------------------------------- #
_REVOCATION_ORIGIN = frozenset({"http://fr.istio-system.svc"})


async def test_revocation(keypair):
    verifier, seen = _verifier(
        keypair.public_key(), revoked=True, revocation_allowed_origins=_REVOCATION_ORIGIN
    )
    body = _attestation_body(
        revocation_check_ref="http://fr.istio-system.svc/attestation/revocation-status"
    )
    token = _issue(keypair, attestation=body)
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is False
    assert result.reason is VerificationReason.REVOKED
    assert any(r.url.path.endswith("/revocation-status") for r in seen)


async def test_revocation_check_failure_fails_closed(keypair):
    """IMP-DEC-002: "a revoked or expired context fails closed" — an unreachable revocation
    endpoint must reject, not be treated as "not revoked"."""

    def _handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/revocation-status"):
            raise httpx.ConnectError("revocation endpoint unreachable")
        return httpx.Response(200, json=_jwks_doc(keypair.public_key()))

    client = httpx.AsyncClient(transport=httpx.MockTransport(_handler))
    verifier = AttestationVerifier(
        JWKS_URL,
        issuer=ISSUER,
        audience=AUDIENCE,
        client=client,
        revocation_allowed_origins=_REVOCATION_ORIGIN,
    )
    body = _attestation_body(
        revocation_check_ref="http://fr.istio-system.svc/attestation/revocation-status"
    )
    token = _issue(keypair, attestation=body)
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is False
    assert result.reason is VerificationReason.REVOCATION_CHECK_FAILED


async def test_revocation_status_non_object_json_fails_closed(keypair):
    """``resp.json().get(...)`` would raise ``AttributeError`` on a JSON array — not in the
    caught exception tuple, which would escape ``verify()``'s "never raises" contract. Must be
    caught and turned into a fail-closed result instead."""

    def _handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/revocation-status"):
            return httpx.Response(200, json=["not", "an", "object"])
        return httpx.Response(200, json=_jwks_doc(keypair.public_key()))

    client = httpx.AsyncClient(transport=httpx.MockTransport(_handler))
    verifier = AttestationVerifier(
        JWKS_URL,
        issuer=ISSUER,
        audience=AUDIENCE,
        client=client,
        revocation_allowed_origins=_REVOCATION_ORIGIN,
    )
    body = _attestation_body(
        revocation_check_ref="http://fr.istio-system.svc/attestation/revocation-status"
    )
    token = _issue(keypair, attestation=body)
    result = await verifier.verify(token, expected=_expected())  # must not raise
    assert result.ok is False
    assert result.reason is VerificationReason.REVOCATION_CHECK_FAILED


async def test_revocation_ssrf_blocks_disallowed_origin(keypair):
    """``revocation_check_ref`` comes from the TOKEN. A holder of a valid signing key (or a
    compromised issuer) must not be able to point this verifier's outbound request at an
    arbitrary origin — e.g. a cloud metadata endpoint — by naming it in the attestation. No
    allow-list configured here at all, matching the module's fail-closed default."""
    verifier, seen = _verifier(keypair.public_key())  # revocation_allowed_origins=frozenset()
    body = _attestation_body(revocation_check_ref="http://169.254.169.254/latest/meta-data/")
    token = _issue(keypair, attestation=body)
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is False
    assert result.reason is VerificationReason.REVOCATION_CHECK_FAILED
    assert len(seen) == 1  # only the JWKS fetch — the disallowed origin was never requested


async def test_revocation_ssrf_allows_configured_origin(keypair):
    """The positive side of the allow-list: a ``revocation_check_ref`` whose origin IS
    configured is still fetched as usual."""
    verifier, seen = _verifier(
        keypair.public_key(), revoked=False, revocation_allowed_origins=_REVOCATION_ORIGIN
    )
    body = _attestation_body(
        revocation_check_ref="http://fr.istio-system.svc/attestation/revocation-status"
    )
    token = _issue(keypair, attestation=body)
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is True
    assert any(r.url.path.endswith("/revocation-status") for r in seen)


@pytest.mark.parametrize(
    ("ref", "pre_fix_error"),
    [
        pytest.param("http://[oops", "Invalid IPv6 URL", id="unclosed-bracket"),
        pytest.param(
            "http://[oops]",
            "'oops' does not appear to be an IPv4 or IPv6 address",
            id="bracketed-non-address",
        ),
    ],
)
async def test_unparseable_revocation_check_ref_does_not_raise(keypair, ref, pre_fix_error):
    """A ``revocation_check_ref`` whose authority ``urlsplit`` refuses to parse.

    Same never-raises contract as the JWKS cases, on the other side of the
    signature: ``_origin`` was called UNGUARDED, and it raises ``ValueError`` on
    a syntactically impossible authority. Pre-fix, measured, this left
    ``verify()`` as a bare ``ValueError`` — ``Invalid IPv6 URL`` for the first
    case and ``'oops' does not appear to be an IPv4 or IPv6 address`` for the
    second — rather than the ``VerificationResult`` the contract promises.

    Two shapes because they come from different checks inside ``urlsplit`` (the
    unclosed bracket from the bracket scan, the bracketed non-address from
    ``_check_bracketed_host``), and a fix that caught only one of them would look
    identical against a single case.

    STRINGS ARE THE WHOLE OF THE SURFACE HERE, which is why this is narrow: the
    released grammar rejects every non-string and empty ``revocation_check_ref``
    as MALFORMED_ATTESTATION before ``_origin`` is reached — measured for
    ``["http://x"]``, ``{"a": 1}``, ``42``, ``True`` and ``""``. So this is not
    an argument for making ``_origin`` total; it is the one caller handling the
    one input class that gets past the schema.
    """
    verifier, seen = _verifier(keypair.public_key())
    body = _attestation_body(revocation_check_ref=ref)

    result = await verifier.verify(_issue(keypair, attestation=body), expected=_expected())

    assert isinstance(result, VerificationResult)
    assert result.ok is False
    assert result.reason is VerificationReason.REVOCATION_CHECK_FAILED
    # Fails CLOSED, and closed means no outbound request: a ref this verifier
    # cannot resolve to an origin can never be shown to be on the allow-list, so
    # the JWKS fetch must remain the only call made.
    assert len(seen) == 1


async def test_no_revocation_check_ref_is_not_checked(keypair):
    """Revocation state is optional on the released schema (no baked-in boolean — see the
    schema's authoring decision 6). An attestation naming no revocation reference has none to
    ask and verifies as usual."""
    verifier, seen = _verifier(keypair.public_key())
    token = _issue(keypair)  # _attestation_body() carries no revocation_check_ref
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is True
    assert not any(r.url.path.endswith("/revocation-status") for r in seen)


# --------------------------------------------------------------------------- #
# 18. an aggregate changed between approval and application — applier-owned; the verifier's
# only job is to hand the applier the pinned target to compare against the live aggregate
# --------------------------------------------------------------------------- #
async def test_an_aggregate_changed_between_approval_and_application(keypair):
    """Detecting that the aggregate moved past the approved revision needs a live read of the
    aggregate's CURRENT state (document 13 section 10.2 step 3) — this verifier never opens a
    database and cannot know what "current" is. What it DOES contribute: a successful result
    carries the exact pinned ``target`` (including ``aggregate_version``) an applier compares
    against the live row. This is a contract check, not staleness-detection coverage.
    """
    verifier, _ = _verifier(keypair.public_key())
    token = _issue(keypair)

    result = await verifier.verify(token, expected=_expected())

    assert result.ok is True
    assert result.target is not None
    assert result.target["aggregate_id"] == AGGREGATE_ID
    assert result.target["aggregate_version"] == 12
    # An applier reads the aggregate's live version and compares it to this value; if they
    # differ, the applier — not this module — records outcome "stale" on the ApplicationReceipt.


# --------------------------------------------------------------------------- #
# JWKS fetch failure -> fail closed (mirrors internal_token's own coverage of this path)
# --------------------------------------------------------------------------- #
async def test_jwks_fetch_failure_rejected(keypair):
    verifier, _ = _verifier(keypair.public_key(), fail=True)
    token = _issue(keypair)
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is False
    assert result.reason is VerificationReason.UNKNOWN_KEY


# --------------------------------------------------------------------------- #
# JWKS entry that is not a usable RS256 key -> verify() must RETURN, not raise
#
# ``verify()``'s documented contract is that it never raises for a data-driven
# rejection (module docstring: "``verify()`` always returns a
# :class:`VerificationResult`, never raises"). A caller that trusts that and does
# not wrap the call gets an exception where it expected a typed failure.
#
# This is a CONTRACT-CONFORMANCE gap, not a security hole: it fails closed, and
# it is only reachable when FR's OWN configured JWKS serves a key entry this
# verifier cannot use. Nothing here is attacker-chosen — the JWKS URL is
# operator config, not token-controlled.
#
# Two distinct escapes, one per test below. Both were confirmed to RAISE out of
# ``verify()`` against the pre-fix module.
# --------------------------------------------------------------------------- #
async def test_jwks_entry_with_unsupported_kty_does_not_raise(keypair):
    """A JWKS entry whose ``kty`` PyJWT does not implement.

    ``PyJWK.from_dict`` raises ``InvalidKeyError`` (a ``PyJWTError`` subclass) —
    and ``PyJWTError`` is NOT in ``_resolve_key``'s caught
    ``(httpx.HTTPError, OSError, ValueError, KeyError)``, so pre-fix it escaped
    ``verify()`` entirely. Note the entry that does NOT reproduce it: a
    ``kty: oct`` with a valid ``k`` parses fine and yields ``bytes`` — that one
    is covered by the EC test below, which is the same failure one layer later.
    """
    verifier, _ = _verifier(
        keypair.public_key(),
        jwks_docs=[{"keys": [{"kty": "OKP-not-a-real-kty", "kid": KID, "use": "sig"}]}],
    )
    token = _issue(keypair)

    result = await verifier.verify(token, expected=_expected())

    # The assertion that matters is that we got HERE at all rather than propagating.
    assert isinstance(result, VerificationResult)
    assert result.ok is False
    # UNKNOWN_KEY, not MALFORMED_TOKEN: the token is fine, it is the key named by
    # its kid that could not be resolved. That distinction is what tells an
    # operator to look at FR's JWKS rather than at the caller.
    assert result.reason is VerificationReason.UNKNOWN_KEY


async def test_jwks_entry_of_the_wrong_algorithm_family_does_not_raise(keypair):
    """A WELL-FORMED JWKS entry that is simply not an RS256 key — an EC P-256 key.

    This is the nastier of the two, and the reason the fix lives at the cache
    boundary rather than in an ``except``: nothing about this JWKS is malformed,
    so no amount of validating the DOCUMENT catches it. ``PyJWK.from_dict``
    succeeds, the EC public key is cached, and it is only when
    ``jwt.decode(..., algorithms=["RS256"])`` reaches ``RSAAlgorithm.prepare_key``
    that a bare ``TypeError`` ("Expecting a PEM-formatted key") is raised.
    ``TypeError`` is not a ``PyJWTError``, so pre-fix it fell through the whole
    decode except-ladder as well as ``_resolve_key``'s tuple.

    This is exactly the shape an ES256 key rotation on FR's side produces.
    """
    ec_jwk = json.loads(ECAlgorithm.to_jwk(ec.generate_private_key(ec.SECP256R1()).public_key()))
    ec_jwk.update({"kid": KID, "use": "sig"})
    verifier, _ = _verifier(keypair.public_key(), jwks_docs=[{"keys": [ec_jwk]}])
    token = _issue(keypair)

    result = await verifier.verify(token, expected=_expected())

    assert isinstance(result, VerificationResult)
    assert result.ok is False
    assert result.reason is VerificationReason.UNKNOWN_KEY


async def test_one_unusable_jwks_entry_does_not_evict_the_usable_ones(keypair):
    """Anti-vacuity for the SKIP-don't-abort half of the fix.

    Both tests above would also pass if the fix had simply widened
    ``_resolve_key``'s ``except`` and let one bad entry abort the entire refresh
    — the result is UNKNOWN_KEY either way. That version would mean FR adding a
    single ES256 key beside its RS256 one takes every kid down at once, which is
    an outage, not a fix. This pins the difference: a JWKS carrying an unusable
    entry FIRST must still load the good key that follows it.
    """
    good = json.loads(RSAAlgorithm.to_jwk(keypair.public_key()))
    good.update({"kid": KID, "use": "sig", "alg": "RS256"})
    doc = {
        "keys": [
            {"kty": "OKP-not-a-real-kty", "kid": "fr-attestation-rotating-in", "use": "sig"},
            good,
        ]
    }
    verifier, _ = _verifier(keypair.public_key(), jwks_docs=[doc])

    result = await verifier.verify(_issue(keypair), expected=_expected())

    assert result.ok is True
    assert result.reason is VerificationReason.VERIFIED


async def test_jwks_served_as_a_json_array_does_not_raise(keypair):
    """A JWKS body that is an array, not an object.

    Same class as the two above and the same contract: ``doc.get("keys", ...)``
    on a ``list`` is an ``AttributeError``, which is not in ``_resolve_key``'s
    caught tuple. Mirrors the guard ``_check_revoked`` already carries for the
    identical shape on the revocation endpoint.
    """
    verifier, _ = _verifier(keypair.public_key(), jwks_docs=[["not", "an", "object"]])

    result = await verifier.verify(_issue(keypair), expected=_expected())

    assert isinstance(result, VerificationResult)
    assert result.ok is False
    assert result.reason is VerificationReason.UNKNOWN_KEY


@pytest.mark.parametrize(
    "bad_kid",
    [
        pytest.param({"a": 1}, id="object"),
        pytest.param(["a"], id="array"),
    ],
)
async def test_jwks_entry_with_an_unhashable_kid_does_not_raise(keypair, bad_kid):
    """A VALID RSA key whose ``kid`` is not a string — the escape one line past the guard.

    This is the same failure class as the three tests above, but it slips past
    the admission guard rather than through it, which is exactly what made it
    easy to miss. The entry is a perfectly good RSA key: ``PyJWK.from_dict``
    succeeds, ``_JWS_KEY_PREPARER`` succeeds, the ``try`` block completes
    without raising and the guard NEVER FIRES. The exception comes from the
    cache assignment on the following line, which sits outside the ``try``:

        self._keys[kid] = key   ->   TypeError: cannot use 'dict' as a dict key

    ``TypeError`` is not in ``_resolve_key``'s caught tuple, so pre-fix it
    escaped ``verify()`` whole. Reachable exactly as the others are — FR's own
    JWKS serving an entry this verifier cannot use — and it fails the same
    "never raises" contract. Note that ``if not kid`` does NOT screen it: a
    non-empty dict and a non-empty list are both truthy.
    """
    jwk = json.loads(RSAAlgorithm.to_jwk(keypair.public_key()))
    jwk.update({"kid": bad_kid, "use": "sig", "alg": "RS256"})
    verifier, _ = _verifier(keypair.public_key(), jwks_docs=[{"keys": [jwk]}])

    result = await verifier.verify(_issue(keypair), expected=_expected())

    assert isinstance(result, VerificationResult)
    assert result.ok is False
    assert result.reason is VerificationReason.UNKNOWN_KEY


async def test_token_with_an_unpaired_surrogate_does_not_raise(keypair):
    """The one escape on this surface that an UNAUTHENTICATED caller chooses.

    Every other never-raises case in this file needs FR's own JWKS to be
    misconfigured. This one does not: ``jwt.get_unverified_header`` calls
    ``token.encode("utf-8")`` before any JWT parsing, so a token string carrying
    an unpaired UTF-16 surrogate raises ``UnicodeEncodeError`` ("surrogates not
    allowed") out of the encode — never reaching PyJWT's error ladder, and so
    never becoming a ``PyJWTError``.

    The string is built with ``json.loads`` rather than written as a literal to
    pin the REACHABILITY claim rather than merely the mechanism: this is the
    exact value any consumer gets from reading the token out of a JSON request
    body, and it arrives on the very first line of ``verify()``, before
    authentication.
    """
    token = json.loads('{"token": "\\ud800.\\ud800.\\ud800"}')["token"]
    verifier, _ = _verifier(keypair.public_key())

    result = await verifier.verify(token, expected=_expected())

    assert isinstance(result, VerificationResult)
    assert result.ok is False
    assert result.reason is VerificationReason.MALFORMED_TOKEN


@pytest.mark.parametrize(
    "keys_member",
    [
        pytest.param(42, id="number"),
        pytest.param(None, id="null"),
    ],
)
async def test_jwks_keys_member_that_is_not_an_array_does_not_raise(keypair, keys_member):
    """``{"keys": <not an array>}`` — the guard on ``entries``, under test at last.

    Distinct from ``test_jwks_served_as_a_json_array_does_not_raise``, which
    exercises the guard on ``doc``: there the whole BODY is an array, here the
    body is a proper object whose ``keys`` member is not. Deleting
    ``isinstance(entries, list)`` makes ``for jwk in entries`` a
    ``TypeError: 'int' object is not iterable``, which is not in
    ``_resolve_key``'s caught tuple and escapes ``verify()``. Measured: that
    mutant survives the rest of this suite untouched, and these two inputs kill
    it.

    ``42`` and ``null``, deliberately not a STRING: a string ``keys`` is
    iterable, so its characters simply fail the per-entry object check and the
    refresh completes without raising. It would leave the mutant alive, which is
    why it is not used here.
    """
    verifier, _ = _verifier(keypair.public_key(), jwks_docs=[{"keys": keys_member}])

    result = await verifier.verify(_issue(keypair), expected=_expected())

    assert isinstance(result, VerificationResult)
    assert result.ok is False
    assert result.reason is VerificationReason.UNKNOWN_KEY


@pytest.mark.parametrize(
    "entry",
    [
        pytest.param("not-an-object", id="string"),
        pytest.param(None, id="null"),
    ],
)
async def test_jwks_entry_that_is_not_an_object_does_not_raise(keypair, entry):
    """A well-formed ``keys`` ARRAY carrying an element that is not an object.

    Pins the per-entry ``isinstance(jwk, dict)`` guard. Deleting it makes
    ``jwk.get("kid")`` an ``AttributeError: 'str' object has no attribute
    'get'`` — not a ``PyJWTError``, not in ``_resolve_key``'s tuple, straight
    out through ``verify()``. Measured: that mutant also survives the rest of
    this suite, and is killed here.

    Note this is a genuinely separate guard from the one above, not a
    restatement of it: the ``keys`` member here IS a list, so the ``entries``
    guard passes and only this check stands between a junk element and an
    attribute lookup on it.
    """
    verifier, _ = _verifier(keypair.public_key(), jwks_docs=[{"keys": [entry]}])

    result = await verifier.verify(_issue(keypair), expected=_expected())

    assert isinstance(result, VerificationResult)
    assert result.ok is False
    assert result.reason is VerificationReason.UNKNOWN_KEY


@pytest.mark.parametrize(
    "unusable",
    [
        # ValueError, from cryptography's parameter validation: "n must be >= 3."
        pytest.param({"kty": "RSA", "n": "!!!!", "e": "AQAB"}, id="ValueError-bad-modulus"),
        # KeyError, from PyJWK.from_dict: the mandatory symmetric member 'k' is absent.
        pytest.param({"kty": "oct"}, id="KeyError-missing-k"),
    ],
)
async def test_an_unusable_key_parameter_does_not_evict_the_usable_ones(keypair, unusable):
    """The ``ValueError``/``KeyError`` arms of the admission guard — the surviving mutant.

    ⚠️ THE OBVIOUS TEST FOR THESE TWO ARMS IS VACUOUS, and asserting UNKNOWN_KEY
    on a JWKS containing only the bad entry is precisely that. Measured against
    a mutant that drops ``ValueError`` and ``KeyError`` from the guard's tuple,
    both inputs still return ``UNKNOWN_KEY``: the exception escapes
    ``_refresh_keys``, but ``verify()`` catches ``(httpx.HTTPError, OSError,
    ValueError, KeyError)`` around ``_resolve_key`` one level up and converts it
    into the identical rejection. The arms are load-bearing, but the REASON CODE
    cannot see them — which is why the mutant survived a suite that already
    covers both inputs' rejection.

    What the arms actually buy is SKIP rather than ABORT, so that is what is
    asserted here: an unusable entry FIRST must not stop the usable key that
    follows it from loading. Without the arms the whole refresh unwinds, the
    good key is never cached, and this assertion flips from VERIFIED to
    UNKNOWN_KEY. Same shape as
    ``test_one_unusable_jwks_entry_does_not_evict_the_usable_ones``, which pins
    the ``PyJWTError`` arm; these two extend it to the remaining reachable ones.

    Both entries are reachable from FR's own JWKS: a truncated/corrupted modulus
    on an RSA entry, and an ``oct`` entry (what a symmetric key rotation emits)
    that carries no ``k``.
    """
    bad = dict(unusable, kid="fr-attestation-rotating-in", use="sig")
    good = json.loads(RSAAlgorithm.to_jwk(keypair.public_key()))
    good.update({"kid": KID, "use": "sig", "alg": "RS256"})
    verifier, _ = _verifier(keypair.public_key(), jwks_docs=[{"keys": [bad, good]}])

    result = await verifier.verify(_issue(keypair), expected=_expected())

    assert result.ok is True
    assert result.reason is VerificationReason.VERIFIED


# --------------------------------------------------------------------------- #
# THE RESIDUAL, NOW CLOSED — and the pinning test below is #45's, INVERTED.
#
# ⚠️ THE TEST BELOW USED TO ASSERT A DEFECT. Everything above closes a
# KEY-DRIVEN escape from the never-raises contract. The decode ladder also had a
# PAYLOAD-DRIVEN one that no key-side guard can reach: PyJWT's
# ``_validate_exp``/``_validate_nbf``/``_validate_iat`` each do ``int(claim)``
# catching only ``ValueError``, so a non-numeric NON-STRING landed as a bare
# ``TypeError`` — not a ``PyJWTError``, and matched by no arm of the ladder in
# ``verify()``. #45 pinned that as an executable fact and said, in this very
# block, that whoever closed it should "replace ``pytest.raises`` with the
# MALFORMED_TOKEN assertion at that point". That is exactly what happened here,
# and the instruction is the reason the flip is a deliberate act with a diff
# rather than a silent behaviour change nobody reviewed.
#
# It was deferred because it is POST-SIGNATURE: reaching it needs a token FR's
# own JWKS validates, so it is not attacker-reachable the way the surrogate case
# above is, and the same ``int()`` handling existed in ``internal_token.py`` —
# one card, fixed in one pass, not smuggled into a key-resolution PR. Both
# halves landed together; ``test_internal_token.py`` carries the sibling.
#
# The fix is NOT the one-line ``except TypeError`` this block's predecessor
# warned against. ``jwt.decode`` raises the identical bare ``TypeError`` for a
# bad ``audience`` ARGUMENT, and checks it before any claim, so that arm alone
# would have reported MALFORMED_TOKEN for every token forever on one mis-wired
# verifier. The arm is only honest because ``__init__`` now type-checks
# ``audience`` — see the audience-precondition tests further below, which are
# the other half of this fix and must not be separated from it.
# --------------------------------------------------------------------------- #
def _issue_with_time_claim(private_key, claim: str, value: Any) -> str:
    """Sign an otherwise-valid attestation whose ``claim`` carries ``value`` verbatim.

    Not ``_issue``: that computes ``iat``/``exp`` itself and so cannot express a
    non-numeric one, which is the entire point of the cases below.
    """
    now = int(time.time())
    claims: dict[str, Any] = dict(_attestation_body())
    claims.update({"iss": ISSUER, "aud": AUDIENCE, "iat": now, "exp": now + 300})
    claims[claim] = value
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": KID})


@pytest.mark.parametrize(
    ("claim", "value"),
    [
        pytest.param("exp", [1], id="exp-array"),
        pytest.param("nbf", {}, id="nbf-object"),
        # ``iat: null`` raises, but ``exp: null`` does NOT — ``options={"require":
        # ["exp", ...]}`` treats a null-valued required claim as missing and rejects
        # it as MALFORMED_TOKEN before any ``int()`` runs. Not interchangeable.
        pytest.param("iat", None, id="iat-null"),
    ],
)
async def test_payload_time_claim_type_confusion_is_a_typed_rejection(
    keypair, other_key, claim, value
):
    """A CORRECTLY-SIGNED token whose ``exp``/``nbf``/``iat`` is not a number.

    ⚠️ THIS TEST WAS INVERTED, ON PURPOSE, and the inversion IS the fix landing.
    Until this change it was named ``..._still_escapes_verify`` and asserted
    ``pytest.raises(TypeError)`` on the ``int()`` message — it pinned
    the DEFECT so that closing it could not happen silently. #45 wrote it that
    way and left the instruction to replace the ``pytest.raises`` with a
    MALFORMED_TOKEN assertion whenever someone did close it. Deleting it would
    have thrown away the only thing forcing that decision into a reviewable diff,
    so it is rewritten in place instead: same three cases, same helper, same
    control, opposite verdict.

    THE NEW CONTRACT: a non-numeric, non-string time claim is a MALFORMED token,
    not an exception. ``verify()`` documents that it always returns a
    :class:`VerificationResult` for every data-driven rejection, and a JSON type
    the issuer chose is data. MALFORMED_TOKEN specifically, because that is what
    the already-handled STRING-typed sibling has always produced (see
    ``test_a_stringly_typed_time_claim_is_already_handled``) — one defect must not
    get two reason codes depending on which JSON type carried it.

    Measured on pyjwt 2.13. The second half is the control that makes "post-
    signature" an executable claim rather than an assertion: the byte-identical
    payload signed by a key the JWKS does not carry never reaches ``int()`` at
    all, so it comes back as BAD_SIGNATURE, not MALFORMED_TOKEN. That control is
    what keeps the severity framing honest — this was never reachable by an
    unauthenticated caller, and the control is how anyone re-checks that claim
    rather than believing this docstring.
    """
    verifier, _ = _verifier(keypair.public_key())

    result = await verifier.verify(
        _issue_with_time_claim(keypair, claim, value), expected=_expected()
    )
    assert result.ok is False
    assert result.reason is VerificationReason.MALFORMED_TOKEN
    # The reason code is not enough on its own: it must be THIS defect that was
    # converted, not some earlier rejection that happens to share the code. The
    # wording is pyjwt's and changed in 2.15: <2.15 leaked a ``TypeError`` (``int()
    # argument must be...``) that this module converts; >=2.15 checks the type
    # itself (``"... claim (exp) must be an integer."``). Pin the CLAIM, not the text.
    detail = result.detail or ""
    assert f"({claim}) must be an integer" in detail or "int() argument must be" in detail, detail

    # CONTROL: same payload, wrong signer -> a DIFFERENT typed rejection, proving
    # the case is post-signature and that MALFORMED_TOKEN above was not simply
    # what every token gets now.
    result = await verifier.verify(
        _issue_with_time_claim(other_key, claim, value), expected=_expected()
    )
    assert result.ok is False
    assert result.reason is VerificationReason.BAD_SIGNATURE


async def test_a_stringly_typed_time_claim_is_already_handled(keypair):
    """The boundary of the defect above — a ``str`` was NEVER part of it.

    ``int("x")`` raises ``ValueError``, which PyJWT DOES catch and re-raise as a
    ``PyJWTError``, so the ladder has always converted it. Without this control
    the defect reads as "any bad ``nbf`` escaped", which is wrong and would have
    over-scoped the fix: only the non-string types needed new handling. It is
    also what fixes the reason code — the ``except TypeError`` arm returns
    MALFORMED_TOKEN because that is what this path has always returned, not
    because MALFORMED_TOKEN was the nearest available enum member.
    """
    verifier, _ = _verifier(keypair.public_key())

    result = await verifier.verify(
        _issue_with_time_claim(keypair, "nbf", "x"), expected=_expected()
    )

    assert result.ok is False
    assert result.reason is VerificationReason.MALFORMED_TOKEN


# --------------------------------------------------------------------------- #
# THE AUDIENCE PRECONDITION — the other half of the fix above, and the reason it
# is a fix rather than a trap.
#
# ``jwt.decode`` raises a bare ``TypeError`` for a bad ``audience`` ARGUMENT and
# checks it BEFORE it reads any claim, so the ``except TypeError`` arm that
# converts a bad time claim would, on its own, convert one mis-wired verifier
# into MALFORMED_TOKEN for EVERY token forever: a total, silent, permanent auth
# outage that blames the caller. These tests exist so that arm can never be kept
# without the precondition that makes it honest. If someone deletes the
# precondition, ``test_the_audience_typeerror_is_real_in_pyjwt`` still passes
# (it tests PyJWT, not us) but ``test_a_bad_audience_is_refused_at_construction``
# goes red, which is the ordering that matters.
# --------------------------------------------------------------------------- #
# ``expect`` is a fragment of the message each shape must produce, NOT just
# "some ValueError". Matching only on the word "audience" let a mutation survive:
# deleting the bytes branch entirely still raised, because the member-type check
# below it catches a bytes' integers too — so the branch that exists to give an
# operator a comprehensible message had no test that could fail for it. Pinning
# the message per row makes each BRANCH of the precondition individually killable.
@pytest.mark.parametrize(
    ("audience", "expect"),
    [
        # NEW behaviour: these three used to construct fine and then raise a bare
        # ``TypeError`` out of verify() on every token.
        pytest.param(123, r"jwt\.decode raises TypeError", id="int"),
        pytest.param(3.5, r"jwt\.decode raises TypeError", id="float"),
        pytest.param(None, r"jwt\.decode raises TypeError", id="none"),
        # NEW: iterable, so PyJWT accepts the ARGUMENT and then refuses every
        # token — no exception, just "Audience doesn't match" forever.
        pytest.param(b"evidence-review", r"bytes is iterable", id="bytes"),
        pytest.param([], r"non-empty audience", id="empty-list"),
        pytest.param([123], r"every audience member", id="list-of-int"),
        pytest.param(["evidence-review", ""], r"every audience member", id="blank-member"),
        # Already refused before this change (truthiness) — kept as a regression
        # guard so replacing the precondition cannot quietly drop the old check.
        pytest.param("", r"non-empty audience", id="empty-str"),
    ],
)
def test_a_bad_audience_is_refused_at_construction(audience, expect):
    """Every shape that would fail on EVERY token must fail HERE, once, loudly.

    Each parameter was measured through ``verify()`` with a correctly-signed,
    otherwise-valid token before the precondition existed, and each produced a
    permanent total outage rather than a rejection of the offending token:
    ``123``/``3.5`` a bare ``TypeError`` out of ``verify()``, ``b"..."``/``[]``/
    ``[123]`` an ``InvalidAudienceError`` on every token, ``None`` an "Invalid
    audience" on every token that carries an ``aud`` (and no check at all on one
    that does not). ``expect`` pins the message each shape must produce, so every
    BRANCH of the precondition has a test that can fail for it alone.
    """
    with pytest.raises(ValueError, match=expect):
        AttestationVerifier(JWKS_URL, issuer=ISSUER, audience=audience)


async def test_a_generator_audience_is_materialised_not_consumed(keypair):
    """Separate from the table above because its damage is DELAYED, not immediate —
    and because the right answer is to REPAIR it, not refuse it.

    A generator has ``__iter__``, so it satisfies PyJWT's own admission test and
    is then CONSUMED by the first ``jwt.decode``. Measured pre-fix: the first
    token verified ``ok=True`` and every token after it came back
    ``wrong_audience``. A verifier is process-scoped and built once at startup,
    so that is a service which works until its second request — the worst shape
    of the set, and the one a truthiness-or-``__iter__`` check would have let
    straight through.

    It is NOT refused, unlike everything in the table above, and the difference
    is intent: ``audience=123`` cannot mean anything, whereas a generator of the
    right strings means exactly what it looks like. The precondition materialises
    it once at construction, which makes the stored value re-readable and the
    caller's evident intent hold on every request rather than only the first.
    Refusing it would have been the more "defensive" choice and the less useful
    one.

    The assertion is the SECOND verify. A test that called ``verify`` once would
    have passed against the pre-fix code too — that is the whole shape of this
    bug.
    """
    verifier, _ = _verifier(keypair.public_key(), audience=(a for a in [AUDIENCE]))

    first = await verifier.verify(_issue(keypair), expected=_expected())
    second = await verifier.verify(_issue(keypair), expected=_expected())

    assert first.reason is VerificationReason.VERIFIED
    assert second.reason is VerificationReason.VERIFIED  # pre-fix: WRONG_AUDIENCE


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
    """THE CONTROL FOR THE FIX ABOVE: a good token still verifies, TWICE.

    A precondition that refused everything would "close" the trap by causing the
    outage it was written to prevent, and every negative test above would still
    pass. These four shapes are the ones measured to work through ``jwt.decode``
    before this change, so all four must keep working after it — the fix must
    not narrow what a caller may configure, only what it may *mis*-configure.

    Verified TWICE per shape on purpose: the precondition materialises an
    iterable into a tuple, and the second call is what proves the stored value is
    still readable (the generator case above is exactly this property failing).
    """
    verifier, _ = _verifier(keypair.public_key(), audience=audience)

    first = await verifier.verify(_issue(keypair), expected=_expected())
    second = await verifier.verify(_issue(keypair), expected=_expected())

    assert first.ok is True and first.reason is VerificationReason.VERIFIED
    assert second.ok is True and second.reason is VerificationReason.VERIFIED


def test_the_audience_typeerror_is_real_in_pyjwt(keypair):
    """Pins the MECHANISM the precondition exists for, in PyJWT itself.

    Without this, the precondition reads as defensive boilerplate and a later
    reader could reasonably delete it. It asserts the thing our own code can no
    longer demonstrate now that it is guarded: ``jwt.decode`` raises a bare
    ``TypeError`` on the audience ARGUMENT, and does so BEFORE looking at any
    claim — which is precisely why an unguarded ``except TypeError`` arm in
    ``verify()`` would have mapped every token to MALFORMED_TOKEN.

    Deliberately calls PyJWT directly, not our verifier: it is a fact about the
    dependency, and it must go red if pyjwt ever changes it.
    """
    token = _issue(keypair)

    with pytest.raises(TypeError, match="audience must be a string, iterable or None"):
        jwt.decode(
            token,
            keypair.public_key(),
            algorithms=[JWS_ALGORITHM],
            issuer=ISSUER,
            audience=123,
            options={"require": ["exp", "iss", "aud"]},
        )


def test_the_audience_precondition_is_the_shared_rule_not_a_second_copy():
    """Both verifiers screen ``audience`` with the SAME function, not two copies.

    Same reasoning as ``test_admission_is_the_shared_rule_not_a_second_copy`` in
    ``test_internal_token.py``: these two modules have now broken the same
    contract in the same way twice — once on JWKS entries, once on the decode
    ladder — because each carried its own copy of a rule. A future edit that
    reinstates a private audience check in either module reds here rather than
    silently reopening the other module's half.
    """
    from kag_common import _audience, attestation, internal_token

    assert attestation.checked_audience is _audience.checked_audience
    assert internal_token.checked_audience is _audience.checked_audience


# --------------------------------------------------------------------------- #
# cache behaviour (shared mechanism with InternalTokenVerifier)
# --------------------------------------------------------------------------- #
async def test_cache_hit_skips_second_fetch(keypair):
    verifier, seen = _verifier(keypair.public_key())
    await verifier.verify(_issue(keypair), expected=_expected())
    await verifier.verify(_issue(keypair), expected=_expected())
    assert len(seen) == 1  # second verify served from the by-kid cache


async def test_malformed_token_rejected(keypair):
    verifier, _ = _verifier(keypair.public_key())
    result = await verifier.verify("not-a-jwt", expected=_expected())
    assert result.ok is False
    assert result.reason is VerificationReason.MALFORMED_TOKEN


# --------------------------------------------------------------------------- #
# client ownership (shared mechanism with InternalTokenVerifier)
# --------------------------------------------------------------------------- #
async def test_aclose_leaves_borrowed_client_open(keypair):
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))
    )
    verifier = AttestationVerifier(JWKS_URL, issuer=ISSUER, audience=AUDIENCE, client=client)
    await verifier.aclose()
    assert not client.is_closed  # borrowed client is the caller's to close
    await client.aclose()


async def test_aclose_closes_owned_client():
    verifier = AttestationVerifier(JWKS_URL, issuer=ISSUER, audience=AUDIENCE)
    owned = verifier._get_client()
    await verifier.aclose()
    assert owned.is_closed


# --------------------------------------------------------------------------- #
# Adversarial-audit regressions (2026-09-06).
#
# An adversarial audit ran a 28-token corpus through this verifier and its
# TypeScript sibling (fr/backend/src/lib/attestation-verifier.ts) side by side.
# Six tokens that should have been refused VERIFIED here. Each test below is
# named for the corpus case it reproduces, and each was confirmed to go red
# against the pre-fix module before the fix landed -- these are regressions,
# not decoration.
#
# The corpus tokens themselves are NOT pinned into this file: every one carries
# a payload window of 120s, so an embedded token would stop testing its own case
# within two minutes of being written and pass forever after as EXPIRED. Each
# case is reproduced from the same helpers the rest of this file uses, so the
# window is always live.
# --------------------------------------------------------------------------- #


def _two_approvers(first: str, second: str, decision: str = "approve") -> list[dict[str, Any]]:
    return [
        {
            "subject": first,
            "role": "review_lead",
            "decision": "approve",
            "decided_at": "2026-09-02T11:14:07Z",
        },
        {
            "subject": second,
            "role": "auditor",
            "decision": decision,
            "decided_at": "2026-09-02T11:14:07Z",
        },
    ]


# --- S1: one person must not satisfy an M-of-N floor -------------------------- #


@pytest.mark.parametrize(
    ("second_spelling", "what"),
    [
        ("ALICE-SUBJECT", "case variant (corpus 12)"),
        ("alice-subject ", "trailing space (corpus 13)"),
        (" alice-subject", "leading space"),
        # NFKC maps NO-BREAK SPACE onto U+0020, which strip() then removes. Folding in the
        # other order (strip first) would leave this row unmatched — it is the reason
        # _normalise_subject normalises BEFORE it strips.
        ("alice-subject ", "NO-BREAK SPACE padding"),
        # Fullwidth Latin capital A (U+FF21). lower() alone maps it to FULLWIDTH SMALL A,
        # not to "a", so this row is dead unless the NFKC step is present. It is the
        # mutant-killer for deleting the normalize() call and keeping strip+lower.
        ("ＡLICE-SUBJECT", "fullwidth capital — needs NFKC, lower alone is not enough"),
        ("  ALICE-SUBJECT  ", "case variant AND padding together"),
        # Category Cf characters, which NFKC does NOT touch. Each renders as nothing, so an
        # operator reading a log, a ticket or a console sees two identical subjects while raw
        # equality sees two people. Removed EVERYWHERE, not just at the edges — hence the
        # interior ZWSP row. Mirrors the sibling's \p{Cf} strip.
        ("alice\u200b-subject", "interior ZERO WIDTH SPACE"),
        ("\u200dalice-subject\u200c", "ZWJ/ZWNJ padding"),
        ("alice\u00ad-subject", "interior SOFT HYPHEN"),
        ("\ufeffALICE-SUBJECT\u2060", "BOM + WORD JOINER, with a case variant"),
    ],
)
async def test_one_human_spelled_two_ways_does_not_satisfy_two_of_n(keypair, second_spelling, what):
    """The M-of-N floor is only a floor if one person cannot fill two of its slots.

    Counting a ``set`` of RAW subjects was not that test: nothing normalised, so
    ``[{"alice", reviewer, approve}, {"Alice", auditor, approve}]`` and
    ``[{"alice"}, {"alice "}]`` both satisfied ``required_approvals: 2``. Measured, both
    verified. The subject is folded (NFKC, strip, casefold) before the distinct count.

    ``what`` names the spelling trick each row exercises; it is only for the test id.
    """
    verifier, _ = _verifier(keypair.public_key())
    body = _attestation_body(
        required_approvals=2,
        approvers=_two_approvers("alice-subject", second_spelling),
    )
    token = _issue(keypair, attestation=body)
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is False
    assert result.reason is VerificationReason.INSUFFICIENT_APPROVALS
    assert "1 distinct approving subjects" in result.detail


async def test_two_genuinely_different_subjects_do_satisfy_two_of_n(keypair):
    """The control for the test above: normalisation must not merge two REAL humans.

    Without this, folding everything to a constant would pass the whole S1 group while
    breaking every legitimate 2-of-N approval — the fix would be indistinguishable from a
    verifier that refuses all M-of-N tokens.
    """
    verifier, _ = _verifier(keypair.public_key())
    body = _attestation_body(
        required_approvals=2,
        approvers=_two_approvers("alice-subject", "bob-subject"),
    )
    token = _issue(keypair, attestation=body)
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is True
    assert result.reason is VerificationReason.VERIFIED


async def test_confusable_homoglyph_subject_is_deliberately_not_folded(keypair):
    """DOCUMENTS A LIMIT, it does not assert a defence.

    A Cyrillic ``а`` (U+0430) survives NFKC, so ``аlice-subject`` counts as a second
    subject and this token verifies at a floor of 2. That is the residual risk
    ``_normalise_subject`` states and declines to close: folding confusables means a UTS #39
    skeleton, which merges legitimately distinct identifiers and would start refusing real
    approvals. This test exists so the limit is a recorded decision with a live example
    rather than a comment nobody re-derives — if a future change adds skeleton folding, this
    test SHOULD go red and be rewritten, deliberately.
    """
    verifier, _ = _verifier(keypair.public_key())
    body = _attestation_body(
        required_approvals=2,
        approvers=_two_approvers("alice-subject", "аlice-subject"),
    )
    token = _issue(keypair, attestation=body)
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is True, "documented limit: confusables are not folded"


async def test_colliding_subjects_are_counted_once_not_refused(keypair):
    """Pins the DECISION taken for a normalised collision: count once, do not refuse.

    ``[alice, Alice]`` against a floor of ONE is a token in which one human approved and one
    approval was required, so it verifies. Refusing the whole token instead would also refuse
    the harmless shape an issuer can legitimately emit (one person recorded under two roles
    in a single round) and would hand an attacker a way to void a genuine approval by getting
    one duplicate row added. The anomaly is not swallowed: it is logged at WARNING.
    """
    verifier, _ = _verifier(keypair.public_key())
    body = _attestation_body(
        required_approvals=1,
        approvers=_two_approvers("alice-subject", "ALICE-SUBJECT"),
    )
    token = _issue(keypair, attestation=body)
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is True
    assert result.reason is VerificationReason.VERIFIED


async def test_colliding_subjects_are_logged_at_warning(keypair, caplog):
    """The other half of "counted once, never silently": an operator must be able to see it."""
    verifier, _ = _verifier(keypair.public_key())
    body = _attestation_body(
        required_approvals=1,
        approvers=_two_approvers("alice-subject", "ALICE-SUBJECT"),
    )
    token = _issue(keypair, attestation=body)
    with caplog.at_level("WARNING", logger="kag_common.attestation"):
        result = await verifier.verify(token, expected=_expected())
    assert result.ok is True
    assert any("collide after normalisation" in r.message for r in caplog.records)


async def test_self_approval_is_not_evaded_by_a_case_variant(keypair):
    """Separation of duty must not be defeatable with a shift key.

    The self-approval check compared RAW strings too, so an attestation whose approver is
    ``Carol`` passed while ``carol`` was the subject applying the command. Same distinctness
    property as the count above, same fold.
    """
    verifier, _ = _verifier(keypair.public_key())
    body = _attestation_body(
        approvers=[
            {
                "subject": PROPOSER_SUBJECT.upper() + " ",
                "role": "review_lead",
                "decision": "approve",
                "decided_at": "2026-09-02T11:14:07Z",
            }
        ]
    )
    token = _issue(keypair, attestation=body)
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is False
    assert result.reason is VerificationReason.SELF_APPROVAL


async def test_blank_approver_subject_rejected(keypair):
    """A subject that folds away to nothing is not a human, and must not take a slot.

    The released schema does NOT catch this — verified directly: it accepts ``" "`` and
    ``"\\u00a0"`` as an approver subject, both non-empty by ``minLength``. Without this
    branch a blank subject would join the approving set as one anonymous slot.
    """
    verifier, _ = _verifier(keypair.public_key())
    body = _attestation_body(
        approvers=[
            {
                "subject": " ",
                "role": "review_lead",
                "decision": "approve",
                "decided_at": "2026-09-02T11:14:07Z",
            }
        ]
    )
    token = _issue(keypair, attestation=body)
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is False
    assert result.reason is VerificationReason.MALFORMED_ATTESTATION
    assert "blank once normalised" in result.detail


def test_blank_acting_subject_is_refused_at_construction():
    """A blank ``acting_subject`` silently disarms the self-approval check — nothing in the
    approver set can equal it. A caller bug, so it raises rather than returning a result."""
    with pytest.raises(ValueError, match="acting_subject"):
        _expected(acting_subject="   ")


# --- S2: a malformed 200 from the revocation endpoint must fail CLOSED -------- #


@pytest.mark.parametrize(
    "status_body",
    [
        pytest.param({}, id="no-revoked-key"),
        pytest.param({"status": "unknown"}, id="status-unknown"),
        pytest.param({"error": "not found"}, id="error-not-found"),
        pytest.param({"revoked": None}, id="revoked-null"),
        pytest.param({"revoked": "false"}, id="revoked-string-false"),
        pytest.param({"revoked": "true"}, id="revoked-string-true"),
        pytest.param({"revoked": 0}, id="revoked-int-zero"),
        pytest.param({"revoked": 1}, id="revoked-int-one"),
    ],
)
async def test_revocation_200_without_a_json_boolean_fails_closed(keypair, status_body):
    """UNKNOWN IS UNAVAILABLE, NEVER PERMISSION.

    ``bool(data.get("revoked", False))`` is a truthiness test over a defaulted lookup, so a
    200 that never answered the question read as NOT REVOKED and the attestation was
    ACCEPTED. Measured fail-open on the first four bodies here. These are the shapes a status
    endpoint produces when it is misrouted, half-deployed, answering for an id it does not
    know, or fronted by a proxy that turns an error into a 200 — precisely when a revocation
    must be assumed. The stringly-typed rows are the mirror image: ``"false"`` is truthy, so
    a string would have failed the other way. Only a real JSON boolean is an answer.
    """
    verifier, _ = _verifier(
        keypair.public_key(),
        revocation_status=status_body,
        revocation_allowed_origins=frozenset({"http://fr.istio-system.svc"}),
    )
    body = _attestation_body(
        revocation_check_ref="http://fr.istio-system.svc/attestation/revocation-status"
    )
    token = _issue(keypair, attestation=body)
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is False
    assert result.reason is VerificationReason.REVOCATION_CHECK_FAILED


@pytest.mark.parametrize(
    ("status_body", "expected_ok", "expected_reason"),
    [
        pytest.param(
            {"revoked": False}, True, VerificationReason.VERIFIED, id="real-boolean-false"
        ),
        pytest.param({"revoked": True}, False, VerificationReason.REVOKED, id="real-boolean-true"),
    ],
)
async def test_revocation_still_reads_a_real_boolean_either_way(
    keypair, status_body, expected_ok, expected_reason
):
    """Control for the fail-closed group: the fix must not turn every revocation check into a
    refusal. A mutant that raises unconditionally in ``_check_revoked`` passes every test
    above and fails both rows here."""
    verifier, _ = _verifier(
        keypair.public_key(),
        revocation_status=status_body,
        revocation_allowed_origins=frozenset({"http://fr.istio-system.svc"}),
    )
    body = _attestation_body(
        revocation_check_ref="http://fr.istio-system.svc/attestation/revocation-status"
    )
    token = _issue(keypair, attestation=body)
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is expected_ok
    assert result.reason is expected_reason


# --- S3: the payload window has an OPENING edge too --------------------------- #


async def test_payload_issued_at_in_the_future_rejected(keypair):
    """Corpus 09: ``issued_at`` = now+1h, ``expires_at`` = now+1h+120s. VERIFIED before.

    Only the closing edge and the window WIDTH were checked, so a post-dated pair slid
    between them — an approval that has not happened yet, presented as one that has. The
    envelope ``exp`` cannot catch it: the same issuer controls both.
    """
    issued = datetime.now(UTC) + timedelta(hours=1)
    body = _attestation_body(
        issued_at=issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
        expires_at=(issued + timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    verifier, _ = _verifier(keypair.public_key())
    token = _issue(keypair, attestation=body)
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is False
    assert result.reason is VerificationReason.NOT_YET_VALID


async def test_payload_issued_at_inside_the_leeway_still_verifies(keypair):
    """Control: the opening edge honours the SAME 30s leeway every other timestamp check here
    uses. A mutant that drops the leeway (``issued_at > now``) passes the test above and
    fails this one — and would reject a large share of legitimate traffic, since a fresh
    attestation's ``issued_at`` is by definition within seconds of now on a skewed clock."""
    issued = datetime.now(UTC) + timedelta(seconds=CLOCK_LEEWAY_SECONDS - 10)
    body = _attestation_body(
        issued_at=issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
        expires_at=(issued + timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    verifier, _ = _verifier(keypair.public_key())
    token = _issue(keypair, attestation=body)
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is True


async def test_payload_window_inverted_rejected(keypair):
    """``expires_at`` at or before ``issued_at`` is not a window. Neither edge check catches
    it on its own — inside the leeway band a pair satisfies both — and the TTL ceiling only
    bounds the window from ABOVE, so a negative width passed it trivially."""
    issued = datetime.now(UTC) + timedelta(seconds=10)
    body = _attestation_body(
        issued_at=issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
        expires_at=(issued - timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    verifier, _ = _verifier(keypair.public_key())
    token = _issue(keypair, attestation=body)
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is False
    assert result.reason is VerificationReason.NOT_YET_VALID


# --- S4: two bindings that were never compared -------------------------------- #


async def test_target_wrong_aggregate_type(keypair):
    """Corpus 20: the attestation targets ``aggregate_type`` "other_thing", the caller is
    applying to "review". VERIFIED before — ``aggregate_type`` was in the schema and in the
    token and was compared nowhere, and ``ExpectedApplication`` had no field to compare it
    against. An ``aggregate_id`` is unique only WITHIN a type, so the approval was bound to a
    coordinate that does not identify a row."""
    verifier, _ = _verifier(keypair.public_key())
    target = dict(_attestation_body()["target"])
    target["aggregate_type"] = "other_thing"
    token = _issue(keypair, attestation=_attestation_body(target=target))
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is False
    assert result.reason is VerificationReason.WRONG_TARGET


@pytest.mark.parametrize("which", ["profile_ref", "policy_ref"])
async def test_pinned_ref_content_hash_tampered(keypair, which):
    """Corpus 19: the caller's expected ``version_id`` matches, the ``content_hash`` does not.

    VERIFIED before, because only ``version_id`` was compared. The version id says WHICH pin;
    the content hash says WHAT WAS IN IT — a profile edited in place under a reused version
    id, or a (version_id, content_hash) pair reassembled from two different releases, is
    exactly what binding to both refuses. Parametrised over both refs: they are separate
    comparisons and a mutant can delete either one.
    """
    approved_hash = "sha256:" + "33" * 32
    tampered_hash = "sha256:" + "44" * 32
    version_id = "22222222-2222-2222-2222-222222222222"
    pinned = {
        "owner_context": "evidence-review",
        "entity_type": "profile_release",
        "entity_id": "11111111-1111-1111-1111-111111111111",
        "resource_scope": "global",
        "version_id": version_id,
        "version_number": 1,
        "schema_ref": "urn:datacompany:profile-release:1",
        "content_hash": approved_hash,
        "resolved_at": "2026-09-02T11:14:08Z",
    }
    verifier, _ = _verifier(keypair.public_key())
    token = _issue(keypair, attestation=_attestation_body(**{which: pinned}))
    # Same version_id, DIFFERENT content hash.
    result = await verifier.verify(
        token, expected=_expected(**{which: PinnedRef(version_id, tampered_hash)})
    )
    assert result.ok is False
    assert result.reason is VerificationReason.WRONG_PROFILE_OR_POLICY
    assert result.detail == which

    # Control: the matching pair verifies, so the test above is not passing because the
    # comparison refuses everything.
    verifier2, _ = _verifier(keypair.public_key())
    ok = await verifier2.verify(
        token, expected=_expected(**{which: PinnedRef(version_id, approved_hash)})
    )
    assert ok.ok is True


# --- S6: an unauthenticated kid must not buy an outbound fetch ---------------- #


async def test_a_burst_of_unknown_kids_makes_at_most_one_jwks_fetch(keypair):
    """``kid`` is read from the token's UNVERIFIED header, so an unauthenticated caller picks
    it. Forcing a refresh on every miss made this verifier a fetch amplifier: measured, 50
    garbage tokens with 50 random kids produced 50 JWKS requests, entirely at FR's expense.
    The refresh is now rate-limited to one per ``JWKS_REFRESH_COOLDOWN_SECONDS``, mirroring
    ``jose``'s ``createRemoteJWKSet`` cooldown that the TypeScript sibling relies on."""
    verifier, seen = _verifier(keypair.public_key())
    for i in range(50):
        token = _issue(keypair, kid=f"attacker-kid-{i}")
        result = await verifier.verify(token, expected=_expected())
        assert result.ok is False
        assert result.reason is VerificationReason.UNKNOWN_KEY
    assert len(seen) == 1, f"{len(seen)} JWKS fetches for 50 unauthenticated tokens"


async def test_a_failing_jwks_endpoint_is_also_only_hit_once_per_cooldown(keypair):
    """The cooldown is stamped on the ATTEMPT, not on a success. A dead JWKS endpoint is
    exactly the one that must not be re-hit by every token in a burst — stamping only on
    success would leave the amplification fully open whenever FR is down."""
    verifier, seen = _verifier(keypair.public_key(), fail=True)
    for i in range(10):
        result = await verifier.verify(_issue(keypair, kid=f"k-{i}"), expected=_expected())
        assert result.ok is False
        assert result.reason is VerificationReason.UNKNOWN_KEY
    assert len(seen) == 1


async def test_a_rotated_key_still_resolves_once_the_cooldown_has_passed(keypair, other_key):
    """The cooldown must be a RATE LIMIT, not a one-shot latch.

    A mutant that simply refuses to refresh more than once passes both tests above and fails
    this one. Here the JWKS serves only the old kid on the first fetch and the rotated kid on
    the next; with the cooldown elapsed (0s), a token signed under the new kid resolves — the
    key-rotation-without-a-restart property this module has always claimed.
    """
    old_doc = _jwks_doc(keypair.public_key(), "old-kid")
    new_doc = _jwks_doc(other_key.public_key(), "rotated-kid")
    verifier, seen = _verifier(
        keypair.public_key(), refresh_cooldown=0.0, jwks_docs=[old_doc, new_doc]
    )
    first = await verifier.verify(_issue(other_key, kid="rotated-kid"), expected=_expected())
    assert first.reason is VerificationReason.UNKNOWN_KEY  # only old_doc served yet
    second = await verifier.verify(_issue(other_key, kid="rotated-kid"), expected=_expected())
    assert second.ok is True, "a rotated key must resolve once the cooldown has passed"
    assert len(seen) == 2


# --- SSRF: documented, and the module-owned client is explicit about it ------- #


async def test_module_owned_client_does_not_follow_redirects():
    """The SSRF allow-list is checked ONCE, against the origin named in the token, before any
    request — so it cannot see a 3xx the server answers with. An allow-listed status endpoint
    replying ``302 Location: http://169.254.169.254/...`` would otherwise walk this verifier
    straight onto the link-local metadata address.

    Set explicitly rather than inherited from the ``httpx`` default, which is not this
    module's to guarantee. A caller-injected ``client=`` with ``follow_redirects=True`` still
    reopens this — that is stated in ``AttestationVerifier``'s docstring, and it cannot be
    asserted here because the injected client is by construction the caller's choice.
    """
    verifier = AttestationVerifier(JWKS_URL, issuer=ISSUER, audience=AUDIENCE)
    try:
        assert verifier._get_client().follow_redirects is False
    finally:
        await verifier.aclose()


# --- where the required_approvals >= 1 control ACTUALLY lives ----------------- #
#
# The audit flagged this as a dud mutant and it is: deleting `or required_approvals < 1`
# from attestation.py leaves the whole suite green. That is not a weak test — the real
# control is upstream, and the three tests below locate it rather than assume it.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("bad", [0, -1, 1.5, "2", None, True])
def test_the_released_schema_is_what_refuses_required_approvals_below_one(bad):
    """MEASURED, not assumed: ``required_approvals: 0`` never reaches this module's own
    ``< 1`` guard, because ``research-contracts`` refuses it first.

    ``approval-attestation.v1.schema.json`` line 92: ``{"type": "integer", "minimum": 1,
    "maximum": 64}``. This test asserts against the schema DIRECTLY, so if a future
    research-contracts ever relaxes that keyword the failure lands here, pointing at the
    module guard that then becomes load-bearing — rather than silently promoting
    attestation.py's redundant check into the only defence with nothing to say so.
    ``pyproject.toml`` floors research-contracts at >=0.9.0 and does not pin it, which is the
    entire reason attestation.py keeps its own guard.
    """
    from research_contracts.canonical import CanonicalError, assert_valid_instance

    body = _attestation_body(required_approvals=bad)
    with pytest.raises(CanonicalError):
        assert_valid_instance(body, "urn:datacompany:approval-attestation:1")


@pytest.mark.parametrize("integral_float", [1.0, 2.0])
def test_the_schema_accepts_an_integral_float_required_approvals(integral_float):
    """The seam the schema leaves open, measured: JSON Schema's ``"type": "integer"`` accepts
    a number with a zero fractional part, so ``2.0`` validates. This is the gap
    attestation.py's ``isinstance(..., int)`` arm actually covers — see the next test."""
    from research_contracts.canonical import assert_valid_instance

    assert_valid_instance(
        _attestation_body(required_approvals=integral_float),
        "urn:datacompany:approval-attestation:1",
    )


async def test_float_required_approvals_rejected_by_this_module(keypair):
    """The NON-dud half of the ``required_approvals`` guard.

    ``2.0`` gets past the released schema (previous test) and is not an ``int``, so a
    comparison against a float count is this module's to refuse. Deleting the
    ``isinstance(required_approvals, int)`` arm turns this test red — so the guard as a whole
    is not vacuous, even though its ``< 1`` arm is currently unreachable.
    """
    verifier, _ = _verifier(keypair.public_key())
    token = _issue(keypair, attestation=_attestation_body(required_approvals=2.0))
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is False
    assert result.reason is VerificationReason.MALFORMED_ATTESTATION
    assert "integer >= 1" in result.detail


# --- cross-verifier parity: the folds this module deliberately does NOT do ---- #
#
# _normalise_subject must stay behaviourally identical to canonicalSubject in
# fr/backend/src/lib/attestation-verifier.ts. Two verifiers of one attestation that fold
# differently are governed by the WEAKER of the two, and the divergence is itself a defect.
# The tests below pin the agreed boundary from the weak side, so a well-meaning unilateral
# strengthening here goes red instead of silently desynchronising the fleet.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("second_spelling", "limit"),
    [
        pytest.param("STRASSE-SUBJECT", "full case folding (ß/ss)", id="case-fold"),
        pytest.param("аlice-subject", "confusables/homoglyphs", id="homoglyph"),
        pytest.param("josé-subject", "diacritics", id="diacritic"),
        pytest.param("alice subject", "internal whitespace", id="internal-space"),
    ],
)
async def test_documented_normalisation_limits_are_not_folded(keypair, second_spelling, limit):
    """DOCUMENTS LIMITS, does not assert defences — and pins them for cross-verifier parity.

    Each row is a fold this module could do and deliberately does not, because the TypeScript
    sibling cannot or does not: ``str.lower()`` is used instead of ``casefold()`` precisely so
    ``straße``/``strasse`` stay distinct on both sides. If a future change adds any of these
    folds, the matching row SHOULD go red — at which point the sibling changes in the same
    commit-pair, or not at all.

    The first row's baseline subject is deliberately the ß spelling so the pair is a real
    case-fold collision and not merely two different names.
    """
    first = "straße-subject" if second_spelling == "STRASSE-SUBJECT" else "alice-subject"
    verifier, _ = _verifier(keypair.public_key())
    body = _attestation_body(required_approvals=2, approvers=_two_approvers(first, second_spelling))
    token = _issue(keypair, attestation=body)
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is True, f"documented limit ({limit}) is expected NOT to be folded"


async def test_lower_is_used_not_casefold(keypair):
    """The parity decision, isolated from any token.

    ``casefold()`` would fold ``ß`` to ``ss``; ``lower()`` does not, and JavaScript has no
    full-case-fold primitive for the sibling to match. A mutant swapping ``.lower()`` for
    ``.casefold()`` is stronger in isolation and WRONG in the fleet — it goes red here.
    """
    from kag_common.attestation import _normalise_subject

    assert _normalise_subject("STRASSE") == "strasse"
    assert _normalise_subject("straße") == "straße"
    assert _normalise_subject("STRASSE") != _normalise_subject("straße")
    # ...while everything the contract DOES fold still folds.
    assert _normalise_subject("  ﻿ＡLI​CE­  ") == "alice"
    assert _normalise_subject("​­ ") is None  # Cf + space folds away to nothing


def test_the_released_schema_refuses_a_non_z_timestamp_offset():
    """The payload timestamp grammar is trailing-``Z`` ONLY, and the schema owns that rule.

    Measured directly against ``research_contracts``: ``...+02:00`` and ``...+00:00`` are
    REJECTED, ``...Z`` and ``...123Z`` accepted. This matters because ``_parse_timestamp``
    normalises ``Z`` to ``+00:00`` and hands the result to ``datetime.fromisoformat``, which
    would happily accept an explicit offset — but structural validation runs FIRST, so an
    offset-bearing token never reaches it. This module deliberately does not re-derive the
    format rule (see the module docstring); this test is what makes that delegation checked
    rather than assumed, and it goes red if the schema ever loosens.
    """
    from research_contracts.canonical import CanonicalError, assert_valid_instance

    for accepted in ("2026-09-02T11:14:07Z", "2026-09-02T11:14:07.123Z"):
        assert_valid_instance(
            _attestation_body(issued_at=accepted, expires_at="2126-09-02T11:16:07Z"),
            "urn:datacompany:approval-attestation:1",
        )
    for refused in (
        "2026-09-02T11:14:07+02:00",
        "2026-09-02T11:14:07+00:00",
        "2026-09-02 11:14:07",
    ):
        with pytest.raises(CanonicalError):
            assert_valid_instance(
                _attestation_body(issued_at=refused, expires_at="2126-09-02T11:16:07Z"),
                "urn:datacompany:approval-attestation:1",
            )


# --- THE CROSS-LANGUAGE PARITY HARNESS ---------------------------------------- #
#
# THIS IS THE TEST WHOSE ABSENCE LET TWO ROUNDS OF FIXES DIVERGE. Everything above
# tests THIS implementation against ITSELF. The defect being closed here is not a
# property of either implementation — it is a property of the RELATION between them,
# and no amount of single-sided testing can see it. Both suites were fully green while
# `str.strip()` here removed five code points that `String.prototype.trim()` in the
# sibling did not, so an approver pair [alice, U+001C + alice] was
# `insufficient_approvals` here and VALID there. The fleet is governed by the weaker
# verifier, so a green suite on this side proved nothing about the guarantee.
#
# The instrument is a frozen corpus committed BYTE-IDENTICALLY to both repositories,
# with its sha256 pinned as a literal in both suites. Editing it on one side alone
# turns that side red. Rows are hand-reviewed against the four documented steps, not
# generated from either implementation's output — a fixture regenerated from the code
# it grades cannot fail for a mutation of that code.
# ------------------------------------------------------------------------------ #

#: sha256 of ``tests/fixtures/subject-canonicalisation-parity.json``.
#:
#: ⚠️ THE IDENTICAL LITERAL IS RECORDED IN THE SIBLING'S SUITE
#: (``fr/backend/tests/unit/attestation-verifier.test.ts``). If the two ever differ,
#: the two corpora have diverged and the parity claim is void. Changing the corpus
#: means changing this constant AND the sibling's, in the same commit-pair.
PARITY_CORPUS_SHA256 = (
    "a3930816e39507a4c0f3cc538dbdcb3fb762a26185cb591661ec6eb97ea10645"  # pragma: allowlist secret
)

PARITY_CORPUS_PATH = Path(__file__).parent / "fixtures" / "subject-canonicalisation-parity.json"
_PARITY_CORPUS = json.loads(PARITY_CORPUS_PATH.read_text(encoding="utf-8"))
PARITY_CASES = _PARITY_CORPUS["cases"]


def test_the_parity_corpus_is_the_one_the_sibling_grades_against():
    """Pin the corpus bytes, because a shared instrument only works while it is shared.

    Without this, the corpus is two files that merely started identical. Any edit here that
    is not mirrored in the sibling silently restores the isolation that caused the defect —
    and it restores it INVISIBLY, because both suites would still be green.
    """
    digest = hashlib.sha256(PARITY_CORPUS_PATH.read_bytes()).hexdigest()
    assert digest == PARITY_CORPUS_SHA256, (
        f"parity corpus changed ({digest}); mirror the change into "
        "fr/backend/tests/fixtures/subject-canonicalisation-parity.json and update "
        "PARITY_CORPUS_SHA256 in BOTH suites"
    )


def test_the_parity_corpus_is_not_vacuous():
    """A corpus that folded everything to one answer would pass any implementation.

    Including one that returns a constant, and including one that refuses every subject.
    The floors below are the anti-vacuity guard: a real spread of expected outputs, at least
    one legitimate identity, and at least one subject that must fold away to nothing.
    """
    canonicals = {c["canonical"] for c in PARITY_CASES.values()}
    assert len(PARITY_CASES) >= 100, f"only {len(PARITY_CASES)} cases"
    assert len(canonicals) >= 30, f"only {len(canonicals)} distinct expected outputs"
    assert "alice" in canonicals, "no case asserts a normal identity survives"
    assert "" in canonicals, "no case asserts a subject folds away to nothing"


@pytest.mark.parametrize("name", sorted(PARITY_CASES), ids=sorted(PARITY_CASES))
def test_cross_language_canonicalisation_parity(name):
    """Every adversarial subject folds to exactly the value the sibling must also produce.

    An empty ``canonical`` means the subject folds away entirely and the verifier must refuse
    it — ``_normalise_subject`` returns ``None`` there, which the caller turns into
    ``invalid_approver``.
    """
    case = PARITY_CASES[name]
    assert (_normalise_subject(case["subject"]) or "") == case["canonical"]


# --- F1 regression: one test per code point that actually diverged ------------- #
#
# `str.strip()` removes all five; `String.prototype.trim()` removes none of them. All
# five are Unicode general category Cc, which is why the fix strips the CATEGORY rather
# than blacklisting the five characters. Each is tested at the EDGE (where the two
# default trims disagreed) and INSIDE the string (where neither ever reached).
# ------------------------------------------------------------------------------ #

DIVERGING_CODE_POINTS = [
    pytest.param(0x0085, id="U+0085-NEL"),
    pytest.param(0x001C, id="U+001C-FILE-SEPARATOR"),
    pytest.param(0x001D, id="U+001D-GROUP-SEPARATOR"),
    pytest.param(0x001E, id="U+001E-RECORD-SEPARATOR"),
    pytest.param(0x001F, id="U+001F-UNIT-SEPARATOR"),
]


@pytest.mark.parametrize("code_point", DIVERGING_CODE_POINTS)
@pytest.mark.parametrize("placement", ["leading", "trailing", "interior"])
async def test_a_control_character_does_not_mint_a_second_approver(keypair, code_point, placement):
    """One person plus one invisible C0 byte must not clear a two-human floor.

    This is the THIRD spelling of this defect: ``[alice, alice]`` was killed by the raw
    ``set``, ``[alice, Alice]`` defeated that and was killed by ``lower()``, and
    ``[alice, U+001C + alice]`` defeated THAT — in the sibling, which is the half that
    governs. Measured on freshly signed tokens at ``required_approvals: 2``.
    """
    char = chr(code_point)
    base = "alice-subject"
    second = {
        "leading": char + base,
        "trailing": base + char,
        "interior": base[:3] + char + base[3:],
    }[placement]

    verifier, _ = _verifier(keypair.public_key())
    body = _attestation_body(required_approvals=2, approvers=_two_approvers(base, second))
    token = _issue(keypair, attestation=body)
    result = await verifier.verify(token, expected=_expected())

    assert result.ok is False
    assert result.reason is VerificationReason.INSUFFICIENT_APPROVALS
    assert "1 distinct approving subjects" in result.detail


@pytest.mark.parametrize("code_point", DIVERGING_CODE_POINTS)
async def test_a_control_character_does_not_bypass_self_approval(keypair, code_point):
    """The same five code points re-opened the self-approval gate, not only the M-of-N floor.

    Both gates compare on the canonical key, so both had to be regression-tested: an acting
    principal that pads its own name with one invisible C0 byte was approving its own command
    in the sibling and reading ``valid``.
    """
    padded = chr(code_point) + PROPOSER_SUBJECT + chr(code_point)
    verifier, _ = _verifier(keypair.public_key())
    body = _attestation_body(
        required_approvals=1,
        approvers=_two_approvers(padded, "bob-subject"),
    )
    token = _issue(keypair, attestation=body)
    result = await verifier.verify(token, expected=_expected())

    assert result.ok is False
    assert result.reason is VerificationReason.SELF_APPROVAL


@pytest.mark.parametrize("code_point", DIVERGING_CODE_POINTS)
def test_each_diverging_code_point_folds_away_entirely(code_point):
    """The unit-level statement of the same fact, isolated from any token.

    A subject that is NOTHING BUT the control character canonicalises to nothing and is
    refused, rather than becoming a subject that quietly matches nothing.
    """
    char = chr(code_point)
    assert _normalise_subject(char + "alice" + char) == "alice"
    assert _normalise_subject("al" + char + "ice") == "alice"
    assert _normalise_subject(char) is None


def test_the_trim_class_is_explicit_and_holds_no_control_characters():
    """The constants themselves, because the defect was in a DEFAULT nobody had enumerated.

    ``SUBJECT_TRIMMED_CHARACTERS`` is passed explicitly to ``str.strip``; a bare
    ``str.strip()`` is what diverged. Asserting the class contains no ``Cc`` is what keeps a
    future "simplification" from quietly reintroducing Python's whitespace table, which is
    the sibling's table plus these five characters.
    """
    assert SUBJECT_REMOVED_CATEGORIES == frozenset({"Cc", "Cf"})
    assert set(SUBJECT_TRIMMED_CHARACTERS) == {
        chr(cp)
        for cp in (
            0x0020,
            0x00A0,
            0x1680,
            *range(0x2000, 0x200B),
            0x2028,
            0x2029,
            0x202F,
            0x205F,
            0x3000,
        )
    }, "the trim class is U+0020 plus categories Zs/Zl/Zp, and nothing else"
    assert not [c for c in SUBJECT_TRIMMED_CHARACTERS if unicodedata.category(c) == "Cc"], (
        "the trim class must contain no control characters — Python's default whitespace "
        "set does, JavaScript's does not, and that gap is the defect"
    )
    for cp in (0x0085, 0x001C, 0x001D, 0x001E, 0x001F):
        assert chr(cp) not in SUBJECT_TRIMMED_CHARACTERS
        assert unicodedata.category(chr(cp)) in SUBJECT_REMOVED_CATEGORIES


# --- F2: ALİCE (U+0130) was a second approver in BOTH implementations ---------- #


async def test_a_dotted_capital_i_does_not_mint_a_second_approver(keypair):
    """``lower()`` maps U+0130 to ``i`` + U+0307, which is not ``i``.

    Parity-consistent — the sibling's ``toLowerCase()`` does exactly the same — so this was
    never a DIVERGENCE, and it was still precisely the "one person plus a shift key" property
    the M-of-N floor exists to enforce. Closed on both sides by removing the combining dot
    that lowercasing manufactures, which is narrower than stripping diacritics generally.
    """
    verifier, _ = _verifier(keypair.public_key())
    body = _attestation_body(
        required_approvals=2,
        approvers=_two_approvers("alice-subject", "ALİCE-SUBJECT"),
    )
    token = _issue(keypair, attestation=body)
    result = await verifier.verify(token, expected=_expected())

    assert result.ok is False
    assert result.reason is VerificationReason.INSUFFICIENT_APPROVALS


async def test_the_combining_dot_bypass_is_closed_too(keypair):
    """Fixing ONLY U+0130 would have been theatre: the attacker types the output instead.

    An attacker who can put ``AL`` + U+0130 + ``CE`` in a subject can equally put
    ``ali`` + U+0307 + ``ce`` there, which is byte-for-byte what lowercasing U+0130 produces.
    A fix that folded the capital but not its own lowercase form would close nothing, so the
    rule is stated on the LOWERCASE sequence and this test is what says so.
    """
    verifier, _ = _verifier(keypair.public_key())
    body = _attestation_body(
        required_approvals=2,
        approvers=_two_approvers("alice-subject", "ali\u0307ce-subject"),
    )
    token = _issue(keypair, attestation=body)
    result = await verifier.verify(token, expected=_expected())

    assert result.ok is False
    assert result.reason is VerificationReason.INSUFFICIENT_APPROVALS


def test_the_soft_dotted_i_fold_is_narrow_and_repeat_safe():
    """It removes the manufactured dot and nothing else — the diacritic limit still holds."""
    assert _normalise_subject("ALİCE") == "alice"
    assert _normalise_subject("ali\u0307ce") == "alice"
    # Repeats: a single non-greedy pass would leave one dot behind.
    assert _normalise_subject("ali\u0307\u0307ce") == "alice"
    # NOT a general diacritic strip: non-defence 3 is unchanged.
    assert _normalise_subject("josé") != _normalise_subject("jose")
    # The dot is only redundant ON an i; it is not removed from anything else.
    assert _normalise_subject("al\u0227ce") == "al\u0227ce"
    # ...and a decomposed dot on a NON-i letter composes under NFKC rather than
    # being dropped, which is what makes the i-rule narrow rather than a mark strip.
    assert _normalise_subject("ala\u0307ce") == "al\u0227ce"


async def test_the_dotless_i_is_deliberately_not_folded(keypair):
    """DOCUMENTS A LIMIT (non-defence 2), it does not assert a defence.

    Turkish dotless ``ı`` (U+0131) is VISIBLY different from ``i`` — it has no dot — and no
    lowercase mapping produces it, so it is a confusable, not an invisible. ``alıce`` counts
    as a second subject and this token verifies at a floor of 2. If a future change adds
    confusable folding, this test SHOULD go red and be rewritten, deliberately.
    """
    verifier, _ = _verifier(keypair.public_key())
    body = _attestation_body(
        required_approvals=2,
        approvers=_two_approvers("alice-subject", "alıce-subject"),
    )
    token = _issue(keypair, attestation=body)
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is True, "documented limit: the dotless i is a confusable, not folded"


async def test_two_genuinely_different_subjects_still_clear_the_floor(keypair):
    """THE POSITIVE CONTROL for this whole section.

    Every test above asserts a REFUSAL. A canonicaliser that folded every subject to one
    value — or a verifier that refused every M-of-N token — would satisfy all of them. This
    is the row that fails if the fix over-merges, and it is deliberately the last word in the
    section rather than an afterthought.
    """
    verifier, _ = _verifier(keypair.public_key())
    body = _attestation_body(
        required_approvals=2,
        approvers=_two_approvers("alice-subject", "bob-subject"),
    )
    token = _issue(keypair, attestation=body)
    result = await verifier.verify(token, expected=_expected())
    assert result.ok is True
    assert result.reason is VerificationReason.VERIFIED
