"""Verify FR ``ApprovalAttestation`` objects (Lane FND-008, document 13 section 10.1).

Foundation Review (FR) mints a short-lived RS256 JWS whenever a human approval clears a
gated command, carrying the claim set released as ``urn:datacompany:approval-attestation:1``
(``research_contracts/schemas/approvals/approval-attestation.v1.schema.json``). A domain
service that wants to apply that command must verify the attestation *before* touching
anything, and this module is that verifier — the ``kag_common`` half of ``FND-008``
(``FND-008I``; the FR signer itself is ``FND-008P`` and does not exist in this estate yet,
see ``DataCompany/implementation-plans/HANDOFF-2026-09-04a-…md`` section 5).

``13-new-services-shared-implementation-foundation.md`` section 10.1 closes with: **"The
verifier produces a typed verification result; it does not apply the command."** This module
honours that literally. It never opens a database connection, never writes anything, and
never calls the owning service's apply path — ``verify()`` is a pure function of (token,
JWKS, expectation) to a :class:`VerificationResult`. Section 10.2's seven-step atomic
application (dedupe, reauthorize, re-verify the current revision, apply, write the
``ApplicationReceipt``, emit the event) is the *owning domain service's* job, not this
module's — it is per-service because the aggregate, the current-revision read and the
outbox all live in that service's own database.

Two of section 10.3's eighteen negative cases follow directly from that boundary and are
**not implemented here**:

* **replay** needs a dedup store keyed on ``attestation_id`` (section 10.2 step 1) — a
  process-local verifier has no persistent state to dedupe against, and inventing an
  in-memory one would be a second, inconsistent copy of what the applier's transaction
  already guarantees.
* **an aggregate changed between approval and application** needs a live read of the
  aggregate's *current* revision (section 10.2 step 3) — this module never touches a
  database, so it cannot know what the current revision is.

For both, this module's contribution is only that :class:`VerificationResult` carries the
fields an applier needs to perform its own check (``attestation_id`` for the dedup key,
``target`` for the current-revision comparison) — see the module-level tests for the
assertion of that contract, and do not mistake it for coverage of the case itself.

Everything else in section 10.3's eighteen cases — wrong audience, signature, key,
approval/task ID, target, command hash, input revision, profile/policy, approval round,
approver subject, role, decision, count, self-approval, expiry, and revocation — is checked
here, either at the JWS envelope (via ``pyjwt``), structurally against the released schema
(via ``research_contracts.canonical.assert_valid_instance``, so this module never re-derives
a format rule the schema already owns), or semantically against the caller-supplied
:class:`ExpectedApplication`.

Mirrors ``kag_common.internal_token.InternalTokenVerifier``'s shape: async, ``httpx.AsyncClient``
with the same tight timeouts, a ``cachetools.TTLCache`` keyed by ``kid``, and a JWKS refresh on
an unknown ``kid`` — rate-limited to at most one fetch per :data:`JWKS_REFRESH_COOLDOWN_SECONDS`,
because ``kid`` comes from the token's *unverified* header and an unauthenticated burst of
random ``kid``s otherwise turned this verifier into a fetch amplifier (a key rotation still
recovers without a restart, within the cooldown). It deliberately does **not** mirror that
module's raise-on-failure contract: section
10.1 requires distinguishing many failure reasons that call for different operator responses
(a replay looks nothing like an expiry), and eighteen exception subclasses would be worse than
one typed result — so ``verify()`` always returns a :class:`VerificationResult`, never raises,
for every data-driven rejection. It still raises for genuine programmer/transport errors it
cannot classify (e.g. a caller passing a non-``str`` token).

Usage (build one verifier at startup per audience, reuse it so the JWKS cache survives):

    from kag_common.attestation import AttestationVerifier, ExpectedApplication, PinnedRef

    verifier = AttestationVerifier(
        jwks_url=settings.fr_attestation_jwks_url,
        issuer=settings.fr_attestation_issuer,
        audience="evidence-review",
    )
    expected = ExpectedApplication(
        target_service="evidence-review",
        aggregate_type="evidence_snapshot",
        aggregate_id=review_id,
        aggregate_version=current_version,
        input_revision=snapshot_hash,
        command_operation="seal_evidence_snapshot",
        command_hash=canonical_sha256(command),
        acting_subject=actor_subject,
        profile_ref=PinnedRef(profile_version_id, profile_content_hash),
        policy_ref=PinnedRef(policy_version_id, policy_content_hash),
    )
    result = await verifier.verify(token, expected=expected)
    if not result.ok:
        return problem_response(result.reason)
    # ... section 10.2's applier takes it from here; this module's job is done.
    await verifier.aclose()
"""

from __future__ import annotations

import logging
import re
import time
import unicodedata
from collections.abc import Collection
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any
from urllib.parse import urlsplit

import httpx
import jwt
from cachetools import TTLCache
from research_contracts.canonical import CanonicalError, assert_valid_instance

from kag_common._audience import checked_audience
from kag_common._jwks import JWS_ALGORITHM, usable_keys_by_kid

logger = logging.getLogger(__name__)

__all__ = [
    "AttestationVerifier",
    "ExpectedApplication",
    "PinnedRef",
    "VerificationReason",
    "VerificationResult",
]

# --------------------------------------------------------------------------------------- #
# IMP-DEC-002 (15-new-services-integration-rollout-and-verification-plan.md §13.1, ratified
# 2026-09-04) — the five ratified JWS parameters, inherited verbatim from the production
# precedent (evidence_review_service/src/auth/verifier.py), not a new cryptographic
# decision. Kept as named module constants rather than inlined literals so a future rotation
# of any one of them is a one-line diff with the ratifying decision cited beside it.
# --------------------------------------------------------------------------------------- #

#: (:data:`~kag_common._jwks.JWS_ALGORITHM` — RS256 only, no HMAC family, so an
#: algorithm-confusion attack is structurally unavailable — is imported above rather than
#: defined here. It is the constant the SHARED admission rule screens against, and the cache
#: invariant and this module's decode rule have to be the same literal or they can drift into
#: "cached a key ``jwt.decode`` will not accept".)

#: How long a fetched JWKS is trusted before a background re-fetch would be due. A rotation
#: is handled immediately regardless, by the forced refresh on an unknown ``kid`` below —
#: this bound only covers a key being *removed* outright.
JWKS_CACHE_TTL_SECONDS = 3600

#: TTL of the *sibling* research-context token (the Keycloak-issued signed context that rides
#: alongside a request, not this attestation) — AND, per IMP-DEC-002, the maximum validity
#: window this module enforces on an ``ApprovalAttestation``'s own ``issued_at``/``expires_at``
#: pair. An ``ApprovalAttestation`` still carries its own ``expires_at``/``exp`` rather than a
#: fixed default (an approval's validity window is set per-approval, not per-protocol), but
#: that window may never exceed this ceiling: without it, a compromised or buggy issuer could
#: mint an attestation whose payload claims a far-future ``expires_at`` and stay "valid" for as
#: long as the envelope ``exp`` (which the issuer also controls) says so. Enforced independently
#: of the envelope ``exp`` — see ``verify()``.
CONTEXT_TOKEN_TTL_SECONDS = 300

#: Minimum interval between two JWKS network fetches, however many unknown ``kid``s arrive in
#: between. Mirrors ``jose``'s ``createRemoteJWKSet`` ``cooldownDuration`` (30s), which the
#: TypeScript sibling relies on, and closes an unauthenticated amplification path: ``kid`` is
#: read from the token's UNVERIFIED header, so before this bound existed every garbage token
#: carrying a fresh random ``kid`` forced its own outbound fetch — 50 such tokens produced 50
#: JWKS requests, measured. A caller needs no credential to send them, so the cost of a burst
#: fell entirely on FR's JWKS endpoint and on this process's connection pool.
#:
#: The cooldown is applied to the ATTEMPT, not to a success: a JWKS endpoint that is down or
#: serving garbage must not be retried per-token either. The bound on rotation recovery is
#: therefore this constant, not ``JWKS_CACHE_TTL_SECONDS`` — a genuinely rotated key resolves
#: within 30s instead of on the first token, which is inside the ``KEY_OVERLAP_HOURS`` window
#: FR keeps the old key valid for, so no legitimate verification is lost.
JWKS_REFRESH_COOLDOWN_SECONDS = 30

#: Overlap window a rotated signing key is kept valid for, server-side (FR's JWKS, not
#: something this verifier enforces directly). Recorded for the same reason as the context
#: TTL above: long enough that a 3600s JWKS cache plus a 300s context token cannot span a
#: rotation without the old key still resolving.
KEY_OVERLAP_HOURS = 24

#: Clock skew tolerance applied to every timestamp check (``exp``, and by extension the
#: attestation's own ``issued_at``/``expires_at`` once decoded). Matches the production
#: precedent's ``leeway=30``.
CLOCK_LEEWAY_SECONDS = 30

#: The released grammar this module verifies attestations against.
ATTESTATION_SCHEMA_REF = "urn:datacompany:approval-attestation:1"

#: Standard JWT-registered claims (RFC 7519) that live in the envelope, never in the payload.
#: The attestation schema's own root ``$comment`` authoring decision 1 is explicit that
#: ``iss``, ``aud``, ``exp``, ``iat`` and ``kid`` belong to the envelope, not to this document
#: — and the schema is sealed (``unevaluatedProperties: false``), so validating the raw
#: decoded claims (envelope keys mixed into the payload by ``jwt.decode``) against it always
#: fails on exactly these keys. They are stripped before structural validation.
_ENVELOPE_CLAIMS = frozenset({"iss", "sub", "aud", "exp", "nbf", "iat", "jti"})

_JWKS_TIMEOUT = httpx.Timeout(2.0, connect=1.0, read=2.0, write=2.0, pool=1.0)
_JWKS_LIMITS = httpx.Limits(max_keepalive_connections=10, max_connections=20, keepalive_expiry=30.0)


class VerificationReason(StrEnum):
    """Why :meth:`AttestationVerifier.verify` accepted or rejected an attestation.

    A bare ``bool`` cannot tell a caller what to do next: an expired attestation is retried
    (ask FR for a fresh one), a revoked one is not, and a wrong-target one is very possibly an
    attacker. Each member below maps to exactly one operator response.
    """

    VERIFIED = "verified"

    # Envelope-level (JWS) failures. No ExpectedApplication needed to detect these.
    MALFORMED_TOKEN = "malformed_token"
    BAD_SIGNATURE = "bad_signature"
    UNKNOWN_KEY = "unknown_key"
    WRONG_AUDIENCE = "wrong_audience"
    WRONG_ISSUER = "wrong_issuer"
    EXPIRED = "expired"
    #: The attestation's PAYLOAD window has not opened yet (``issued_at`` is in the future
    #: beyond the clock leeway), or is inverted (``expires_at`` at or before ``issued_at``).
    #: Distinct from EXPIRED: an expiry is retried by asking FR for a fresh attestation, a
    #: not-yet-valid one means this verifier's clock and the issuer's disagree — or the issuer
    #: post-dated the window, which is a standing authorisation, not an approval.
    NOT_YET_VALID = "not_yet_valid"

    # Structural failures against the released ApprovalAttestation grammar — covers a
    # malformed/absent approval or task identity, an out-of-range approval round, and a
    # malformed approver subject/role/decision. research_contracts.canonical owns the format
    # rule in every one of these; this module does not re-derive it.
    MALFORMED_ATTESTATION = "malformed_attestation"

    # Semantic mismatches against the caller-supplied ExpectedApplication.
    WRONG_TARGET = "wrong_target"
    WRONG_COMMAND_HASH = "wrong_command_hash"
    WRONG_INPUT_REVISION = "wrong_input_revision"
    WRONG_PROFILE_OR_POLICY = "wrong_profile_or_policy"
    WRONG_APPROVAL_ROUND = "wrong_approval_round"

    # Approver-set semantics, internal to the attestation (no ExpectedApplication needed for
    # the count; the acting subject is what makes self-approval checkable).
    INSUFFICIENT_APPROVALS = "insufficient_approvals"
    SELF_APPROVAL = "self_approval"

    # Revocation. Failing to resolve revocation_check_ref is NOT the same as "not revoked" —
    # IMP-DEC-002: "a revoked or expired context fails closed".
    REVOKED = "revoked"
    REVOCATION_CHECK_FAILED = "revocation_check_failed"


@dataclass(frozen=True, slots=True)
class PinnedRef:
    """The caller's half of a ``profile_ref``/``policy_ref`` comparison: version AND content.

    ``version_id`` alone is not the identity of a pinned version. The attestation carries a
    whole ``urn:datacompany:pinned-version-ref:1`` shape (version_id, version_number, schema_ref,
    ``content_hash``, resolved_at), and comparing only ``version_id`` meant an attestation
    whose ``content_hash`` had been swapped for another document's still verified — measured:
    a token pinned to the caller's expected ``version_id`` but carrying a foreign
    ``content_hash`` was accepted. The version id says *which* pin; the content hash says
    *what was in it*. A profile edited in place under a reused version id, or a
    version_id/content_hash pair reassembled from two different releases, is exactly what
    binding to both refuses. The TypeScript sibling has always compared both.

    Both fields are required — an optional ``content_hash`` would be the same half-binding
    with a nicer name, and the caller that resolved the pin necessarily has both.
    """

    version_id: str
    content_hash: str


@dataclass(frozen=True, slots=True)
class ExpectedApplication:
    """What the CALLER is about to apply — the other half of every equality check below.

    An attestation on its own only says what FR approved in the past; a verifier with no
    notion of what the caller intends to do *right now* cannot detect a wrong target, a wrong
    command, a wrong input revision, a wrong profile/policy, or a self-approval (that last one
    needs to know who the acting subject is). Most of document 13 section 10.3's eighteen
    negative cases are unwritable without this — see the module docstring for the six cases
    that do not need it.

    ``profile_ref``/``policy_ref`` are :class:`PinnedRef` (version_id + content_hash), not a
    bare version-id string. See that class for why ``version_id`` alone was not a binding.
    ``None`` means "the caller is applying under no pinned profile/policy", and an attestation
    that DOES carry one is then refused — a token pinned to a release the caller has never
    heard of is unbound in the direction that matters.
    """

    target_service: str
    #: ``target.aggregate_type``. Required, and deliberately not defaulted: this was the
    #: binding that went missing, and an optional one is a binding a caller forgets. Without
    #: it an attestation approved to seal an ``evidence_snapshot`` verified against a caller
    #: about to mutate a different aggregate KIND that happened to share the service, id and
    #: version — measured. ``aggregate_id`` is only unique within its type.
    aggregate_type: str
    aggregate_id: str
    aggregate_version: int
    input_revision: str | None
    command_operation: str
    command_hash: str
    acting_subject: str
    profile_ref: PinnedRef | None = None
    policy_ref: PinnedRef | None = None
    #: The approval round the caller is applying against. Optional because not every caller
    #: tracks rounds explicitly; when supplied, a first-round attestation must not satisfy a
    #: caller applying a later round (or vice versa) — see ``VerificationReason.
    #: WRONG_APPROVAL_ROUND`` and document 13 section 10.3's approval-round negative case.
    approval_round: int | None = None

    def __post_init__(self) -> None:
        # A blank acting_subject silently disarms the self-approval check: nothing in the
        # approver set can equal it, so every attestation passes separation of duty. That is a
        # caller bug, not a token-driven rejection, so it raises rather than returning a
        # VerificationResult — see the module docstring's "raises for genuine programmer
        # errors" contract.
        if not _normalise_subject(self.acting_subject):
            raise ValueError(
                "ExpectedApplication requires a non-blank acting_subject — the self-approval "
                "check compares against it and would otherwise never fire"
            )


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """A typed outcome of :meth:`AttestationVerifier.verify`. Never applies anything.

    Identity fields (``attestation_id``, ``approval_id``, ``approval_round``, ``target``,
    ``command_operation``, ``command_hash``, ``raw``) are populated once the token has passed
    signature and schema validation — i.e. once its content can be trusted enough to log or
    key a dedup check on — even when a later semantic check (wrong target, insufficient
    approvals, …) makes ``ok`` False. They are left at their defaults for every failure at or
    before schema validation, because nothing in the token is trustworthy yet.

    ``attestation_id`` and ``target`` are exactly what document 13 section 10.2 needs to
    perform the two applier-owned checks this module cannot: dedup on ``attestation_id``
    (replay) and compare ``target.aggregate_version`` against the aggregate's current
    revision (an aggregate changed between approval and application).
    """

    ok: bool
    reason: VerificationReason
    detail: str = ""
    attestation_id: str | None = None
    approval_id: str | None = None
    approval_round: int | None = None
    target: dict[str, Any] | None = None
    command_operation: str | None = None
    command_hash: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


def _origin(url: str) -> str:
    """``scheme://host[:port]`` of ``url`` — the comparison unit for the SSRF allow-list.

    Deliberately not the whole URL: an allow-list entry names an origin the caller trusts to
    answer revocation queries, not one specific path on it.

    RAISES ``ValueError`` on a URL whose authority ``urlsplit`` refuses to parse — measured,
    two distinct shapes: ``"http://[oops"`` -> ``Invalid IPv6 URL``, ``"http://[oops]"`` ->
    ``'oops' does not appear to be an IPv4 or IPv6 address``. Left raising rather than made
    total, because the one caller has an obvious right answer for it (fail the revocation
    check closed) and a sentinel return would only move the decision somewhere it reads as
    a normal origin string.
    """
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


# ===========================================================================
# THE SHARED SUBJECT CHARACTER CLASSES - A CROSS-LANGUAGE CONTRACT.
#
# These three classes and the four steps of :func:`_normalise_subject` below are
# mirrored, code point for code point and item for item, in the TypeScript sibling
# ``fr/backend/src/lib/attestation-verifier.ts`` (``canonicalSubject``). They MUST be
# changed as a pair. Two verifiers of the SAME signed attestation that fold subjects
# differently are not "one strict and one lax": the fleet is governed by whichever is
# WEAKER, because an attacker picks the service to apply through - so a divergence is
# never a partial defence, it is a total one.
#
# WHY THE CLASSES ARE ENUMERATED HERE INSTEAD OF CALLING ``str.strip()``.
# They used to be implicit: this file called ``str.strip()`` and the sibling called
# ``String.prototype.trim()``, on the reasoning that both "strip whitespace". They do not
# strip the same whitespace. Enumerated over a 90-input adversarial corpus, Python's
# ``str.strip()`` set is JS's ``trim()`` set plus FIVE code points - U+0085 NEL, U+001C
# FILE SEPARATOR, U+001D GROUP SEPARATOR, U+001E RECORD SEPARATOR, U+001F UNIT SEPARATOR
# - and minus U+FEFF, which both remove anyway as ``\p{Cf}``. End to end on freshly
# signed tokens at ``required_approvals: 2``, that gap meant an approver pair
# [alice, U+001C + alice] was ``insufficient_approvals`` HERE and **valid in the
# sibling**, and an acting subject ``carol`` was not matched there by an approver
# U+0085 + ``carol``, re-opening self-approval. One person plus one invisible C0 byte
# cleared a two-human floor - on the weaker side, which is the side that governs.
#
# All five of those code points are Unicode general category **Cc**. That is the fix,
# and it is why this removes category ``Cc`` rather than blacklisting five characters:
# the divergence is not five special cases, it is one category that one language's
# default trim reaches into and the other's does not. Enumerating the class makes the
# agreement checkable by READING the two files, instead of by knowing two runtimes'
# whitespace tables by heart.
# ===========================================================================

#: Removed EVERYWHERE in the string, not only at the edges.
#:
#: ``Cf`` - format / default-ignorable characters: U+00AD SOFT HYPHEN, U+200B..U+200D
#: ZERO WIDTH SPACE/NON-JOINER/JOINER, U+2060 WORD JOINER, U+FEFF BOM, the bidi controls
#: U+202A..U+202E and the isolates. NFKC does not touch these and they render as nothing,
#: so ``ali`` + U+200B + ``ce`` is a second "distinct" subject that is byte-different and
#: pixel-identical in every log, ticket and console an operator would check it against.
#:
#: ``Cc`` - the C0 and C1 controls (U+0000..U+001F, U+007F..U+009F). Same argument, plus:
#: no directory mints a subject containing a control character, so removing them cannot
#: merge two real humans. They are removed EVERYWHERE rather than trimmed at the edges
#: precisely BECAUSE the edge-only reading is what diverged - ``str.strip()`` reaches 5 of
#: them and ``trim()`` reaches none, whereas "an identity contains no control characters"
#: is a rule both languages state exactly. Matches the sibling's ``/[\p{Cc}\p{Cf}]/gu``.
SUBJECT_REMOVED_CATEGORIES = frozenset({"Cc", "Cf"})

#: Trimmed at the EDGES only - this is the visible whitespace an issuer may pad a subject
#: with in transport. It is exactly U+0020 plus Unicode categories Zs, Zl and Zp, written
#: out so the sibling can hold the identical set: U+0020, U+00A0 NBSP, U+1680 OGHAM SPACE
#: MARK, U+2000..U+200A, U+2028 LINE SEPARATOR, U+2029 PARAGRAPH SEPARATOR, U+202F NARROW
#: NBSP, U+205F MEDIUM MATHEMATICAL SPACE, U+3000 IDEOGRAPHIC SPACE.
#:
#: Most of these never survive step 1 (NFKC folds the compatibility spaces to U+0020);
#: they are listed anyway so this class does not silently depend on the NFKC table, which
#: is versioned per runtime (non-defence 6). TAB, LF, VT, FF and CR are absent on purpose
#: - they are category ``Cc`` and step 2 has already removed them. Passed EXPLICITLY to
#: ``str.strip``: a bare ``str.strip()`` is the defect this constant exists to close.
SUBJECT_TRIMMED_CHARACTERS = (
    "\u0020\u00a0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000"
)

#: Applied AFTER lowercasing. U+0307 COMBINING DOT ABOVE following a lowercase ``i`` is
#: not a diacritic a human typed: it is the literal output of Unicode SpecialCasing for
#: U+0130 LATIN CAPITAL LETTER I WITH DOT ABOVE, which both ``str.lower()`` and the
#: sibling's ``toLowerCase()`` map to ``i`` + U+0307. Without this, subject ``ALI`` +
#: U+0130 + ``CE`` lowercases to something that renders as ``alice`` and counts as a
#: SECOND approver beside ``alice`` - in BOTH implementations, so it was parity-consistent
#: and still exactly the "one person plus a shift key" defect the M-of-N floor exists to
#: stop. Collapsing only the redundant dot on an already-dotted ``i`` closes it, and
#: closes the bypass of feeding ``i`` + U+0307 directly, without stripping diacritics
#: generally (non-defence 3).
#:
#: ``+`` because the sequence can repeat: a single pass would otherwise leave ``i`` +
#: U+0307 behind for the input ``i`` + U+0307 + U+0307.
_SUBJECT_SOFT_DOTTED_I = re.compile("i\u0307+")


def _normalise_subject(value: Any) -> str | None:
    """Fold an approver/acting subject to the form two records of the SAME HUMAN share.

    THE PROPERTY THIS DEFENDS is "N *distinct humans* approved" - not "N distinct byte
    strings appear in the ``approvers`` array". Counting a set of raw ``subject`` values is
    the second thing while claiming the first. It has now been defeated three times, each
    time by a spelling the previous fix did not fold, and all three are regression-tested:

        [alice, alice]                  - killed by the raw set
        [alice, Alice]                  - killed by ``str.lower()``
        [alice, U+001C + alice]         - killed by removing category ``Cc``

    One person plus a shift key, or plus one invisible byte, is not separation of duty. The
    same key is used for the SELF-APPROVAL check, for exactly the same reason: an acting
    subject ``applying-principal`` was previously not matched by an approver row reading
    ``Applying-Principal``, and after that fix still not by U+0085 + ``applying-principal``.

    See the CROSS-LANGUAGE CONTRACT block above this function for why the character classes
    are enumerated as module constants instead of being left to ``str.strip()``.

    The transform, in order (each step's output feeds the next):

    1. **NFKC** - compatibility composition. Collapses the fullwidth Latin block,
       ligatures (U+FB00 -> ``ff``), and the many superscript / circled / mathematical
       variants of ASCII letters. These are distinct code points that a human reads as the
       same name.
    2. **remove** every character whose general category is in
       :data:`SUBJECT_REMOVED_CATEGORIES` (``Cc`` + ``Cf``), everywhere.
    3. **trim** :data:`SUBJECT_TRIMMED_CHARACTERS` at the edges. NOT a bare ``strip()``:
       see the contract block above for the five code points that cost us.
    4. **``str.lower()``, deliberately NOT ``str.casefold()``** - see non-defence 1. Then
       :data:`_SUBJECT_SOFT_DOTTED_I` removes the dot that lowercasing U+0130 leaves
       behind.

    WHAT THIS DELIBERATELY DOES **NOT** DEFEND AGAINST. This list is mirrored item for item
    in the sibling and the two must stay identical - a boundary only one file states is a
    boundary only one file honours, and these lists having drifted (6 items here, 5 there,
    and the trim divergence named by neither) is how the ``Cc`` hole above survived two
    rounds of fixes.

    1. **FULL CASE FOLDING.** JS has no ``String.prototype.casefold``; its ``toLowerCase``
       is simple + special-casing only, so German sharp s does NOT fold to ``ss`` and
       ``strasse`` spelled either way still counts as two. This module must therefore use
       ``str.lower()``, NOT ``str.casefold()`` - ``casefold`` would make Python STRICTER
       than the sibling, and per the contract block the fleet's real guarantee is the
       WEAKER of the two verifiers, so the only thing a mismatch buys is a token one
       service accepts and the other refuses.
    2. **CONFUSABLES / HOMOGLYPHS.** Cyrillic U+0430 and Latin ``a`` are different
       characters that render identically, and count as two here. Turkish dotless ``i``
       (U+0131) is in this class too: unlike U+0130 it is VISIBLY different - it has no dot
       - and no lowercase mapping produces it, so it stays a second subject. Collapsing
       scripts (UTS #39 skeletons) would mean shipping and version-pinning the confusables
       table inside a verifier that today validates entirely offline, and it is lossy the
       other way too (``rn``/``m``, ``l``/``I``), so it would start REFUSING real two-human
       approvals. The place to refuse a confusable subject is where identities are ISSUED -
       the IdP - not where an already-issued one is counted.
    3. **DIACRITICS.** ``jose`` with and without an acute stay distinct; NFKC composes, it
       does not strip combining marks, and NFKD-plus-mark-removal would merge people who
       really are different. Note the narrow exception in step 4: U+0307 after ``i`` is
       removed, because that one sequence is manufactured by lowercasing rather than typed.
       THIS IS ALSO WHERE THE INVISIBLE-CHARACTER DEFENCE STOPS. U+034F COMBINING GRAPHEME
       JOINER and U+FE0F VARIATION SELECTOR-16 are category ``Mn``, NOT ``Cf``, so step 2
       does not reach them: measured, ``al`` + U+034F + ``ice`` is a second subject that
       renders identically to ``alice``. Parity-consistent - the sibling leaves them too -
       so it is a shared residual, not a divergence. Removing them means stripping ``Mn``,
       which is the diacritic merge this item declines.
    4. **INTERNAL WHITESPACE, the visible kind.** ``al ice`` and ``alice`` stay distinct;
       collapsing it would merge subjects that are simply different. (Internal CONTROL
       characters are removed - step 2 - on the grounds that no directory issues them.)
    5. **DIRECTORY-LEVEL ALIASING.** ``alice``, ``alice@corp``, ``a.lice@corp`` and a
       rotated subject id for the same human are not related here. This module has no
       directory to ask. Callers whose issuer emits unstable subjects must not rely on
       M-of-N alone.
    6. **UNICODE VERSION SKEW BETWEEN THE TWO RUNTIMES.** Category ``Cc`` is frozen
       forever, but ``Cf`` and the NFKC table are not: a code point whose category changes
       between the Unicode version in CPython's ``unicodedata`` and the one in Bun's ICU
       re-opens a divergence of exactly the shape described in the contract block, with
       neither file changing. Nothing inside either module can detect that. The control is
       the cross-language parity test, which pushes the SAME corpus through both
       implementations and asserts identical output. It is the only instrument that can see
       this class of defect and it must not be deleted.
    7. **THE IRREDUCIBLE ONE: a distinct SUBJECT is only a proxy for a distinct HUMAN.**
       Two accounts held by one person, a shared service account, or a person who controls
       a colleague's session all defeat M-of-N no matter how the string is folded.
       Separation of duty ultimately rests on the identity provider and the approval
       workflow, not on this comparison.

    Returns ``None`` for a non-string or a value that is empty once folded - the caller
    treats that as a malformed attestation rather than as a subject that matches nothing
    (the sibling's ``invalid_approver``).
    """
    if not isinstance(value, str):
        return None
    normalised = unicodedata.normalize("NFKC", value)
    without_invisibles = "".join(
        c for c in normalised if unicodedata.category(c) not in SUBJECT_REMOVED_CATEGORIES
    )
    trimmed = without_invisibles.strip(SUBJECT_TRIMMED_CHARACTERS)
    return _SUBJECT_SOFT_DOTTED_I.sub("i", trimmed.lower()) or None


def _pinned_ref_matches(claimed: Any, expected_ref: PinnedRef | None) -> bool:
    """Is the attestation's ``profile_ref``/``policy_ref`` the pin the caller is applying under?

    Both halves of the pin are compared — see :class:`PinnedRef`. When the caller expects no
    pin, an attestation carrying one is a mismatch: it was approved under a release the caller
    cannot show it is applying, which is exactly the unbound direction.
    """
    if expected_ref is None:
        return claimed is None
    if not isinstance(claimed, dict):
        return False
    return (
        claimed.get("version_id") == expected_ref.version_id
        and claimed.get("content_hash") == expected_ref.content_hash
    )


def _parse_timestamp(value: Any) -> datetime | None:
    """Parse an RFC 3339 ``...Z`` timestamp (the schema's ``timestamp`` format). ``None`` on
    anything that is not a well-formed one — the caller treats that as malformed."""
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _rejected(
    reason: VerificationReason,
    detail: str = "",
    *,
    claims: dict[str, Any] | None = None,
) -> VerificationResult:
    """Build a rejection, carrying identity fields when ``claims`` has already been trusted."""
    if claims is None:
        return VerificationResult(ok=False, reason=reason, detail=detail)
    target = claims.get("target")
    return VerificationResult(
        ok=False,
        reason=reason,
        detail=detail,
        attestation_id=claims.get("attestation_id"),
        approval_id=claims.get("approval_id"),
        approval_round=claims.get("approval_round"),
        target=dict(target) if isinstance(target, dict) else None,
        command_operation=claims.get("command_operation"),
        command_hash=claims.get("command_hash"),
        raw=claims,
    )


class AttestationVerifier:
    """Verify FR ``ApprovalAttestation`` JWS objects against a cached, by-``kid`` JWKS.

    Build one per process (per consuming service, since ``audience`` is service-scoped —
    IMP-DEC-002: "service-audience short-lived signed context and distinct FR attestation
    keys") and reuse it, exactly like ``InternalTokenVerifier``: the by-``kid`` key cache
    survives across calls, so steady-state verification does no network I/O beyond the
    optional revocation check.

    ``revocation_allowed_origins`` guards that revocation check against SSRF: an attestation's
    ``revocation_check_ref`` is a URL taken from the (signed, but attacker-reachable-if-the-key-
    or-issuer-is-compromised) TOKEN. Fetching it unconditionally would let a holder of a valid
    signing key — or a compromised issuer — point this verifier's outbound request at an
    arbitrary origin, including cluster-internal addresses the token itself has no business
    naming. The allow-list is supplied by the CALLER at construction, never derived from the
    token, and a ``revocation_check_ref`` whose origin (scheme + host + port) is not in it is
    refused — fail closed, exactly like an unreachable revocation endpoint.

    .. warning::

       **The allow-list guards the request this module makes, not where that request ends
       up.** It is checked once, against the origin in the token, before a single outbound
       call — so it cannot see a 3xx the server answers with. The client this module builds
       for itself therefore sets ``follow_redirects=False`` explicitly (rather than leaning on
       the ``httpx`` default, which is not this module's to guarantee), and an allow-listed
       status endpoint answering ``302 Location: http://169.254.169.254/…`` is simply not
       followed.

       **A caller passing its own ``client=`` overrides that.** Verified by construction: an
       injected ``httpx.AsyncClient(follow_redirects=True)`` follows the hop, and the SSRF
       protection this class documents is gone — the allow-listed origin becomes a redirector
       to any address the token's issuer chooses, cluster-internal ones included. The same
       client is used for the JWKS fetch, so the exposure is not limited to revocation. If you
       inject a client, it MUST be built with ``follow_redirects=False``; the ``client=``
       parameter exists for test transports and for pool sharing, not to relax this.
    """

    def __init__(
        self,
        jwks_url: str,
        *,
        issuer: str,
        # ``str`` OR a collection of str: PyJWT accepts either, and both are measured to work
        # here. The annotation used to say ``str`` alone while ``list``/``tuple``/``set``
        # verified fine -- a narrower annotation than the code's real contract is what let the
        # audience type go unexamined in the first place.
        audience: str | Collection[str],
        cache_ttl: int = JWKS_CACHE_TTL_SECONDS,
        refresh_cooldown: float = JWKS_REFRESH_COOLDOWN_SECONDS,
        client: httpx.AsyncClient | None = None,
        revocation_allowed_origins: frozenset[str] = frozenset(),
    ) -> None:
        if not jwks_url:
            raise ValueError("AttestationVerifier requires a jwks_url (FR's own JWKS endpoint)")
        if not issuer:
            raise ValueError("AttestationVerifier requires an issuer (FR's attestation issuer)")
        self.jwks_url = jwks_url
        self.issuer = issuer
        # TYPE-checked, not merely truthy — and it has to be, or the ``except TypeError`` arm
        # in verify() would be a trap rather than a fix. ``jwt.decode`` raises a bare
        # ``TypeError`` on a non-str, non-iterable ``audience`` BEFORE it reads the payload,
        # so that arm would report MALFORMED_TOKEN for every token forever on one line of bad
        # wiring. Failing here instead turns a silent permanent outage into a startup crash
        # naming the mis-wired verifier. See :mod:`kag_common._audience` for the four distinct
        # ways a bad audience used to fail, each measured.
        self.audience = checked_audience(audience, owner="AttestationVerifier")
        # Never populated from the token — see the class docstring's SSRF note.
        self.revocation_allowed_origins = revocation_allowed_origins
        # kid -> signing key object (the public key built from the served JWK).
        self._keys: TTLCache[str, Any] = TTLCache(maxsize=16, ttl=cache_ttl)
        # An injected client is borrowed (caller owns it); a lazily-built one is ours.
        self._client = client
        self._owns_client = client is None
        self._refresh_cooldown = refresh_cooldown
        #: ``time.monotonic()`` of the last JWKS fetch ATTEMPT (not the last success — a dead
        #: endpoint must not be retried per-token either). ``None`` until the first attempt.
        self._last_refresh_attempt: float | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=_JWKS_TIMEOUT,
                limits=_JWKS_LIMITS,
                # Explicit, not inherited from the httpx default: the SSRF allow-list is
                # checked against the origin named in the token BEFORE any request, so a
                # followed 3xx would land this verifier on an address the allow-list never
                # saw. See the class docstring's warning — a caller-injected client can still
                # undo this, which is why the parameter is documented as it is.
                follow_redirects=False,
            )
            self._owns_client = True
        return self._client

    async def _refresh_keys(self) -> None:
        """Fetch the JWKS and rebuild the by-kid key cache.

        Raises only what ``verify()``'s caught tuple already handles (``httpx.HTTPError`` on
        transport/status, ``ValueError`` on a body that is not a usable JWKS). An individual
        key ENTRY never raises out of here — admission is
        :func:`kag_common._jwks.usable_keys_by_kid`, which documents the six ways a JWKS entry
        used to escape this method's caller and closes each of them at the CACHE BOUNDARY
        rather than by widening a downstream ``except``: the cache's invariant is "keys usable
        for ``JWS_ALGORITHM``", and admission is the only place that invariant can be
        established. ``internal_token.InternalTokenVerifier`` broke its own never-raises
        contract in the identical six ways through the identical loop, which is why the rule
        now lives in one module instead of two copies.

        WHAT THAT DOES NOT DO. It closes the KEY-DRIVEN raises — an unsupported ``kty``, an
        unhashable ``kid`` — and only those. It never made the decode ladder in ``verify()``
        correct, because that ladder had a PAYLOAD-DRIVEN hole no key-side guard can reach:
        PyJWT's ``_validate_exp``/``_validate_nbf``/``_validate_iat`` each do ``int(claim)``
        catching only ``ValueError``, so a non-numeric NON-STRING arrives as a bare
        ``TypeError`` — not a ``PyJWTError``, and matched by no arm of that ladder. Measured on
        pyjwt 2.13: ``exp``, ``nbf`` or ``iat`` of ``[1]`` or ``{}`` (and ``nbf``/``iat`` of
        ``null``) raised ``TypeError: int() argument must be...`` straight out of ``verify()``.
        ``exp: null`` does not — ``options={"require": [...]}`` rejects it first.

        ✅ CLOSED (2026-09-08, this repo's PR after #46), and this paragraph now records the
        shape of the fix rather than an open card. It took three parts, not one ``except``:

        1. ``__init__`` screens ``audience`` through
           :func:`kag_common._audience.checked_audience`, which TYPE-checks it rather than
           merely testing it for truthiness. That is the precondition the arm depends on —
           ``jwt.decode`` raises the identical bare ``TypeError`` on a non-str, non-iterable
           ``audience`` ARGUMENT, and checks it BEFORE any claim, so an unconditional arm on
           its own would have reported MALFORMED_TOKEN for every token forever on one line of
           bad wiring: an operator error re-presented as "all our callers send bad tokens".
        2. ``verify()`` carries an ``except TypeError`` arm, now scoped to the token's own
           claims by (1), mapping to MALFORMED_TOKEN — the same reason code the already-handled
           string-typed sibling produces.
        3. ``internal_token.verify`` took the identical pair in the same pass, because it ran
           the identical ``int()`` exposure and had no audience check of any kind.

        The residual was POST-SIGNATURE, which is why it was narrow enough to defer once but
        not to leave: reaching it needs a token this verifier's own JWKS validates. Controls
        kept in the suite: the same ``exp: [1]`` from a WRONG signer returns BAD_SIGNATURE
        (proving the post-signature framing is a measurement, not an assertion), and
        ``nbf: "x"`` — a str, so ``ValueError``, which PyJWT does catch — has always returned
        MALFORMED_TOKEN. ``test_payload_time_claim_type_confusion_is_a_typed_rejection`` pins
        the new contract; it is #45's pinning test, deliberately INVERTED here rather than
        deleted, which is what it was written to force.
        """
        # Stamped BEFORE the await, and regardless of outcome: the cooldown exists to bound
        # outbound requests, and an endpoint that hangs or 500s is precisely the one that must
        # not be re-hit by the next token in the burst.
        self._last_refresh_attempt = time.monotonic()
        resp = await self._get_client().get(self.jwks_url)
        resp.raise_for_status()
        # Merged, not replaced: an entry that has become unusable stops being served rather
        # than evicting the keys that are still good, and the TTLCache expires it on its own.
        for kid, key in usable_keys_by_kid(resp.json(), source="attestation", log=logger).items():
            self._keys[kid] = key

    def _refresh_is_on_cooldown(self) -> bool:
        """Has a JWKS fetch been attempted too recently to justify another one?"""
        if self._last_refresh_attempt is None:
            return False
        return (time.monotonic() - self._last_refresh_attempt) < self._refresh_cooldown

    async def _resolve_key(self, kid: str) -> Any:
        """Return the signing key for ``kid``, refreshing the JWKS at most once per cooldown.

        ``kid`` is read from the token's UNVERIFIED header (it has to be — it names the key the
        signature will be checked with), so an unauthenticated caller chooses it. Refreshing on
        every miss therefore made this verifier an amplifier: measured, 50 garbage tokens with
        50 random ``kid``s produced 50 JWKS fetches. The refresh is now rate-limited by
        :data:`JWKS_REFRESH_COOLDOWN_SECONDS`, mirroring ``jose``'s ``createRemoteJWKSet``
        cooldown that the TypeScript sibling depends on; a miss inside the cooldown simply
        resolves to ``None`` and the caller reports UNKNOWN_KEY, which is what an unknown kid
        deserves.
        """
        key = self._keys.get(kid)
        if key is not None:
            return key
        if self._refresh_is_on_cooldown():
            logger.debug("attestation JWKS refresh suppressed by cooldown", extra={"kid": kid})
            return None
        await self._refresh_keys()
        return self._keys.get(kid)

    async def _check_revoked(self, revocation_check_ref: str) -> bool:
        """Resolve ``revocation_check_ref`` against the FR status endpoint it names.

        IMP-DEC-002: "``revocation_check_ref`` resolved against an FR status endpoint; a
        revoked or expired context fails closed." A transport failure here is deliberately
        NOT treated as "not revoked" — the caller sees :attr:`VerificationReason.
        REVOCATION_CHECK_FAILED` and must decide how to fail closed, exactly the wording of
        that decision. The caller (``verify()``) has already checked the ref's origin against
        ``revocation_allowed_origins`` before this is reached.
        """
        resp = await self._get_client().get(revocation_check_ref)
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict):
            # A status endpoint returning a JSON array (or scalar) is not the documented
            # object shape. ``data.get(...)`` would raise AttributeError here, which is not
            # in this module's caught-exception tuple and would escape verify()'s "never
            # raises" contract — so this is deliberately raised as ValueError instead, which
            # the caller does catch and turns into REVOCATION_CHECK_FAILED (fail closed).
            raise ValueError(
                f"revocation status endpoint returned {type(data).__name__}, expected an object"
            )
        # UNKNOWN IS UNAVAILABLE, NEVER PERMISSION. This used to read
        # ``bool(data.get("revoked", False))``, which is a truthiness test over a defaulted
        # lookup — so a 200 that did not actually answer the question read as "not revoked"
        # and the attestation was ACCEPTED. Measured, all four fail-open: ``{}``,
        # ``{"status": "unknown"}``, ``{"error": "not found"}`` and ``{"revoked": null}``.
        # Those are the shapes a status endpoint produces when it is misrouted, half-deployed,
        # answering for an unknown attestation id, or fronted by a proxy that turns an error
        # into a 200 body — exactly when a revocation must be assumed, not waived. Note also
        # ``{"revoked": "false"}``: a string is truthy, so a stringly-typed endpoint would
        # have failed the OTHER way. Only a real JSON boolean is an answer; anything else is
        # raised as ValueError, which verify() already catches and turns into
        # REVOCATION_CHECK_FAILED (fail closed), matching the module docstring's claim and the
        # TypeScript sibling's `typeof revoked !== 'boolean'` guard.
        revoked = data.get("revoked")
        if not isinstance(revoked, bool):
            raise ValueError(
                "revocation status endpoint returned "
                f"revoked={type(revoked).__name__}, expected a JSON boolean"
            )
        return revoked

    async def verify(self, token: str, *, expected: ExpectedApplication) -> VerificationResult:
        """Verify ``token`` against ``expected``. Always returns — never applies anything."""
        try:
            header = jwt.get_unverified_header(token)
        # ``ValueError`` AS WELL AS ``PyJWTError``, and this one IS attacker-reachable —
        # unlike the JWKS escapes above, which need FR's own JWKS to be misconfigured.
        # ``get_unverified_header`` calls ``token.encode("utf-8")`` BEFORE it does any JWT
        # parsing, so a string carrying an unpaired UTF-16 surrogate raises
        # ``UnicodeEncodeError`` ("surrogates not allowed") out of the encode, never reaching
        # the PyJWT error ladder. ``json.loads('{"token": "\\ud800"}')`` produces exactly such
        # a string, so ANY consumer that reads the token out of a JSON request body can be
        # handed one — by an UNAUTHENTICATED caller, since this is the very first thing
        # verify() does. Measured: verify("\ud800.\ud800.\ud800", ...) raised
        # ``UnicodeEncodeError: 'utf-8' codec can't encode character '\ud800' in position 0``.
        #
        # ``UnicodeEncodeError`` subclasses ``ValueError``, so widening to ``ValueError``
        # closes it, and stays narrow for the same reason the admission guard's tuple does:
        # it names the way UNTRUSTED INPUT fails to be a token, and cannot swallow the
        # ``AttributeError``/``NameError`` class of programming error in this module.
        # MALFORMED_TOKEN is the honest reason — the caller's token is not decodable.
        except (jwt.PyJWTError, ValueError) as exc:
            return _rejected(VerificationReason.MALFORMED_TOKEN, str(exc))

        kid = header.get("kid")
        if not kid:
            return _rejected(VerificationReason.MALFORMED_TOKEN, "token header has no kid")

        try:
            key = await self._resolve_key(kid)
        except (httpx.HTTPError, OSError, ValueError, KeyError) as exc:
            # JWKS unreachable or malformed — fails closed the same as a genuinely unknown key.
            return _rejected(VerificationReason.UNKNOWN_KEY, str(exc))
        if key is None:
            return _rejected(VerificationReason.UNKNOWN_KEY, f"no signing key for kid {kid!r}")

        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=[JWS_ALGORITHM],
                issuer=self.issuer,
                audience=self.audience,
                leeway=CLOCK_LEEWAY_SECONDS,
                options={"require": ["exp", "iss", "aud"]},
            )
        except jwt.ExpiredSignatureError as exc:
            return _rejected(VerificationReason.EXPIRED, str(exc))
        except jwt.InvalidAudienceError as exc:
            return _rejected(VerificationReason.WRONG_AUDIENCE, str(exc))
        except jwt.InvalidIssuerError as exc:
            return _rejected(VerificationReason.WRONG_ISSUER, str(exc))
        except jwt.InvalidSignatureError as exc:
            return _rejected(VerificationReason.BAD_SIGNATURE, str(exc))
        except jwt.PyJWTError as exc:
            return _rejected(VerificationReason.MALFORMED_TOKEN, str(exc))
        # PAYLOAD-DRIVEN, and NOT a ``PyJWTError``. PyJWT's ``_validate_exp`` /
        # ``_validate_nbf`` / ``_validate_iat`` each do ``int(claim)`` catching only
        # ``ValueError``, so a time claim that is a non-numeric NON-STRING escapes as a bare
        # ``TypeError``. Measured on pyjwt 2.13, through a correctly-signed token: ``exp``,
        # ``nbf`` or ``iat`` of ``[1]`` or ``{}``, and ``nbf`` or ``iat`` of ``null``, all
        # raised ``TypeError: int() argument must be...`` straight out of ``verify()`` —
        # against a module contract of "always returns a VerificationResult". (``exp: null``
        # does not: ``options={"require": [...]}`` treats a null required claim as missing and
        # rejects it first. A str does not either: ``int("x")`` is a ``ValueError``, which
        # PyJWT catches and converts — see the stringly-typed control in the tests.)
        #
        # WHY THIS ARM IS SAFE, WHICH IS THE WHOLE REASON IT TOOK A CARD AND NOT A ONE-LINER.
        # ``jwt.decode`` raises the SAME bare ``TypeError`` for a bad ``audience`` ARGUMENT,
        # and ``_validate_claims`` checks that argument BEFORE it reads any claim — so on its
        # own this arm would convert one mis-wired verifier into MALFORMED_TOKEN for every
        # token forever, a total silent auth outage that blames the caller. It is
        # :func:`kag_common._audience.checked_audience` in ``__init__`` that makes the
        # conversion honest: the argument cannot be the cause here, because a verifier with a
        # bad one cannot be constructed. Do not keep one without the other.
        #
        # MALFORMED_TOKEN is the same reason code the string-typed sibling already produced,
        # so one defect does not get two names depending on which JSON type it arrived as.
        except TypeError as exc:
            return _rejected(VerificationReason.MALFORMED_TOKEN, str(exc))

        # From here on the signature, issuer, audience and expiry are trusted. Structural
        # shape is not — validate against the released grammar before reading anything else.
        # The envelope claims jwt.decode folded in (iss/aud/exp/iat/…) are not part of the
        # attestation payload the schema describes (see _ENVELOPE_CLAIMS) and must be
        # stripped first, or the sealed schema rejects every token on those alone.
        claims = {k: v for k, v in claims.items() if k not in _ENVELOPE_CLAIMS}
        try:
            assert_valid_instance(claims, ATTESTATION_SCHEMA_REF)
        except CanonicalError as exc:
            return _rejected(VerificationReason.MALFORMED_ATTESTATION, str(exc))

        # The envelope's own `exp` is trusted (checked above by jwt.decode), but that is NOT
        # the same claim as the attestation payload's `expires_at`/`issued_at` — both are
        # required by the schema and both are under the ISSUER's control, so a compromised or
        # buggy issuer could otherwise mint a token whose envelope `exp` is fresh while the
        # payload claims an `expires_at` far in the past (silently unusable evidence) or, more
        # dangerously, far in the future (a standing authorisation the envelope never expires
        # in time to end). Both are checked here, independently of the envelope.
        issued_at = _parse_timestamp(claims.get("issued_at"))
        expires_at = _parse_timestamp(claims.get("expires_at"))
        if issued_at is None or expires_at is None:
            return _rejected(
                VerificationReason.MALFORMED_ATTESTATION,
                "issued_at/expires_at are not well-formed RFC 3339 timestamps",
                claims=claims,
            )
        now = datetime.now(UTC)
        leeway = timedelta(seconds=CLOCK_LEEWAY_SECONDS)
        if expires_at + leeway < now:
            return _rejected(
                VerificationReason.EXPIRED, "attestation expires_at has passed", claims=claims
            )
        # The window has an OPENING edge too, and nothing checked it: measured, an attestation
        # whose issued_at was now+1h (and expires_at now+1h+120s) VERIFIED. Only the closing
        # edge and the width were enforced, so a post-dated pair slid between them — an
        # approval that has not happened yet, presented as one that has, and one that stays
        # usable for the whole 300s ceiling once its hour arrives while the envelope `exp` the
        # same issuer controls says nothing about it. Uses the SAME CLOCK_LEEWAY_SECONDS as
        # every other timestamp check here rather than a second tolerance: a clock disagreeing
        # with FR's by more than the leeway is the condition this module already refuses to
        # paper over at the closing edge, and it cannot be a different number at the opening
        # one without one of the two being wrong.
        if issued_at - leeway > now:
            return _rejected(
                VerificationReason.NOT_YET_VALID,
                "attestation issued_at is in the future",
                claims=claims,
            )
        # An inverted or zero-width window (expires_at <= issued_at) is not a window at all.
        # The two edge checks above cannot catch it on their own — inside the leeway band a
        # pair can satisfy both — and the ceiling check below only bounds the window from
        # above, so a negative width passed it trivially. Matches the sibling's `ttlSeconds
        # <= 0` guard.
        if expires_at <= issued_at:
            return _rejected(
                VerificationReason.NOT_YET_VALID,
                "expires_at is at or before issued_at",
                claims=claims,
            )
        # IMP-DEC-002's 300s TTL ceiling on the attestation's OWN validity window, enforced
        # independently of the envelope: even a not-yet-expired attestation is rejected if the
        # issuer minted a window wider than the ceiling permits. Compared without leeway — this
        # is a structural ceiling on what the issuer was allowed to mint, not a clock-skew
        # tolerance on a live deadline.
        if expires_at - issued_at > timedelta(seconds=CONTEXT_TOKEN_TTL_SECONDS):
            return _rejected(
                VerificationReason.EXPIRED,
                "expires_at - issued_at exceeds the IMP-DEC-002 TTL ceiling",
                claims=claims,
            )

        if (
            expected.approval_round is not None
            and claims.get("approval_round") != expected.approval_round
        ):
            return _rejected(VerificationReason.WRONG_APPROVAL_ROUND, claims=claims)

        target = claims["target"]
        if (
            target.get("service") != expected.target_service
            # aggregate_type was in the schema and in the token and was never compared:
            # measured, a token targeting aggregate_type "other_thing" verified against a
            # caller applying to "evidence_snapshot". An aggregate id is unique only WITHIN a
            # type, so without this the approval is bound to a coordinate that does not
            # identify a row.
            or target.get("aggregate_type") != expected.aggregate_type
            or target.get("aggregate_id") != expected.aggregate_id
            or target.get("aggregate_version") != expected.aggregate_version
        ):
            return _rejected(VerificationReason.WRONG_TARGET, claims=claims)
        if target.get("input_revision") != expected.input_revision:
            return _rejected(VerificationReason.WRONG_INPUT_REVISION, claims=claims)

        # command_operation is checked alongside command_hash (document 13 section 10.1 pairs
        # them: "command operation and RFC 8785 command hash"); section 10.3 names only a
        # wrong-command-hash case, not a separate wrong-operation one, so both mismatches
        # report the same reason — either way the attestation was not issued for the command
        # about to be applied.
        if (
            claims.get("command_operation") != expected.command_operation
            or claims.get("command_hash") != expected.command_hash
        ):
            return _rejected(VerificationReason.WRONG_COMMAND_HASH, claims=claims)

        # BOTH halves of each pin — version_id AND content_hash. Comparing version_id alone
        # accepted a token whose content_hash had been swapped for a foreign one, measured:
        # the caller pinned (version_id V, content_hash E) and a token carrying (V, D)
        # verified. See PinnedRef.
        if not _pinned_ref_matches(claims.get("profile_ref"), expected.profile_ref):
            return _rejected(
                VerificationReason.WRONG_PROFILE_OR_POLICY, "profile_ref", claims=claims
            )
        if not _pinned_ref_matches(claims.get("policy_ref"), expected.policy_ref):
            return _rejected(
                VerificationReason.WRONG_PROFILE_OR_POLICY, "policy_ref", claims=claims
            )

        # required_approvals is trusted from the released schema (minimum: 1) in normal
        # operation, but this module does not take that on faith from a dependency it does not
        # control the version of at runtime (pyproject only floors research-contracts>=0.9.0) —
        # a required-count of zero would make the count check below vacuously true and let a
        # reject-only attestation (or one with no approvers) through. Checked explicitly.
        required_approvals = claims["required_approvals"]
        if (
            not isinstance(required_approvals, int)
            or isinstance(required_approvals, bool)
            or required_approvals < 1
        ):
            return _rejected(
                VerificationReason.MALFORMED_ATTESTATION,
                "required_approvals must be an integer >= 1",
                claims=claims,
            )

        approvers = claims["approvers"]
        # The property being enforced is "N DISTINCT HUMANS approved", and every check below
        # compares NORMALISED subjects (see _normalise_subject for exactly what is folded and
        # what is deliberately left undefended). Counting raw strings was not that property
        # twice over: the schema's `uniqueItems: true` compares whole approver objects, so one
        # subject under two roles is two items; and raw equality made two spellings of one
        # name two people. Measured before this fix, both of these satisfied
        # `required_approvals: 2`:
        #     [{"alice", reviewer, approve}, {"Alice", auditor, approve}]
        #     [{"alice", reviewer, approve}, {"alice ", auditor, approve}]
        normalised = [(_normalise_subject(a.get("subject")), a.get("decision")) for a in approvers]
        if any(subject is None for subject, _ in normalised):
            # The schema requires a non-empty string subject, but "non-empty" and "non-blank"
            # are not the same rule, and a subject that folds away to nothing would silently
            # join the approving set as a single anonymous slot.
            return _rejected(
                VerificationReason.MALFORMED_ATTESTATION,
                "an approver subject is blank once normalised",
                claims=claims,
            )

        approving = [subject for subject, decision in normalised if decision == "approve"]
        distinct_approving = set(approving)
        # DECISION: subjects that collide after normalisation are COUNTED ONCE, not refused.
        # Counting once IS the property — one human occupies one slot — so `[alice, Alice]`
        # against a floor of 2 is refused as INSUFFICIENT_APPROVALS (one human is not two),
        # while against a floor of 1 it verifies, which is correct: a human did approve. The
        # alternative, refusing the whole token on collision, was rejected because it also
        # refuses the harmless case an issuer can legitimately produce (the same person
        # recorded under two roles in one round) and it gives an attacker a way to invalidate
        # a genuine approval by getting one duplicate row added. Nothing is accepted silently:
        # a collision means the issuer emitted two rows for one person, which is a bug or a
        # padding attempt, so it is logged at WARNING with the raw spellings — the count is
        # safe, the anomaly is still visible to an operator.
        if len(approving) != len(distinct_approving):
            logger.warning(
                "attestation approver subjects collide after normalisation; counted once",
                extra={
                    "attestation_id": claims.get("attestation_id"),
                    "approval_id": claims.get("approval_id"),
                    "raw_approving_subjects": [
                        a.get("subject") for a in approvers if a.get("decision") == "approve"
                    ],
                    "distinct_approving_subjects": len(distinct_approving),
                },
            )
        if len(distinct_approving) < required_approvals:
            return _rejected(
                VerificationReason.INSUFFICIENT_APPROVALS,
                f"{len(distinct_approving)} distinct approving subjects, "
                f"{required_approvals} required",
                claims=claims,
            )

        # Self-approval is the same distinctness property with the acting subject on one side,
        # so it folds the same way. Raw equality here would have let "Carol" approve what
        # "carol" is applying — separation of duty defeated by a shift key. __post_init__
        # guarantees the expected side is non-blank, so this can never match vacuously.
        acting = _normalise_subject(expected.acting_subject)
        if any(subject == acting for subject, decision in normalised if decision == "approve"):
            return _rejected(VerificationReason.SELF_APPROVAL, claims=claims)

        revocation_check_ref = claims.get("revocation_check_ref")
        if revocation_check_ref:
            # SSRF guard: revocation_check_ref comes from the TOKEN, so its origin must be on
            # the caller-supplied allow-list before this module makes any outbound request to
            # it — never trust an address named by the thing being verified. Fails closed like
            # every other revocation-check failure.
            #
            # ``_origin`` RAISES on a ref whose authority ``urlsplit`` cannot parse, and this
            # is past the signature check, so nothing above it catches ``ValueError`` any
            # more: measured on the pre-fix module, ``revocation_check_ref="http://[oops"``
            # left ``verify()`` as a bare ``ValueError: Invalid IPv6 URL``, breaking the
            # "always returns a VerificationResult" contract. The released grammar screens
            # every NON-STRING and empty ref to MALFORMED_ATTESTATION before this point
            # (measured: list, object, number, bool, "" all reject there), so an unparseable
            # ``str`` is the whole of what reaches here — two shapes, both ``ValueError``.
            #
            # Rejecting rather than falling through is the only safe reading: a ref this
            # module cannot even resolve to an origin can never be shown to be on the
            # allow-list, and the allow-list is the SSRF guard. Same reason code as an origin
            # that is simply absent from the list, because operationally it is the same event
            # — a revocation ref this verifier will not dial.
            try:
                origin = _origin(revocation_check_ref)
            except ValueError as exc:
                return _rejected(
                    VerificationReason.REVOCATION_CHECK_FAILED,
                    f"revocation_check_ref is not a parseable URL: {exc}",
                    claims=claims,
                )
            if origin not in self.revocation_allowed_origins:
                return _rejected(
                    VerificationReason.REVOCATION_CHECK_FAILED,
                    f"revocation_check_ref origin {origin!r} is not allow-listed",
                    claims=claims,
                )
            try:
                revoked = await self._check_revoked(revocation_check_ref)
            except (httpx.HTTPError, OSError, ValueError, KeyError) as exc:
                return _rejected(
                    VerificationReason.REVOCATION_CHECK_FAILED, str(exc), claims=claims
                )
            if revoked:
                return _rejected(VerificationReason.REVOKED, claims=claims)

        return VerificationResult(
            ok=True,
            reason=VerificationReason.VERIFIED,
            attestation_id=claims.get("attestation_id"),
            approval_id=claims.get("approval_id"),
            approval_round=claims.get("approval_round"),
            target=dict(target),
            command_operation=claims.get("command_operation"),
            command_hash=claims.get("command_hash"),
            raw=claims,
        )

    async def aclose(self) -> None:
        """Close the owned httpx client (call from lifespan shutdown). No-op for a borrowed one."""
        if self._owns_client and self._client is not None and not self._client.is_closed:
            await self._client.aclose()
        if self._owns_client:
            self._client = None
