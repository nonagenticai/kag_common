"""Shared ``audience`` precondition for this package's two RS256 verifiers.

Both ``attestation.AttestationVerifier`` and ``internal_token.InternalTokenVerifier`` hand a
caller-supplied ``audience`` straight to ``jwt.decode``, and both declare it ``str``. Neither
checked that it *is* one — and PyJWT does not fail closed on a bad one in any single way, so
"whatever the caller passed" produced four different permanent outages depending on the type
it passed. This module exists for the same reason :mod:`kag_common._jwks` does: the rule is
one rule, and a second verifier must not have to rediscover it.

WHY A PRECONDITION AND NOT AN ``except`` ARM. The verifiers must convert a bad *token* into a
typed rejection (``MALFORMED_TOKEN`` / ``InvalidInternalTokenError``), and PyJWT signals one
class of bad time claim with a bare ``TypeError`` (see the arms in both ``verify()``
methods). But ``jwt.decode`` raises the SAME bare ``TypeError`` for a bad ``audience``
ARGUMENT — ``_validate_claims`` checks ``isinstance(audience, (str, Iterable))`` before it
looks at the payload at all, so the argument error is raised *first*, on every token. An
``except TypeError`` arm alone would therefore turn one line of bad wiring into "every caller
sends malformed tokens", forever, silently, blaming the caller. Screening ``audience`` at
CONSTRUCTION is what makes those arms honest: once the argument cannot be the cause, a
``TypeError`` out of ``jwt.decode`` can only have come from the token's own claims.

WHAT IS REFUSED, AND WHY EACH ONE IS ALREADY BROKEN. Measured against pyjwt 2.13 through
``AttestationVerifier.verify`` with a correctly-signed, otherwise-valid token. Every row but
the last is REFUSED; the last is REPAIRED, because it is the one whose intent is unambiguous:

===========================  ===================================================
``audience=``                pre-precondition behaviour, on EVERY token forever
===========================  ===================================================
``123`` / ``3.5``            ``TypeError: audience must be a string, iterable or
                             None`` — escapes ``verify()`` entirely
``""``                       ``InvalidAudienceError: Audience doesn't match``
``None``                     ``InvalidAudienceError: Invalid audience``
``b"evidence-review"``       ``Audience doesn't match`` — ``bytes`` IS iterable,
                             so PyJWT compares the token's ``aud`` against a
                             sequence of INTEGERS
``[]``                       ``Audience doesn't match`` (nothing to match)
``[123]``                    ``Audience doesn't match``
a generator                  verifies ONCE, then ``Audience doesn't match``
                             forever — PyJWT consumes the iterator. REPAIRED, not
                             refused: materialised once here, so it holds on
                             every request instead of only the first.
===========================  ===================================================

Every row is a total, permanent auth failure that presents as a caller problem. None of them
is a configuration anyone can be depending on today, which is why refusing them breaks no
working deployment: the shapes that DO work — ``str``, ``list[str]``, ``tuple[str, ...]``,
``set[str]`` — are exactly the shapes this function admits (measured: all four returned
``ok=True`` on the same token, both before and after this module existed).

``ValueError``, not ``TypeError``, for consistency with the ``jwks_url``/``issuer`` checks
standing beside it in the same ``__init__`` — and because these constructors' contract is
that a caller wiring error raises immediately, while a ``TypeError`` is the very thing the
decode ladders now convert.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

__all__ = ["checked_audience"]


def checked_audience(value: Any, *, owner: str) -> str | tuple[str, ...]:
    """Return ``value`` as an audience ``jwt.decode`` can use, or raise ``ValueError``.

    ``owner`` names the constructing class in the message, so an operator reading the
    traceback is told which verifier is mis-wired without having to guess.

    An iterable is materialised into a ``tuple`` rather than passed through. That is not
    tidiness: a generator has ``__iter__``, so it satisfies PyJWT's own admission test and
    then gets CONSUMED by the first ``jwt.decode`` — measured, the first token verified and
    every token after it was refused ``Audience doesn't match``. Materialising once at
    construction makes the value re-readable, which is the property a process-scoped verifier
    needs and the one an iterator cannot offer.
    """
    if isinstance(value, str):
        if not value:
            raise ValueError(f"{owner} requires a non-empty audience (this service's own)")
        return value

    # Checked BEFORE the ``Iterable`` test, which ``bytes`` would otherwise pass: PyJWT would
    # then match the token's ``aud`` against a sequence of ints and refuse every token.
    if isinstance(value, bytes | bytearray):
        raise ValueError(
            f"{owner} requires audience to be a str (or a collection of str), not "
            f"{type(value).__name__} — bytes is iterable, so PyJWT would compare the token's "
            "aud against integers and refuse every token"
        )

    # The same test ``jwt.api_jwt._validate_claims`` applies to this argument, so a value that
    # passes here cannot make ``jwt.decode`` raise ``TypeError`` on the audience — which is
    # precisely what the ``except TypeError`` arms in both verifiers depend on.
    if not isinstance(value, Iterable):
        raise ValueError(
            f"{owner} requires audience to be a str (or a collection of str), not "
            f"{type(value).__name__} — jwt.decode raises TypeError on it, on every token"
        )

    members = tuple(value)
    if not members:
        raise ValueError(f"{owner} requires a non-empty audience (this service's own)")
    if any(not isinstance(member, str) or not member for member in members):
        raise ValueError(
            f"{owner} requires every audience member to be a non-empty str; got "
            f"{[type(m).__name__ for m in members]} — PyJWT would refuse every token"
        )
    return members
