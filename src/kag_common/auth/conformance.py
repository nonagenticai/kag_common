"""Static conformance check: network membership must never BE an identity gate.

WHY THIS MODULE EXISTS
======================
``kag_common.auth`` deliberately ships no ASGI ``dispatch`` — every consumer owns
its own middleware (see this package's ``__init__`` docstring, "What deliberately
STAYS per-service"). That is a real architectural choice, but it has a cost:
:func:`kag_common.auth.is_trusted_identity_source` cannot gate anything on its
own, because no request ever flows through this library. A safety helper that
nothing invokes is a guard that cannot fire, and shipping one is worse than
shipping nothing — it reads as protection at review time and provides none.

This module is the compensating control. It is a **lint that fails a build**,
wired into the CONSUMER's own test suite in one line::

    from kag_common.auth.conformance import assert_tokenless_identity_is_gated

    def test_no_tokenless_identity_bypass():
        assert_tokenless_identity_is_gated("src")

It detects the exploitable shape directly in the consumer's source: a branch
gated on NETWORK MEMBERSHIP alone whose body reads a bare tenant header and uses
it as the caller's identity. That is the confused-deputy hole described at
length in ``kag_common.auth`` — with ``10.0.0.0/8`` in the default CIDR list, any
pod in the cluster can name any tenant with no credential, and RLS then binds
``app.current_tenant`` to the FORGED tenant and faithfully scopes the query to
the victim.

Two shapes make a branch conformant:

* it also requires the explicit opt-in — ``is_trusted_identity_source(host)``, or
  ``trust_incluster_identity() and is_trusted_network(host)``; or
* it delegates the whole decision to
  :func:`kag_common.auth.resolve_tokenless_tenant`, which is the preferred form
  because it cannot be re-derived incorrectly.

WHAT THIS CHECK IS NOT
======================
It is a source lint, not a runtime gate. It proves a consumer does not contain
the known-bad shape; it cannot prove the consumer's auth is correct. It is also
deliberately narrow: it flags network-membership-as-identity and nothing else.

KNOWN BLIND SPOTS — stated so nobody reads a clean run as an all-clear
=====================================================================
Measured against the ten repos that depend on this package (census 2026-08-03).
The shapes below are NOT detected, and a consumer exhibiting one will pass:

* **A predicate injected under a different name.** ``graph_adapter_service``
  writes ``if is_trusted(client_host):`` where ``is_trusted`` is a function
  PARAMETER bound to ``_is_trusted_network`` at the call site. Only names in
  ``_NETWORK_ONLY_GATES`` are recognised, so this is invisible. (That specific
  consumer happens to be safe — it pins to the server-side default tenant and
  ignores the header — but the blind spot is real.)
* **A header read more than one call away, or in another module.** The
  interprocedural expansion below resolves exactly ONE hop, and only to a
  function defined in the SAME file.
* **A tenant taken from anywhere other than a literal header name** — a
  constant (``HEADER = "X-Tenant-Id"`` referenced by name), an f-string, or a
  value already extracted upstream of the branch.
* **Whether the resulting tenant is actually used for authorization.** The check
  proves the shape is absent, not that the service is safe.

Widening any of these is welcome; silently trusting a clean run is not.

SIBLING CHECK — licence-token carriage
======================================
:func:`assert_licence_token_carriage` is a second, independent lint in the same
module, wired in the same one-line way::

    from kag_common.auth.conformance import assert_licence_token_carriage

    def test_licence_tokens_are_carried_correctly():
        assert_licence_token_carriage("src")

Where the check above asks "may this peer name a tenant with no token", this one
asks "did the caller actually SEND one". Three rules:

* **R4 — a bare tenant assertion with nothing vouching for it.** A headers dict
  that sets ``X-Tenant-Id`` to a value carrying no ``Bearer`` and does NOT also
  set ``Authorization``. A bare ``X-Tenant-Id`` is an ASSERTION, not a
  credential; per ``kag_common.auth.outbound`` the downstream honours it only
  when an allowlisted ``Authorization: Bearer <service token>`` vouches for it.

  ⚠️ SCOPE, corrected — do not overclaim this rule. R4 would NOT have caught the
  ``kag/src/services/proxy.py`` defect that motivated this lane. That bug was an
  OMISSION FROM A DESTINATION TUPLE — the vouch was applied to a listed set of
  hops and the orchestrator was not in the list — not a headers dict missing an
  ``Authorization`` key, and the proxy builds its headers by subscript
  assignment (``headers["X-Tenant-Id"] = ...``) — a shape R4 cannot read at all,
  along with any dict carrying a ``**spread``. R4 catches the *sibling* shape:
  a hand-rolled headers LITERAL asserting a tenant with no identity behind it. It
  is a narrower rule than the bug that prompted it, and a clean R4 run says
  nothing about whether every destination is vouched — an allowlist/destination
  set is data, and only :func:`assert_onbehalf_allowlists_are_set` and a runtime
  test can speak to its coverage.
* **R1 — a licence token read from the wrong header.** A value derived from
  ``Authorization`` passed into ``introspect_license``. Licences travel in
  ``X-Tenant-Id: Bearer <token>``; ``Authorization`` is the caller's OWN auth.
* **R2 — a caller-supplied subject overwriting the authenticated one.** An
  assignment that rebinds a ``subject_id`` already bound from an introspection
  result with a value read off ``X-Subject-Id``.

REPORT-ONLY CHECK — unseamed tenant admission (0.37.0)
=====================================================
:func:`report_unseamed_tenant_admission` flags a trusted-path branch (gated on
network membership OR the opt-in) that reads a tenant header by hand instead of
through :func:`kag_common.auth.resolve_tokenless_tenant` or a refusing vouch. It
returns findings and emits warnings; it NEVER fails a build on its own, so
upgrading to 0.37.0 cannot turn a consumer red. Assert its result is ``[]`` to
make it gate.

VACUITY
=======
Every failure mode that could make this check silently pass is an error, not a
skip. Scanning zero files raises; a file that cannot be parsed raises. A source
file containing a raw NUL byte is invisible to ``grep``/``ripgrep`` but NOT to
``ast.parse`` — it raises ``ValueError``, which this module surfaces as
:class:`VacuousScanError` rather than swallowing. A check that reports "clean"
because it looked at nothing is the exact class of defect this module exists to
prevent, so it must never be able to do that.
"""

from __future__ import annotations

import ast
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

__all__ = [
    "AllowlistFinding",
    "CarriageFinding",
    "Finding",
    "LicenceCarriageError",
    "OnBehalfAllowlistError",
    "TokenlessIdentityBypassError",
    "UnseamedAdmissionFinding",
    "UnseamedTenantAdmissionWarning",
    "VacuousScanError",
    "assert_licence_token_carriage",
    "assert_onbehalf_allowlists_are_set",
    "assert_tokenless_identity_is_gated",
    "report_unseamed_tenant_admission",
    "scan_carriage_paths",
    "scan_carriage_source",
    "scan_paths",
    "scan_source",
    "scan_unseamed_admission_source",
]


class TokenlessIdentityBypassError(AssertionError):
    """Raised when a consumer uses network membership as an identity gate.

    Subclasses ``AssertionError`` so it reads as a plain test failure in a
    consumer's suite rather than an infrastructure error.
    """


class VacuousScanError(RuntimeError):
    """Raised when the scan could not actually examine what it was asked to.

    A conformance check that inspected nothing must fail loudly. Covers: no
    Python files resolved, and any file that could not be parsed (syntax error,
    unreadable bytes, or an embedded NUL).
    """


# Predicates that answer "WHERE did this come from". Never an identity answer.
_NETWORK_ONLY_GATES = frozenset(
    {
        "is_trusted_network",
        "_is_trusted_network",
        "is_trusted_ip",
        "_is_trusted_ip",
        "is_internal_network",
        "_is_internal_network",
    }
)

# Predicates that answer "MAY this peer assert an identity with no token".
# Presence of any of these in the branch test makes the branch conformant.
_IDENTITY_GATES = frozenset(
    {
        "is_trusted_identity_source",
        "_is_trusted_identity_source",
        "trust_incluster_identity",
        "_trust_incluster_identity",
        "resolve_tokenless_tenant",
    }
)

# Headers that carry a caller-asserted tenant. Compared case-insensitively —
# HTTP header lookups are case-insensitive and consumers spell these both ways.
_TENANT_HEADERS = frozenset({"x-tenant-id", "x-effective-tenant-id", "tenant-id"})

# A REFUSING vouch inside the branch is a real mitigation: the asserted tenant is
# only honoured when an allowlisted service token vouches for it, else 403.
# `kag_graph_service/src/auth/middleware.py:187` is the reference implementation.
# ⚠️ A vouch that only LABELS the result (hirag_service assigns `tenant_source =
# SOURCE_UNVOUCHED_HEADER` and carries on) is NOT a mitigation — but it is not
# distinguishable from a refusing one by name alone, so `_authorized_onbehalf`
# appearing in a branch that ALSO returns/raises is what clears the finding.
_VOUCH_GATES = frozenset(
    {
        "authorized_onbehalf",
        "_authorized_onbehalf",
        "authorized_on_behalf",
        "_authorized_on_behalf",
    }
)


@dataclass(frozen=True)
class Finding:
    """One branch that treats network membership as proof of identity."""

    filename: str
    lineno: int
    col_offset: int
    gate: str
    header: str

    def __str__(self) -> str:
        return (
            f"{self.filename}:{self.lineno}:{self.col_offset}: branch gated on "
            f"`{self.gate}(...)` reads `{self.header}` and binds it as the caller's "
            f"identity. Network membership is not a credential: with 10.0.0.0/8 in "
            f"TRUSTED_CIDRS this lets ANY pod name ANY tenant with no token. Require "
            f"the explicit opt-in — call `kag_common.auth.resolve_tokenless_tenant("
            f"client_host, headers)`, or gate on `is_trusted_identity_source(host)`."
        )


def _called_names(node: ast.AST) -> Iterator[str]:
    """Yield the bare name of every function CALLED anywhere inside ``node``."""
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Call):
            continue
        func = sub.func
        if isinstance(func, ast.Name):
            yield func.id
        elif isinstance(func, ast.Attribute):
            yield func.attr


def _tenant_header_reads(node: ast.AST) -> Iterator[str]:
    """Yield each tenant-header name read as a string constant inside ``node``.

    Covers both spellings consumers actually use::

        request.headers.get("X-Tenant-Id")     # Call arg
        headers["X-Tenant-Id"]                 # Subscript
    """
    for sub in ast.walk(node):
        raw: object = None
        if isinstance(sub, ast.Constant):
            raw = sub.value
        if isinstance(raw, str) and raw.strip().lower() in _TENANT_HEADERS:
            yield raw


def _branch_tests(node: ast.If) -> Iterator[ast.expr]:
    """The test of ``node``.

    ``elif`` chains are separate ``ast.If`` nodes in the ``orelse`` list, so
    ``ast.walk`` reaches them independently; only this node's own test matters.
    """
    yield node.test


def _local_functions(tree: ast.AST) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    """Map every function DEFINED in this module to its node, by bare name.

    Used for the one-hop interprocedural expansion below.
    """
    return {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _refuses_after_vouch(body: list[ast.stmt]) -> bool:
    """True only when a FAILED vouch can stop the request.

    The bail-out must be CONTROLLED BY the vouch: an ``if`` whose test calls a
    vouch predicate and whose body returns or raises. That is
    ``kag_graph_service/src/auth/middleware.py:187``::

        if not await _authorized_onbehalf(request):
            return JSONResponse(status_code=403, ...)

    ⚠️ "the branch calls a vouch AND contains a return somewhere" is NOT good
    enough, and getting this wrong produced a real false negative during
    development: ``hirag_service`` computes the vouch in a TERNARY assigned to
    ``tenant_source`` and then returns on the SUCCESS path
    (``return await call_next(request)``), so the loose rule cleared it. Its own
    comment is explicit — "Vouching can only WIDEN: `authorized_onbehalf` never
    raises and a failed vouch leaves the request accepted exactly as before." A
    labelling-only vouch changes nothing about who gets in, so it must still be
    flagged. An ``ast.IfExp`` (ternary) is deliberately not an ``ast.If`` and so
    can never clear a finding here.
    """
    for stmt in body:
        for sub in ast.walk(stmt):
            if not isinstance(sub, ast.If):
                continue
            if not set(_called_names(sub.test)) & _VOUCH_GATES:
                continue
            branch = list(sub.body) + list(sub.orelse)
            if any(
                isinstance(inner, (ast.Return, ast.Raise))
                for node in branch
                for inner in ast.walk(node)
            ):
                return True
    return False


def scan_source(source: str, *, filename: str = "<string>") -> list[Finding]:
    """Return every tokenless-identity bypass in one Python source string.

    Raises :class:`VacuousScanError` if ``source`` cannot be parsed — an unparseable
    file must never be counted as a clean file.
    """
    try:
        tree = ast.parse(source, filename=filename)
    except (SyntaxError, ValueError) as exc:  # ValueError covers embedded NULs
        msg = f"{filename}: could not be parsed, so it was NOT checked: {exc!r}"
        raise VacuousScanError(msg) from exc

    local_funcs = _local_functions(tree)
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        for test in _branch_tests(node):
            called = set(_called_names(test))
            unsafe = called & _NETWORK_ONLY_GATES
            if not unsafe or called & _IDENTITY_GATES:
                continue
            # A refusing vouch inside the branch is a real mitigation.
            if _refuses_after_vouch(node.body):
                continue
            # The branch body — NOT the else — is what runs for a trusted peer.
            body_reads = {h for stmt in node.body for h in _tenant_header_reads(stmt)}
            # ONE-HOP INTERPROCEDURAL: `requirements_management` puts the branch
            # in `dispatch` and the header read in `_principal_from_trusted_network`
            # in the same module. An intra-function rule would report that file
            # clean, which is exactly the silent pass this check must not do.
            if not body_reads:
                for callee in {n for stmt in node.body for n in _called_names(stmt)}:
                    target = local_funcs.get(callee)
                    if target is not None:
                        body_reads |= set(_tenant_header_reads(target))
            if not body_reads:
                continue
            findings.append(
                Finding(
                    filename=filename,
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                    gate=sorted(unsafe)[0],
                    header=sorted(body_reads)[0],
                )
            )
    return findings


def _python_files(paths: Iterable[str | Path]) -> list[Path]:
    resolved: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            resolved.extend(sorted(p for p in path.rglob("*.py") if p.is_file()))
        elif path.is_file():
            resolved.append(path)
        else:
            msg = f"{path}: does not exist, so nothing was checked"
            raise VacuousScanError(msg)
    return resolved


def scan_paths(*paths: str | Path) -> list[Finding]:
    """Scan files/directories and return every finding.

    Raises :class:`VacuousScanError` when no paths are given, when the paths resolve
    to zero ``.py`` files, or when any resolved file cannot be parsed.
    """
    if not paths:
        msg = "no paths given, so nothing was checked"
        raise VacuousScanError(msg)

    files = _python_files(paths)
    if not files:
        joined = ", ".join(str(p) for p in paths)
        msg = f"resolved zero .py files from [{joined}], so nothing was checked"
        raise VacuousScanError(msg)

    findings: list[Finding] = []
    for file in files:
        try:
            source = file.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            msg = f"{file}: could not be read, so it was NOT checked: {exc!r}"
            raise VacuousScanError(msg) from exc
        findings.extend(scan_source(source, filename=str(file)))
    return findings


def assert_tokenless_identity_is_gated(*paths: str | Path) -> None:
    """Fail the build if any scanned source uses network membership as identity.

    The one-line hook a consumer wires into its own test suite::

        def test_no_tokenless_identity_bypass():
            assert_tokenless_identity_is_gated("src")

    Raises:
        TokenlessIdentityBypassError: at least one offending branch was found.
        VacuousScanError: the scan could not examine what it was asked to.
    """
    findings = scan_paths(*paths)
    if findings:
        detail = "\n".join(f"  - {f}" for f in findings)
        msg = f"{len(findings)} tokenless-identity bypass(es) found:\n{detail}"
        raise TokenlessIdentityBypassError(msg)


# =========================================================================== #
# REPORT-ONLY (0.37.0) — header-asserted tenant admitted on the trusted path
# without the resolve/vouch seam.
#
# `assert_tokenless_identity_is_gated` above clears a branch whose test carries
# the opt-in (`is_trusted_identity_source(host)`), even when its body then reads
# `X-Tenant-Id` by hand. That shape is gated, but it re-derives the decision
# `resolve_tokenless_tenant` exists to own (blank header, `Bearer`-shaped header,
# the observability counter) — the README's own 0.20.0 migration example is
# exactly it. This rule flags every trusted-path branch (network-only OR opt-in
# gate) that reads a tenant header directly with neither `resolve_tokenless_tenant`
# nor a refusing on-behalf vouch.
#
# ⛔ It NEVER raises on a finding, by design: it is new in a minor release and
# must not turn any consumer's CI red on upgrade. It returns the findings and
# emits one `UnseamedTenantAdmissionWarning` each; a consumer that wants it to
# gate asserts the returned list is empty. Vacuity still raises
# (`VacuousScanError`) — a report over nothing is not a clean report.
# =========================================================================== #
_TRUSTED_PATH_GATES = _NETWORK_ONLY_GATES | (_IDENTITY_GATES - {"resolve_tokenless_tenant"})
_RESOLVE_SEAM = "resolve_tokenless_tenant"


class UnseamedTenantAdmissionWarning(UserWarning):
    """A trusted-path branch reads a tenant header without the resolve/vouch seam."""


@dataclass(frozen=True)
class UnseamedAdmissionFinding:
    """One trusted-path branch admitting a header-asserted tenant by hand."""

    filename: str
    lineno: int
    col_offset: int
    gate: str
    header: str

    def __str__(self) -> str:
        return (
            f"{self.filename}:{self.lineno}:{self.col_offset}: [report-only] trusted-path "
            f"branch gated on `{self.gate}(...)` reads `{self.header}` directly. Admit a "
            f"header-asserted tenant through `kag_common.auth.resolve_tokenless_tenant("
            f"client_host, headers)` (or a refusing on-behalf vouch) so the blank / "
            f"Bearer-shaped / counted cases are decided once, not per service."
        )


def scan_unseamed_admission_source(
    source: str, *, filename: str = "<string>"
) -> list[UnseamedAdmissionFinding]:
    """Report-only scan of one source string. Raises only :class:`VacuousScanError`."""
    try:
        tree = ast.parse(source, filename=filename)
    except (SyntaxError, ValueError) as exc:
        msg = f"{filename}: could not be parsed, so it was NOT checked: {exc!r}"
        raise VacuousScanError(msg) from exc

    local_funcs = _local_functions(tree)
    findings: list[UnseamedAdmissionFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        called = set(_called_names(node.test))
        gates = called & _TRUSTED_PATH_GATES
        if not gates or _RESOLVE_SEAM in called:
            continue
        body_calls = {n for stmt in node.body for n in _called_names(stmt)}
        if _RESOLVE_SEAM in body_calls or _refuses_after_vouch(node.body):
            continue
        body_reads = {h for stmt in node.body for h in _tenant_header_reads(stmt)}
        if not body_reads:
            for callee in body_calls:
                target = local_funcs.get(callee)
                if target is None:
                    continue
                if _RESOLVE_SEAM in set(_called_names(target)) or _refuses_after_vouch(target.body):
                    continue
                body_reads |= set(_tenant_header_reads(target))
        if not body_reads:
            continue
        findings.append(
            UnseamedAdmissionFinding(
                filename=filename,
                lineno=node.lineno,
                col_offset=node.col_offset,
                gate=sorted(gates)[0],
                header=sorted(body_reads)[0],
            )
        )
    return findings


def report_unseamed_tenant_admission(*paths: str | Path) -> list[UnseamedAdmissionFinding]:
    """Report (never fail on) trusted-path tenant admission without the seam.

    Returns every finding and emits one :class:`UnseamedTenantAdmissionWarning`
    per finding. To make it gate, a consumer opts in explicitly::

        def test_tenant_admission_uses_the_seam():
            assert report_unseamed_tenant_admission("src") == []

    Raises:
        VacuousScanError: no paths, zero ``.py`` files, or an unparseable file.
    """
    if not paths:
        msg = "no paths given, so nothing was checked"
        raise VacuousScanError(msg)
    files = _python_files(paths)
    if not files:
        joined = ", ".join(str(p) for p in paths)
        msg = f"resolved zero .py files from [{joined}], so nothing was checked"
        raise VacuousScanError(msg)
    findings: list[UnseamedAdmissionFinding] = []
    for file in files:
        try:
            source = file.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            msg = f"{file}: could not be read, so it was NOT checked: {exc!r}"
            raise VacuousScanError(msg) from exc
        findings.extend(scan_unseamed_admission_source(source, filename=str(file)))
    for finding in findings:
        warnings.warn(str(finding), UnseamedTenantAdmissionWarning, stacklevel=2)
    return findings


# =========================================================================== #
# SIBLING CHECK — licence-token carriage (R4, R1, R2). See the module docstring
# for what each rule is the generalisation of.
# =========================================================================== #


class LicenceCarriageError(AssertionError):
    """Raised when a consumer's source mis-carries a licence or service token.

    Subclasses ``AssertionError`` for the same reason
    :class:`TokenlessIdentityBypassError` does — it must read as a test failure
    in the consumer's suite, not as an infrastructure error.
    """


class OnBehalfAllowlistError(AssertionError):
    """Raised when an ``*_ONBEHALF_SUBJECTS`` env var is read but never set.

    An allowlist that no manifest populates is an empty allowlist: the receiver
    vouches for nobody, so every on-behalf-of call it is supposed to accept is
    refused (or, worse, falls through to a tokenless branch).
    """


# The header a caller's OWN auth travels in. A licence NEVER travels here — see
# `kag_common.auth.extract_license_token`, which reads `X-Tenant-Id` only.
_AUTHORIZATION_HEADERS = frozenset({"authorization", "proxy-authorization"})

# R4 keys on the PRIMARY tenant slot only, deliberately NOT on `_TENANT_HEADERS`.
# `X-Effective-Tenant-Id` is bare BY DESIGN (see `auth.apply_effective_tenant`):
# the credential sits in the sibling `X-Tenant-Id: Bearer <SA>`, so treating it as
# a bare assertion would false-positive on every correct delegating call.
_R4_TENANT_HEADER = "x-tenant-id"

# The forwarded end-user subject. Attribution data, never an authenticated one.
_SUBJECT_HEADERS = frozenset({"x-subject-id"})

# The binding an introspection result populates. Rebinding it from a header is
# how a caller renames the acting principal.
_SUBJECT_BINDINGS = frozenset({"subject_id"})

# Substring match, not equality: consumers wrap this as `_introspect_license`,
# `introspect_license_cached`, `auth.introspect_license`, ...
_LICENCE_INTROSPECT_MARKER = "introspect_license"

# Broader marker, used only to seed R2's "this name came from an introspection".
_INTROSPECT_MARKER = "introspect"

_ONBEHALF_ENV_SUFFIX = "_ONBEHALF_SUBJECTS"

_CARRIAGE_REMEDY = {
    "R4": (
        "A bare `X-Tenant-Id` is an ASSERTION, not a credential — the downstream "
        "honours it only when an allowlisted `Authorization: Bearer <service token>` "
        "vouches for it. Build the headers with `kag_common.auth.outbound_headers("
        "tenant_id=..., authorization_service_token=...)` rather than a hand-rolled "
        "dict, so the vouch cannot be omitted one call site at a time."
    ),
    "R1": (
        "Licence tokens travel in `X-Tenant-Id: Bearer <token>`; `Authorization` is "
        "the caller's OWN auth. Introspecting it either 401s or introspects the "
        "wrong principal. Read the token with "
        "`kag_common.auth.extract_license_token(request)`. A service that must "
        "accept the ingress gateway's `Authorization: Bearer <licence>` opts in "
        "with `kag_common.auth.extract_license_token_with_source(request, "
        "accept_authorization=True)` (0.37.0) and binds the plain `X-Tenant-Id` "
        "with `bind_plain_tenant` — never a hand-rolled Authorization read."
    ),
    "R2": (
        "A forwarded `X-Subject-Id` is caller-supplied data; the introspected "
        "subject is the authenticated one. Overwriting the latter with the former "
        "lets any caller rename the acting principal. Use the header only as a "
        "fallback when introspection produced none (`fwd_subject or subject_id`), "
        "which is what `kag_common.auth.apply_effective_tenant` does."
    ),
}


@dataclass(frozen=True)
class CarriageFinding:
    """One outbound call, introspect call, or assignment that mis-carries a token."""

    filename: str
    lineno: int
    col_offset: int
    rule: str
    symbol: str
    detail: str

    def __str__(self) -> str:
        return (
            f"{self.filename}:{self.lineno}:{self.col_offset}: [{self.rule}] "
            f"{self.detail} {_CARRIAGE_REMEDY[self.rule]}"
        )


@dataclass(frozen=True)
class AllowlistFinding:
    """One ``*_ONBEHALF_SUBJECTS`` env var read in code and set in no manifest."""

    env_var: str
    filename: str
    lineno: int

    def __str__(self) -> str:
        return (
            f"{self.filename}:{self.lineno}: `{self.env_var}` is read here but no "
            f"`deployment.yaml` under the manifests root sets it to a non-empty "
            f"`value:`. The allowlist is therefore EMPTY at runtime: the receiver "
            f"vouches for nobody and every on-behalf-of call it should accept is "
            f"refused. Add the env var with an explicit subject CSV to the "
            f"Deployment (a `valueFrom:` does not satisfy this check — this lint "
            f"cannot read a secret, so it cannot prove the value is non-empty)."
        )


def _string_constants(node: ast.AST) -> Iterator[str]:
    """Yield every ``str`` constant in ``node``'s subtree.

    Reaches an f-string's literal segments too: ``f"Bearer {tok}"`` parses to a
    ``JoinedStr`` whose ``values`` include ``Constant("Bearer ")``, so a plain
    ``ast.walk`` sees the word. (Concatenating the literal parts instead would
    drop it whenever a hole splits the phrase.)
    """
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            yield sub.value


def _carries_bearer(value: ast.expr) -> bool:
    """True when ``value`` mentions ``Bearer`` in any string literal it contains.

    Deliberately over-broad in the CLEARING direction: ``f"Bearer {tok}"``,
    ``"Bearer " + tok`` and ``f"Bearer {t}" if t else t`` all clear. A value that
    builds the prefix out of a named constant (``BEARER + tok``) does not, and
    would be a false positive — the fix there is to inline the literal or use
    :func:`kag_common.auth.outbound_headers`.
    """
    return any("bearer" in text.lower() for text in _string_constants(value))


def _reads_authorization_header(node: ast.AST) -> bool:
    """True when ``node``'s subtree names the ``Authorization`` header literally."""
    return any(text.strip().lower() in _AUTHORIZATION_HEADERS for text in _string_constants(node))


def _reads_subject_header(node: ast.AST) -> bool:
    """True when ``node``'s subtree names the ``X-Subject-Id`` header literally."""
    return any(text.strip().lower() in _SUBJECT_HEADERS for text in _string_constants(node))


def _assign_target_names(node: ast.Assign | ast.AnnAssign) -> Iterator[str]:
    """Yield the bare name bound by each target of an assignment.

    ``x`` yields ``x``; ``obj.subject_id`` yields ``subject_id`` (the attribute,
    because ``request.state.subject_id`` is how most consumers spell the
    binding); tuple targets are flattened.
    """
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    for target in targets:
        for sub in ast.walk(target):
            if isinstance(sub, ast.Name):
                yield sub.id
            elif isinstance(sub, ast.Attribute):
                yield sub.attr


def _dict_literal_entries(node: ast.Dict) -> tuple[dict[str, ast.expr], bool]:
    """Map a dict display's literal string keys to their values.

    The second element is True when the display contains something this check
    cannot read statically — a ``**spread`` or a computed key. Such a dict is
    skipped rather than flagged: the missing ``Authorization`` may well be in the
    part that cannot be seen, and a false positive on a correct call site is the
    fastest way to get a lint disabled.
    """
    entries: dict[str, ast.expr] = {}
    opaque = False
    for key, value in zip(node.keys, node.values, strict=True):
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            entries[key.value.strip().lower()] = value
        else:
            opaque = True  # `**other`, or a non-literal key
    return entries, opaque


def _dict_call_entries(node: ast.Call) -> tuple[dict[str, ast.expr], bool, list[ast.Dict]]:
    """Same as :func:`_dict_literal_entries` for a ``dict(...)`` call.

    Keyword names are normalised ``X_Tenant_Id=`` → ``x-tenant-id`` so the two
    spellings compare equal. Any ``**{literal}`` is absorbed and returned in the
    third element so the outer walk does not ALSO evaluate it standalone — doing
    so would flag ``dict(**{"X-Tenant-Id": t}, **{"Authorization": a})``, which
    is compliant.
    """
    entries: dict[str, ast.expr] = {}
    opaque = bool(node.args)  # `dict(mapping)` — contents unknown
    absorbed: list[ast.Dict] = []
    for keyword in node.keywords:
        if keyword.arg is None:
            if isinstance(keyword.value, ast.Dict):
                sub_entries, sub_opaque = _dict_literal_entries(keyword.value)
                entries.update(sub_entries)
                opaque = opaque or sub_opaque
                absorbed.append(keyword.value)
            else:
                opaque = True
        else:
            entries[keyword.arg.replace("_", "-").strip().lower()] = keyword.value
    return entries, opaque, absorbed


def _r4_offence(entries: dict[str, ast.expr], opaque: bool) -> str | None:
    """Return the offending key list when a headers mapping asserts a bare tenant.

    ``None`` when the mapping is compliant, carries a ``Bearer`` tenant value, is
    not a headers mapping at all, or could not be read statically.
    """
    if opaque:
        return None
    tenant = entries.get(_R4_TENANT_HEADER)
    if tenant is None:
        return None
    if _carries_bearer(tenant):
        return None  # the tenant slot itself carries the credential
    if any(header in entries for header in _AUTHORIZATION_HEADERS):
        return None  # a service identity vouches for the bare assertion
    return "{" + ", ".join(sorted(entries)) + "}"


def _authorization_tainted_names(tree: ast.AST) -> frozenset[str]:
    """Names bound anywhere in this module from a read of the Authorization header.

    TRANSITIVE, not one-hop — the shipped shape is two hops
    (``auth_header = headers.get("Authorization")`` then
    ``token = auth_header.removeprefix("Bearer ")``), so a one-hop rule would
    miss the most common instance of the very bug R1 exists for. Iterated to a
    fixpoint; the name set is finite and only grows, so it terminates.

    Module-wide and flow-insensitive: two unrelated locals in different functions
    that happen to share a name are treated as one, and an assignment is honoured
    regardless of where it sits relative to the call. Both over-approximate
    toward REPORTING, which is the correct direction for a credential rule — but
    it does mean a finding can be a false positive on a shadowed name.
    """
    bindings: list[tuple[frozenset[str], ast.expr]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            bindings.append((frozenset(_assign_target_names(node)), node.value))
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            bindings.append((frozenset(_assign_target_names(node)), node.value))
        elif isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
            bindings.append((frozenset({node.target.id}), node.value))

    tainted: set[str] = set()
    changed = True
    while changed:
        changed = False
        for targets, value in bindings:
            names = {sub.id for sub in ast.walk(value) if isinstance(sub, ast.Name)}
            if not _reads_authorization_header(value) and not (names & tainted):
                continue
            fresh = targets - tainted
            if fresh:
                tainted |= fresh
                changed = True
    return frozenset(tainted)


def _is_authorization_derived(arg: ast.expr, tainted: frozenset[str]) -> bool:
    """True when ``arg`` reads Authorization directly or via a one-hop local."""
    if _reads_authorization_header(arg):
        return True
    return any(isinstance(sub, ast.Name) and sub.id in tainted for sub in ast.walk(arg))


def _walk_own_scope(func: ast.FunctionDef | ast.AsyncFunctionDef) -> Iterator[ast.AST]:
    """Walk ``func``'s body WITHOUT descending into a nested function or class.

    A nested scope rebinds names independently, so folding it into the enclosing
    function's ordered pass would compare two different ``subject_id``\\ s. Each
    nested function is reached on its own by the caller's ``ast.walk``.
    """
    stack: list[ast.AST] = list(func.body)
    while stack:
        node = stack.pop()
        yield node
        for child in ast.iter_child_nodes(node):
            if isinstance(
                child,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
            ):
                continue
            stack.append(child)


def _r2_findings(
    func: ast.FunctionDef | ast.AsyncFunctionDef, filename: str
) -> Iterator[CarriageFinding]:
    """Yield each header-sourced rebinding of an introspection-sourced subject.

    THE NARROW, SOUND VERSION — read this before trusting a clean run. A finding
    requires ALL of, inside ONE function body, in source order:

    1. an assignment to a ``subject_id`` target whose value is introspection-
       derived (a call whose name contains ``introspect``, or a name previously
       bound from one), then
    2. a LATER assignment (strictly greater ``lineno``) to a ``subject_id``
       target whose value is ``X-Subject-Id``-derived — the header named
       literally, or a name previously bound from it — and which does NOT still
       reference the introspected binding.

    That last clause is the discriminator, and it is why the sanctioned
    ``subject_id = fwd_subject or subject_id`` fallback is not flagged: the
    authenticated value can still win, so nothing was overwritten. A plain
    ``subject_id = fwd_subject`` is.

    It therefore CANNOT see: the overwrite happening in a different function or
    module from the introspection (``ident.subject_id = hdr`` in a helper that
    takes the introspected object as a parameter is the realistic miss — the two
    assignments are in different scopes, so nothing links them); a rebinding
    through an alias (``ident.subject = hdr``); a dict or state write
    (``state["subject_id"] = hdr``); branch-relative order, since it compares
    source position, not control flow; or a header read hidden behind a constant
    (``SUBJECT_HEADER = "X-Subject-Id"`` referenced by name).

    A broad version that guessed at those would report a clean run it had not
    earned. This one under-reports and says so.
    """
    introspected: set[str] = set()
    header_sourced: set[str] = set()
    assignments = sorted(
        (
            node
            for node in _walk_own_scope(func)
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None
        ),
        key=lambda node: (node.lineno, node.col_offset),
    )
    authenticated_subject_line: int | None = None
    for node in assignments:
        value = node.value
        if value is None:  # unreachable — guarded by the comprehension above
            continue
        names = {sub.id for sub in ast.walk(value) if isinstance(sub, ast.Name)}
        from_introspection = bool(names & introspected) or any(
            _INTROSPECT_MARKER in called for called in _called_names(value)
        )
        from_header = _reads_subject_header(value) or bool(names & header_sourced)
        targets = set(_assign_target_names(node))
        # Introspection wins: a value that STILL references the authenticated
        # binding (`fwd_subject or subject_id`) has not overwritten anything.
        if from_introspection:
            introspected |= targets
            if targets & _SUBJECT_BINDINGS:
                authenticated_subject_line = node.lineno
            continue
        if from_header:
            header_sourced |= targets
        if authenticated_subject_line is not None and targets & _SUBJECT_BINDINGS and from_header:
            yield CarriageFinding(
                filename=filename,
                lineno=node.lineno,
                col_offset=node.col_offset,
                rule="R2",
                symbol="subject_id",
                detail=(
                    f"`subject_id`, bound from an introspection result at line "
                    f"{authenticated_subject_line}, is overwritten here with the "
                    f"caller-supplied `X-Subject-Id` header."
                ),
            )


def _scan_carriage_tree(tree: ast.AST, filename: str) -> tuple[list[CarriageFinding], int]:
    """Run R4/R1/R2 over one parsed module.

    Returns the findings and the number of CANDIDATE nodes examined — dict
    displays, calls and assignments, the three node kinds these rules key on.
    Zero candidates across every resolved file means the scan walked no code, and
    the caller turns that into a :class:`VacuousScanError`.
    """
    findings: list[CarriageFinding] = []
    candidates = 0

    # --- R4 -------------------------------------------------------------- #
    # `dict(...)` calls first, so any `**{literal}` they absorb is not ALSO
    # evaluated on its own by the walk below.
    absorbed_ids: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not (isinstance(node.func, ast.Name) and node.func.id == "dict"):
            continue
        entries, opaque, absorbed = _dict_call_entries(node)
        absorbed_ids.update(id(literal) for literal in absorbed)
        candidates += 1
        offence = _r4_offence(entries, opaque)
        if offence is not None:
            findings.append(
                CarriageFinding(
                    filename=filename,
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                    rule="R4",
                    symbol=offence,
                    detail=(
                        f"`dict(...)` {offence} sets a bare `X-Tenant-Id` and no "
                        f"`Authorization`, so this outbound call carries no service "
                        f"identity to vouch for the tenant it asserts."
                    ),
                )
            )

    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict) or id(node) in absorbed_ids:
            continue
        candidates += 1
        entries, opaque = _dict_literal_entries(node)
        offence = _r4_offence(entries, opaque)
        if offence is not None:
            findings.append(
                CarriageFinding(
                    filename=filename,
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                    rule="R4",
                    symbol=offence,
                    detail=(
                        f"headers dict {offence} sets a bare `X-Tenant-Id` and no "
                        f"`Authorization`, so this outbound call carries no service "
                        f"identity to vouch for the tenant it asserts."
                    ),
                )
            )

    # --- R1 -------------------------------------------------------------- #
    tainted = _authorization_tainted_names(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        candidates += 1
        callee = node.func
        name = (
            callee.id
            if isinstance(callee, ast.Name)
            else callee.attr
            if isinstance(callee, ast.Attribute)
            else ""
        )
        if _LICENCE_INTROSPECT_MARKER not in name:
            continue
        args = list(node.args) + [keyword.value for keyword in node.keywords]
        if any(_is_authorization_derived(arg, tainted) for arg in args):
            findings.append(
                CarriageFinding(
                    filename=filename,
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                    rule="R1",
                    symbol=name,
                    detail=(
                        f"`{name}(...)` is called with a value derived from the "
                        f"`Authorization` header."
                    ),
                )
            )

    # --- R2 -------------------------------------------------------------- #
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            candidates += 1
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            findings.extend(_r2_findings(node, filename))

    findings.sort(key=lambda f: (f.lineno, f.col_offset, f.rule))
    return findings, candidates


def scan_carriage_source(source: str, *, filename: str = "<string>") -> list[CarriageFinding]:
    """Return every licence-carriage finding in one Python source string.

    Raises :class:`VacuousScanError` if ``source`` cannot be parsed — an
    unparseable file must never be counted as a clean file.
    """
    try:
        tree = ast.parse(source, filename=filename)
    except (SyntaxError, ValueError) as exc:  # ValueError covers embedded NULs
        msg = f"{filename}: could not be parsed, so it was NOT checked: {exc!r}"
        raise VacuousScanError(msg) from exc
    findings, _ = _scan_carriage_tree(tree, filename)
    return findings


def scan_carriage_paths(*paths: str | Path) -> list[CarriageFinding]:
    """Scan files/directories for licence-carriage findings.

    Raises :class:`VacuousScanError` when no paths are given, when the paths
    resolve to zero ``.py`` files, when any resolved file cannot be read or
    parsed, or when every resolved file together yielded ZERO candidate nodes —
    a lint that found nothing because it looked at nothing must fail loudly.
    """
    if not paths:
        msg = "no paths given, so nothing was checked"
        raise VacuousScanError(msg)

    files = _python_files(paths)
    if not files:
        joined = ", ".join(str(p) for p in paths)
        msg = f"resolved zero .py files from [{joined}], so nothing was checked"
        raise VacuousScanError(msg)

    findings: list[CarriageFinding] = []
    candidates = 0
    for file in files:
        try:
            source = file.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            msg = f"{file}: could not be read, so it was NOT checked: {exc!r}"
            raise VacuousScanError(msg) from exc
        try:
            tree = ast.parse(source, filename=str(file))
        except (SyntaxError, ValueError) as exc:
            msg = f"{file}: could not be parsed, so it was NOT checked: {exc!r}"
            raise VacuousScanError(msg) from exc
        file_findings, file_candidates = _scan_carriage_tree(tree, str(file))
        findings.extend(file_findings)
        candidates += file_candidates

    if candidates == 0:
        joined = ", ".join(str(p) for p in paths)
        msg = (
            f"examined zero candidate nodes (dict displays, calls, assignments) across "
            f"{len(files)} file(s) from [{joined}], so nothing was actually checked"
        )
        raise VacuousScanError(msg)
    return findings


def assert_licence_token_carriage(*paths: str | Path) -> None:
    """Fail the build if any scanned source mis-carries a licence or service token.

    The one-line hook a consumer wires into its own test suite, alongside
    :func:`assert_tokenless_identity_is_gated`::

        def test_licence_tokens_are_carried_correctly():
            assert_licence_token_carriage("src")

    Static only — no network, no cluster, no manifests — so it runs in any
    consumer's CI. See the module docstring for what R4/R1/R2 each match, and
    :func:`_r2_findings` for R2's stated limits.

    Raises:
        LicenceCarriageError: at least one offending site was found.
        VacuousScanError: the scan could not examine what it was asked to.
    """
    findings = scan_carriage_paths(*paths)
    if findings:
        detail = "\n".join(f"  - {f}" for f in findings)
        msg = f"{len(findings)} licence-carriage defect(s) found:\n{detail}"
        raise LicenceCarriageError(msg)


# --------------------------------------------------------------------------- #
# R5/R8 — the on-behalf-of allowlist cross-check. DELIBERATELY a separate
# function with a REQUIRED `manifests_root`: it needs the gitops tree on disk,
# which a consumer's CI does not have. Folding it into
# `assert_licence_token_carriage` would either make that check un-runnable in a
# consumer, or make it silently skip the manifest half — a green light for a
# rule that never ran.
# --------------------------------------------------------------------------- #


def _is_onbehalf_env_name(value: str) -> bool:
    """True for a SCREAMING_SNAKE name ending in ``_ONBEHALF_SUBJECTS``."""
    if not value.endswith(_ONBEHALF_ENV_SUFFIX) or value == _ONBEHALF_ENV_SUFFIX:
        return False
    return all(
        char.isascii() and (char.isupper() or char.isdigit() or char == "_") for char in value
    )


def _yaml_scalar(raw: str) -> str:
    """Strip whitespace and one layer of matching quotes off a YAML scalar."""
    text = raw.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        text = text[1:-1]
    return text.strip()


def _manifest_env_values(path: Path) -> dict[str, str]:
    """Every ``- name: FOO`` / ``value: ...`` container env pair in one manifest.

    Deliberately line-based. ``kag_common`` is a PUBLISHED library and ships no
    YAML dependency; adding one for a lint that only runs where the gitops tree
    is on disk would push a transitive dep onto every consumer.

    Only a literal ``value:`` counts. A ``valueFrom:`` (secret/configMap ref) is
    recorded as ABSENT: this lint cannot read the referenced object, so it cannot
    prove the value is non-empty, and claiming otherwise would be the vacuous
    pass this module exists to prevent.

    Known limits: an inline-flow entry (``- {name: FOO, value: bar}``) and a
    name/value pair split across a YAML anchor or merge key are not read.
    """
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        msg = f"{path}: could not be read, so it was NOT checked: {exc!r}"
        raise VacuousScanError(msg) from exc

    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.startswith("- name:"):
            continue
        name = _yaml_scalar(stripped[len("- name:") :])
        if not name:
            continue
        item_indent = len(line) - len(line.lstrip())
        found = ""
        for follow in lines[index + 1 :]:
            if not follow.strip():
                continue
            indent = len(follow) - len(follow.lstrip())
            if indent <= item_indent:
                break  # dedent — this list item is over
            follow_stripped = follow.strip()
            if follow_stripped.startswith("- "):
                # A nested list opened under this `- name:` — so it was a
                # CONTAINER name, not an env entry, and the `value:` further down
                # belongs to one of its env vars. Do not steal it.
                break
            if follow_stripped.startswith("value:"):
                found = _yaml_scalar(follow_stripped[len("value:") :])
                break
            if follow_stripped.startswith("valueFrom:"):
                break  # a ref this check cannot read; leave it recorded as absent
        # A name set with a real value ANYWHERE must not be erased by a later
        # valueFrom-only occurrence in another Deployment in the same tree.
        if found or name not in values:
            values[name] = found
    return values


def _onbehalf_env_reads(tree: ast.AST, filename: str) -> Iterator[AllowlistFinding]:
    """Yield every ``*_ONBEHALF_SUBJECTS`` env var this module reads.

    TWO shapes, because the fleet uses both and matching only the first reports
    the majority of consumers CLEAN:

    1. **The name as a string literal** — ``os.getenv("FOO_ONBEHALF_SUBJECTS")``,
       ``os.environ["FOO_ONBEHALF_SUBJECTS"]``, an explicit pydantic alias.
       ``discovery_engine`` is written this way.
    2. **The name as an assignment TARGET** — a pydantic-settings field
       declaration inside a ``Settings`` class::

           class Settings(BaseSettings):
               KAG_ONBEHALF_SUBJECTS: str = Field(default="")

       ``kag/src/core/config.py`` is written this way, and most FastAPI services
       on this fleet are pydantic-settings. Matched on the IDENTIFIER pattern
       alone — deliberately conservative, no attempt to resolve what
       pydantic-settings will actually read.

    ⚠️ BLIND SPOT, stated rather than guessed at. Shape 2 assumes the env var
    name EQUALS the field name, which is pydantic-settings' default but not its
    only behaviour. A field carrying ``validation_alias=`` or ``alias=`` to a
    DIFFERENT env name is attributed to the wrong variable: this check will go
    looking for a manifest entry named after the FIELD and report a finding
    against a var that is not the one the process reads, while the var it does
    read goes unchecked. There is a measured incident on this fleet of exactly
    that erasure — a ``validation_alias`` silently discarded the field name and
    eight tests that believed they were armed ran unarmed. Resolving the alias
    is possible and welcome; pretending it is resolved is not, so until then a
    finding on an aliased field is a NAME to verify by hand, not a verdict.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str) and _is_onbehalf_env_name(node.value):
                yield AllowlistFinding(env_var=node.value, filename=filename, lineno=node.lineno)
            continue
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            for name in _assign_target_names(node):
                if _is_onbehalf_env_name(name):
                    yield AllowlistFinding(env_var=name, filename=filename, lineno=node.lineno)


def assert_onbehalf_allowlists_are_set(code_root: str | Path, manifests_root: str | Path) -> None:
    """Fail if an ``*_ONBEHALF_SUBJECTS`` env var is read in code and set nowhere.

    ``manifests_root`` is REQUIRED and has no default on purpose — this check can
    only be called where the gitops manifests genuinely exist, so it can never
    "pass" by finding no manifests to contradict it::

        def test_onbehalf_allowlists_are_populated():
            assert_onbehalf_allowlists_are_set("src", "/path/to/gitops/clusters/strato")

    Finds every ``*_ONBEHALF_SUBJECTS`` name read under ``code_root`` — as a
    string literal (``os.getenv(...)``) OR as a pydantic-settings field
    declaration, see :func:`_onbehalf_env_reads` for both shapes and for the
    ``validation_alias`` blind spot — then requires each to appear in some
    ``deployment.yaml``/``deployment.yml`` under ``manifests_root`` with a
    non-empty literal ``value:``.

    Known limits: a name assembled at runtime (``f"{SERVICE}_ONBEHALF_SUBJECTS"``)
    is not seen; a field whose env name is aliased away from its identifier is
    attributed to the WRONG variable (see :func:`_onbehalf_env_reads`); and a
    ``valueFrom:`` is treated as unset because this lint cannot read a Secret.

    Raises:
        OnBehalfAllowlistError: at least one read var is set in no manifest.
        VacuousScanError: zero ``.py`` files, zero manifests, or zero
            ``*_ONBEHALF_SUBJECTS`` reads — nothing was actually cross-checked.
    """
    files = _python_files([code_root])
    if not files:
        msg = f"resolved zero .py files from [{code_root}], so nothing was checked"
        raise VacuousScanError(msg)

    reads: list[AllowlistFinding] = []
    for file in files:
        try:
            source = file.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            msg = f"{file}: could not be read, so it was NOT checked: {exc!r}"
            raise VacuousScanError(msg) from exc
        try:
            tree = ast.parse(source, filename=str(file))
        except (SyntaxError, ValueError) as exc:
            msg = f"{file}: could not be parsed, so it was NOT checked: {exc!r}"
            raise VacuousScanError(msg) from exc
        reads.extend(_onbehalf_env_reads(tree, str(file)))

    if not reads:
        msg = (
            f"found zero `*{_ONBEHALF_ENV_SUFFIX}` reads under [{code_root}], so the "
            f"manifest cross-check had nothing to verify"
        )
        raise VacuousScanError(msg)

    manifests_path = Path(manifests_root)
    if not manifests_path.exists():
        msg = f"{manifests_path}: manifests root does not exist, so nothing was checked"
        raise VacuousScanError(msg)
    manifests = sorted(
        {
            path
            for pattern in ("deployment.yaml", "deployment.yml")
            for path in manifests_path.rglob(pattern)
            if path.is_file()
        }
    )
    if not manifests:
        msg = (
            f"resolved zero deployment.yaml files from [{manifests_path}], so no "
            f"allowlist could be confirmed set"
        )
        raise VacuousScanError(msg)

    declared: dict[str, str] = {}
    for manifest in manifests:
        for name, value in _manifest_env_values(manifest).items():
            if value or name not in declared:
                declared[name] = value

    findings: list[AllowlistFinding] = []
    seen: set[str] = set()
    for read in sorted(reads, key=lambda r: (r.env_var, r.filename, r.lineno)):
        if read.env_var in seen:
            continue
        seen.add(read.env_var)
        if not declared.get(read.env_var):
            findings.append(read)

    if findings:
        detail = "\n".join(f"  - {f}" for f in findings)
        msg = (
            f"{len(findings)} on-behalf-of allowlist(s) read in code but set in no "
            f"manifest under {manifests_path} ({len(manifests)} deployment file(s) "
            f"checked):\n{detail}"
        )
        raise OnBehalfAllowlistError(msg)
