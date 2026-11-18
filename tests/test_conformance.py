"""The tokenless-identity gate must be LOAD-BEARING, not decorative.

Two layers are under test here:

* :func:`kag_common.auth.resolve_tokenless_tenant` — the single runtime seam. It
  is real library code that INVOKES ``is_trusted_identity_source``, so a
  regression in the gate is caught in this repo's own CI rather than in a
  consumer months later.
* ``kag_common.auth.conformance`` — the static lint that fires in a CONSUMER's
  suite when network membership is used as an identity gate.

Every test here asserts on BEHAVIOUR against the real functions. None of them
can be satisfied by a stub: the mutations listed in each docstring each produce a
real assertion failure, never an ``ImportError``.
"""

from __future__ import annotations

import textwrap

import pytest

from kag_common import auth
from kag_common.auth import conformance

VICTIM_TENANT = "00000000-0000-0000-0000-victim000001"
POD_CIDR_PEER = "10.42.7.31"

# --------------------------------------------------------------------------- #
# The REAL exploitable shape, copied from the consumers this gate exists for:
# `kag_orchestrator/src/auth/middleware.py` and
# `ingestion_service/src/auth/middleware.py`. A branch gated on network
# membership alone, whose body takes the tenant straight off a bare header.
# --------------------------------------------------------------------------- #
UNSAFE_CONSUMER_SOURCE = textwrap.dedent(
    """
    from kag_common.auth import is_trusted_network


    class AuthMiddleware:
        async def dispatch(self, request, call_next):
            client_host = request.client.host if request.client else None
            token = extract_license_token(request)
            if not token and is_trusted_network(client_host):
                tenant_id = request.headers.get("X-Tenant-Id", "").strip()
                request.state.tenant_id = tenant_id
                return await call_next(request)
            return unauthorized(request)
    """
)

# Same middleware, migrated onto the opt-in predicate.
SAFE_PREDICATE_SOURCE = UNSAFE_CONSUMER_SOURCE.replace(
    "is_trusted_network(client_host)", "is_trusted_identity_source(client_host)"
).replace("import is_trusted_network", "import is_trusted_identity_source")

# Same middleware, migrated onto the single seam.
SAFE_SEAM_SOURCE = textwrap.dedent(
    """
    from kag_common.auth import resolve_tokenless_tenant


    class AuthMiddleware:
        async def dispatch(self, request, call_next):
            client_host = request.client.host if request.client else None
            tenant_id = resolve_tokenless_tenant(client_host, request.headers)
            if tenant_id is not None:
                request.state.tenant_id = tenant_id
                return await call_next(request)
            return unauthorized(request)
    """
)


# --------------------------------------------------------------------------- #
# Layer 1 — the runtime seam. `is_trusted_identity_source` is now invoked by
# library code, so the gate regresses HERE if it is ever weakened.
# --------------------------------------------------------------------------- #
def test_seam_refuses_a_forged_tenant_when_the_opt_in_is_absent(monkeypatch):
    """The default posture: a pod CIDR peer naming a victim tenant gets NOTHING.

    MUTATION: change ``is_trusted_identity_source`` to
    ``return is_trusted_network(host)`` (drop the flag) and this fails with a
    real assertion — ``resolve_tokenless_tenant`` starts handing back the forged
    tenant. Membership below is asserted separately so the test cannot pass
    merely because the peer stopped being trusted.
    """
    monkeypatch.delenv("AUTH_TRUST_INCLUSTER_IDENTITY", raising=False)
    # The peer IS network-trusted — this is a gate decision, not a routing accident.
    assert auth.is_trusted_network(POD_CIDR_PEER) is True

    resolved = auth.resolve_tokenless_tenant(POD_CIDR_PEER, {"X-Tenant-Id": VICTIM_TENANT})
    assert resolved is None


def test_seam_returns_the_tenant_only_once_explicitly_opted_in(monkeypatch):
    """The GREEN half — without it, "always None" would pass the test above.

    MUTATION: make ``resolve_tokenless_tenant`` return ``None`` unconditionally
    and this fails with a real assertion.
    """
    monkeypatch.setenv("AUTH_TRUST_INCLUSTER_IDENTITY", "true")
    resolved = auth.resolve_tokenless_tenant(POD_CIDR_PEER, {"X-Tenant-Id": VICTIM_TENANT})
    assert resolved == VICTIM_TENANT


def test_seam_is_not_widened_by_the_flag_alone(monkeypatch):
    """Opting in must not make the whole internet a trusted identity source."""
    monkeypatch.setenv("AUTH_TRUST_INCLUSTER_IDENTITY", "true")
    assert auth.resolve_tokenless_tenant("8.8.8.8", {"X-Tenant-Id": VICTIM_TENANT}) is None


def test_seam_never_returns_a_license_token_as_a_tenant(monkeypatch):
    """``X-Tenant-Id: Bearer <token>`` is a CREDENTIAL, not a tokenless claim.

    Returning it would bind a secret as ``app.current_tenant`` and log it. The
    request must fall through to introspection instead.
    """
    monkeypatch.setenv("AUTH_TRUST_INCLUSTER_IDENTITY", "true")
    assert auth.resolve_tokenless_tenant(POD_CIDR_PEER, {"X-Tenant-Id": "Bearer s3cr3t"}) is None
    assert auth.resolve_tokenless_tenant(POD_CIDR_PEER, {"X-Tenant-Id": "bearer s3cr3t"}) is None


@pytest.mark.parametrize("headers", [{}, {"X-Tenant-Id": ""}, {"X-Tenant-Id": "   "}])
def test_seam_requires_a_non_blank_tenant(monkeypatch, headers):
    monkeypatch.setenv("AUTH_TRUST_INCLUSTER_IDENTITY", "true")
    assert auth.resolve_tokenless_tenant(POD_CIDR_PEER, headers) is None


def test_seam_header_lookup_is_case_insensitive(monkeypatch):
    """Starlette lower-cases headers; a plain dict does not. Both must work."""
    monkeypatch.setenv("AUTH_TRUST_INCLUSTER_IDENTITY", "true")
    assert auth.resolve_tokenless_tenant(POD_CIDR_PEER, {"x-tenant-id": VICTIM_TENANT}) == (
        VICTIM_TENANT
    )


# --------------------------------------------------------------------------- #
# Layer 2 — the static lint. Positive control first: if this stops finding the
# real consumer shape, the check has silently become decorative.
# --------------------------------------------------------------------------- #
def test_lint_flags_the_real_consumer_bypass():
    """POSITIVE CONTROL. The shipped kag_orchestrator/ingestion_service shape.

    MUTATION: drop ``"is_trusted_network"`` from ``_NETWORK_ONLY_GATES``, or drop
    ``"x-tenant-id"`` from ``_TENANT_HEADERS``, and this fails with a real
    assertion (``0 == 1``).
    """
    findings = conformance.scan_source(UNSAFE_CONSUMER_SOURCE, filename="middleware.py")
    assert len(findings) == 1
    (finding,) = findings
    assert finding.gate == "is_trusted_network"
    assert finding.header == "X-Tenant-Id"
    assert finding.filename == "middleware.py"
    # The message must name the fix, not just the sin.
    assert "resolve_tokenless_tenant" in str(finding)


def test_lint_raises_on_the_real_consumer_bypass(tmp_path):
    """The assertion helper — what a consumer actually wires in — must FAIL."""
    (tmp_path / "middleware.py").write_text(UNSAFE_CONSUMER_SOURCE)
    with pytest.raises(conformance.TokenlessIdentityBypassError) as excinfo:
        conformance.assert_tokenless_identity_is_gated(tmp_path)
    assert "middleware.py" in str(excinfo.value)


@pytest.mark.parametrize(
    ("label", "source"),
    [("opt-in predicate", SAFE_PREDICATE_SOURCE), ("single seam", SAFE_SEAM_SOURCE)],
)
def test_lint_passes_a_migrated_consumer(label, source):
    """NEGATIVE CONTROL — the lint must not be a constant `fail`.

    Without this, ``return [Finding(...)]`` would satisfy the positive control.
    """
    assert conformance.scan_source(source, filename="middleware.py") == [], label


def test_lint_accepts_the_explicit_conjunction():
    """``trust_incluster_identity() and is_trusted_network()`` is the safe form.

    w2v_common spells the gate this way (``middleware.py:794``); flagging it
    would be a false positive that trains people to disable the check.
    """
    source = textwrap.dedent(
        """
        def dispatch(request):
            if trust_incluster_identity() and is_trusted_network(client_host):
                return request.headers.get("X-Tenant-Id")
        """
    )
    assert conformance.scan_source(source, filename="w2v_shape.py") == []


def test_lint_ignores_network_checks_that_are_not_identity_decisions():
    """``is_trusted_network`` is legitimate for non-identity allowlists."""
    source = textwrap.dedent(
        """
        def metrics(request):
            if is_trusted_network(request.client.host):
                return render_metrics()
            return forbidden()
        """
    )
    assert conformance.scan_source(source, filename="metrics.py") == []


def test_lint_does_not_flag_the_else_branch():
    """Only the branch that RUNS for a trusted peer matters.

    Reading the tenant header in the ``else`` (the token path) is normal and must
    not be flagged, or the check is noise.
    """
    source = textwrap.dedent(
        """
        def dispatch(request):
            if is_trusted_network(client_host):
                return anonymous()
            token = request.headers.get("X-Tenant-Id")
            return introspect(token)
        """
    )
    assert conformance.scan_source(source, filename="else_branch.py") == []


def test_lint_flags_a_locally_defined_equivalent():
    """A consumer that hand-rolls ``_is_trusted_network`` is equally exploitable.

    The hole is the SHAPE, not the import.
    """
    source = textwrap.dedent(
        """
        def dispatch(request):
            if _is_trusted_network(client_host):
                return request.headers["x-tenant-id"]
        """
    )
    findings = conformance.scan_source(source, filename="local.py")
    assert len(findings) == 1
    assert findings[0].gate == "_is_trusted_network"


def test_lint_flags_the_inline_or_default_shape():
    """`nlp_service/src/auth/middleware.py:154-166` — no temp var, fused `or`.

    The tightest variant in the fleet. A rule that keyed on the ``raw_tenant =``
    assignment would miss it.
    """
    source = textwrap.dedent(
        """
        def dispatch(request):
            client_host = request.client.host if request.client else None
            if _is_trusted_network(client_host):
                tenant_id = request.headers.get("X-Tenant-Id", "").strip() or DEFAULT_TENANT_ID
                if tenant_id.lower().startswith("bearer "):
                    tenant_id = DEFAULT_TENANT_ID
                request.state.tenant_id = tenant_id
        """
    )
    findings = conformance.scan_source(source, filename="nlp_shape.py")
    assert len(findings) == 1


def test_lint_follows_one_hop_into_a_module_local_helper():
    """`requirements_management/src/auth/middleware.py:213-222` — interprocedural.

    The branch and the header read are in DIFFERENT functions in the same module.
    An intra-function rule reports this file clean, which is precisely the silent
    pass this check exists to prevent.

    MUTATION: delete the one-hop expansion block in ``scan_source`` and this
    fails with a real assertion (``0 == 1``).
    """
    source = textwrap.dedent(
        """
        def _principal_from_trusted_network(request):
            x_tenant_id = request.headers.get("X-Tenant-Id")
            tenant_id = x_tenant_id.strip() if x_tenant_id else DEFAULT_TENANT_ID
            return Principal(tenant_id=tenant_id, source="trusted_network")


        def dispatch(request):
            client_host = request.client.host if request.client else None
            if _is_trusted_network(client_host):
                principal = _principal_from_trusted_network(request)
                _apply_principal(request, principal)
        """
    )
    findings = conformance.scan_source(source, filename="req_mgmt_shape.py")
    assert len(findings) == 1
    assert findings[0].gate == "_is_trusted_network"


def test_lint_does_not_flag_a_refusing_vouch():
    """`kag_graph_service/src/auth/middleware.py:165-211` — the SAFE consumer.

    Structurally identical to the unsafe shape up to the header read; the
    discriminator is a vouch that REFUSES. Flagging this would be a false
    positive on the one consumer that already closed the hole properly, which is
    the fastest way to get a check disabled.

    MUTATION: delete the ``_refuses_after_vouch`` guard in ``scan_source`` and
    this fails with a real assertion.
    """
    source = textwrap.dedent(
        """
        async def dispatch(request, call_next):
            client_host = request.client.host if request.client else None
            if _is_trusted_network(client_host):
                raw_tenant = request.headers.get("X-Tenant-Id", "").strip()
                tenant_id = raw_tenant
                if not await _authorized_onbehalf(request):
                    return JSONResponse(
                        status_code=403,
                        content={"error": "TENANT_TOKEN_REQUIRED"},
                    )
                request.state.tenant_id = tenant_id
        """
    )
    assert conformance.scan_source(source, filename="kag_graph_shape.py") == []


def test_a_labelling_only_vouch_is_still_flagged():
    """`hirag_service/src/auth/middleware.py:259-303`, INCLUDING its trailing
    ``return await call_next(request)``.

    ⚠️ REGRESSION GUARD. An earlier version of this test omitted that trailing
    return, and the earlier ``_refuses_after_vouch`` cleared any branch that
    called a vouch and contained a return ANYWHERE. The narrower fixture passed
    while the REAL hirag source was silently reported CLEAN — a false negative
    found only by running the check against the real corpus, never by the
    fixtures. The success-path return must stay in this fixture.

    hirag's own comment states the mitigation is not one: "Vouching can only
    WIDEN: `authorized_onbehalf` never raises and a failed vouch leaves the
    request accepted exactly as before."

    MUTATION: relax ``_refuses_after_vouch`` back to "any Return in the body" and
    this fails with a real assertion (``0 == 1``).
    """
    source = textwrap.dedent(
        """
        async def dispatch(request, call_next):
            client_host = request.client.host if request.client else None
            if _is_trusted_network(client_host):
                raw_tenant = request.headers.get("X-Tenant-Id", "").strip()
                tenant_id = raw_tenant or DEFAULT_TENANT_ID
                subject_id = request.headers.get("X-Subject-Id", "").strip()
                user = _default_user(tenant_id, tenant_name, subject_id)
                if raw_tenant:
                    tenant_source = (
                        SOURCE_VOUCHED_ONBEHALF
                        if await authorized_onbehalf(request)
                        else SOURCE_UNVOUCHED_HEADER
                    )
                else:
                    tenant_source = SOURCE_TRUSTED_NETWORK_DEFAULT
                request.state.tenant_id = tenant_id
                request.state.tenant_source = tenant_source
                with _bind_identity(tenant_id, tenant_source):
                    return await call_next(request)
            return _unauthorized("Missing license token")
        """
    )
    findings = conformance.scan_source(source, filename="hirag_shape.py")
    assert len(findings) == 1


def test_documented_blind_spot_injected_predicate_is_not_detected():
    """CHARACTERIZATION, not an endorsement — pins a stated limitation.

    ``graph_adapter_service`` injects the predicate as a parameter named
    ``is_trusted``, so the branch is invisible to a name-keyed rule. This is
    listed under "KNOWN BLIND SPOTS" in the module docstring. The test exists so
    the gap stays visible: if someone widens the rule to catch it, this test
    fails and forces the docstring to be corrected in the same change.
    """
    source = textwrap.dedent(
        """
        def resolve(request, is_trusted):
            if is_trusted(client_host):
                return request.headers.get("X-Tenant-Id")
        """
    )
    assert conformance.scan_source(source, filename="gas_shape.py") == []


# --------------------------------------------------------------------------- #
# Vacuity — a check that examined nothing must never report "clean".
# --------------------------------------------------------------------------- #
def test_scanning_no_paths_is_an_error():
    """MUTATION: return ``[]`` instead of raising and this fails."""
    with pytest.raises(conformance.VacuousScanError):
        conformance.assert_tokenless_identity_is_gated()


def test_scanning_a_directory_with_no_python_is_an_error(tmp_path):
    (tmp_path / "README.md").write_text("no python here")
    with pytest.raises(conformance.VacuousScanError, match="zero .py files"):
        conformance.assert_tokenless_identity_is_gated(tmp_path)


def test_scanning_a_missing_path_is_an_error(tmp_path):
    with pytest.raises(conformance.VacuousScanError, match="does not exist"):
        conformance.assert_tokenless_identity_is_gated(tmp_path / "nope")


def test_an_unparseable_file_is_an_error_not_a_clean_file(tmp_path):
    """A file the checker cannot parse must NOT be counted as conformant."""
    (tmp_path / "broken.py").write_text("def (:::\n")
    with pytest.raises(conformance.VacuousScanError, match="could not be parsed"):
        conformance.assert_tokenless_identity_is_gated(tmp_path)


def test_a_nul_byte_cannot_hide_a_file_from_the_scan(tmp_path):
    """A single raw NUL hides a whole file from grep/ripgrep — but not from AST.

    ``ast.parse`` raises ``ValueError`` on embedded NULs. Swallowing that would
    let an attacker (or an editor accident) make an exploitable file invisible to
    this check while it still imports and runs. It must be an error.
    """
    (tmp_path / "hidden.py").write_bytes(UNSAFE_CONSUMER_SOURCE.encode() + b"\x00")
    with pytest.raises(conformance.VacuousScanError, match="could not be parsed"):
        conformance.assert_tokenless_identity_is_gated(tmp_path)


def test_kag_common_itself_is_conformant():
    """Dogfood: this library must not contain the shape it lints for.

    Also proves the scan is non-vacuous against a real tree — it resolves files
    and parses every one of them, or it raises.
    """
    conformance.assert_tokenless_identity_is_gated("src/kag_common")


# --------------------------------------------------------------------------- #
# Layer 3 — licence-token CARRIAGE (R4 / R1 / R2). The sibling lint: layer 2
# asks "may this peer name a tenant with no token", this one asks "did the
# caller actually SEND one".
# --------------------------------------------------------------------------- #
def _line_of(source: str, needle: str) -> int:
    """1-based line number of the ONE line in ``source`` containing ``needle``.

    Anchoring on the text rather than a hard-coded integer means a fixture edit
    can never silently point an assertion at the wrong statement — and the
    uniqueness assert fails loudly if the anchor stops being unique.
    """
    hits = [n for n, line in enumerate(source.splitlines(), start=1) if needle in line]
    assert len(hits) == 1, f"{needle!r} must appear on exactly one line; found {hits}"
    return hits[0]


# R4 — a hand-rolled headers LITERAL that asserts a tenant with no service
# identity behind it. A bare `X-Tenant-Id` is an assertion; the downstream
# honours it only when an allowlisted `Authorization: Bearer <service token>`
# vouches for it.
#
# ⚠️ SCOPE, corrected. This is NOT the `kag/src/services/proxy.py` bug that
# prompted the lane. That one was an omission from a vouch DESTINATION TUPLE
# (the orchestrator was not in the list), and the proxy builds its headers by
# subscript assignment — neither of which R4 can see. R4 is the narrower
# sibling shape, and a clean R4 run says nothing about destination coverage.
UNVOUCHED_TENANT_SOURCE = textwrap.dedent(
    """
    async def forward(client, url, tenant_id, payload):
        headers = {
            "Content-Type": "application/json",
            "X-Tenant-Id": tenant_id,
        }
        return await client.post(url, json=payload, headers=headers)
    """
)

# Same call, with the vouch the proxy omitted.
VOUCHED_TENANT_SOURCE = UNVOUCHED_TENANT_SOURCE.replace(
    '"X-Tenant-Id": tenant_id,',
    '"X-Tenant-Id": tenant_id,\n        "Authorization": f"Bearer {service_token}",',
)

# Same call, credential in the tenant slot itself (the non-on-behalf ladder).
BEARER_TENANT_SOURCE = UNVOUCHED_TENANT_SOURCE.replace(
    '"X-Tenant-Id": tenant_id,', '"X-Tenant-Id": f"Bearer {service_token}",'
)


def test_carriage_flags_a_bare_tenant_with_no_authorization():
    """POSITIVE CONTROL for R4 — a hand-rolled headers literal with no vouch.

    NOT the `kag` proxy shape (see the note above the fixture): that bug was a
    destination-tuple omission over subscript-built headers, which R4 cannot see.

    MUTATION: make ``_r4_offence`` return ``None`` for a bare tenant (i.e. treat
    every headers dict as vouched) and this fails with a real assertion
    (``0 == 1``) — verified, not asserted. The opposite mutation, dropping the
    ``_AUTHORIZATION_HEADERS`` clause so every headers dict is a finding, is
    killed by ``test_carriage_passes_a_credentialled_call`` instead.
    """
    findings = conformance.scan_carriage_source(UNVOUCHED_TENANT_SOURCE, filename="proxy.py")
    assert len(findings) == 1
    (finding,) = findings
    assert finding.rule == "R4"
    assert finding.filename == "proxy.py"
    assert finding.lineno == _line_of(UNVOUCHED_TENANT_SOURCE, "headers = {")
    assert "x-tenant-id" in finding.symbol
    # The message must name the fix, not just the sin.
    assert "outbound_headers" in str(finding)


def test_carriage_raises_on_the_unvouched_shape(tmp_path):
    """The assertion helper — what a consumer actually wires in — must FAIL."""
    (tmp_path / "proxy.py").write_text(UNVOUCHED_TENANT_SOURCE)
    with pytest.raises(conformance.LicenceCarriageError) as excinfo:
        conformance.assert_licence_token_carriage(tmp_path)
    assert "proxy.py" in str(excinfo.value)
    assert "R4" in str(excinfo.value)


@pytest.mark.parametrize(
    ("label", "source"),
    [("vouched by Authorization", VOUCHED_TENANT_SOURCE), ("Bearer tenant", BEARER_TENANT_SOURCE)],
)
def test_carriage_passes_a_credentialled_call(label, source):
    """NEGATIVE CONTROL for R4 — without it, a constant `fail` passes the above."""
    assert conformance.scan_carriage_source(source, filename="proxy.py") == [], label


def test_carriage_flags_a_bare_tenant_built_with_dict():
    """`dict(...)` is the same shape spelled differently and equally exploitable."""
    source = textwrap.dedent(
        """
        def build(tenant_id):
            return dict(**{"X-Tenant-Id": tenant_id}, **{"Content-Type": "application/json"})
        """
    )
    findings = conformance.scan_carriage_source(source, filename="build.py")
    assert len(findings) == 1
    assert findings[0].rule == "R4"


def test_carriage_does_not_double_report_an_absorbed_literal():
    """A ``**{...}`` inside a compliant ``dict(...)`` must not be judged alone.

    MUTATION: delete the ``absorbed_ids`` bookkeeping in ``_scan_carriage_tree``
    and this fails — the inner literal is re-evaluated without the sibling
    ``Authorization`` and reports a false positive on a correct call site.
    """
    source = textwrap.dedent(
        """
        def build(tenant_id, service_token):
            return dict(
                **{"X-Tenant-Id": tenant_id},
                **{"Authorization": f"Bearer {service_token}"},
            )
        """
    )
    assert conformance.scan_carriage_source(source, filename="build.py") == []


def test_carriage_does_not_flag_a_bare_effective_tenant():
    """`X-Effective-Tenant-Id` is bare BY DESIGN — the credential is its sibling.

    REGRESSION GUARD. Keying R4 on the module's existing ``_TENANT_HEADERS``
    (which includes the effective-tenant and bare `tenant-id` spellings) would
    flag every correct delegating call in the fleet — see
    ``kag_common.auth.apply_effective_tenant``. Worse, ``_TENANT_HEADERS`` is a
    frozenset, so the match order is not stable: the false positive would appear
    and disappear between runs.
    """
    source = textwrap.dedent(
        """
        def build(effective_tenant, service_token):
            return {
                "X-Tenant-Id": f"Bearer {service_token}",
                "X-Effective-Tenant-Id": effective_tenant,
            }
        """
    )
    assert conformance.scan_carriage_source(source, filename="delegate.py") == []


def test_documented_blind_spot_a_spread_headers_dict_is_not_read():
    """CHARACTERIZATION, not an endorsement — pins a stated limitation.

    A ``**base`` spread hides whatever it carries, so the dict is SKIPPED rather
    than flagged: the missing ``Authorization`` may well be in the part that
    cannot be seen, and a false positive on a correct call site is the fastest
    way to get a lint disabled. If someone teaches the check to resolve spreads,
    this test fails and forces the docstring to be corrected in the same change.
    """
    source = textwrap.dedent(
        """
        def build(base, tenant_id):
            return {**base, "X-Tenant-Id": tenant_id}
        """
    )
    assert conformance.scan_carriage_source(source, filename="spread.py") == []


def test_carriage_flags_a_licence_introspected_from_authorization():
    """POSITIVE CONTROL for R1 — licences never travel in `Authorization`.

    Two hops from header to call, which is how it is actually written. A rule
    that only looked for the header literal in the call's own arguments reports
    this file clean.

    MUTATION: delete the ``names & tainted`` clause in
    ``_authorization_tainted_names`` (making the taint non-transitive) and this
    fails with a real assertion (``0 == 1``) — verified, not asserted.

    ⚠️ What this does NOT pin: collapsing that function's fixpoint loop to a
    SINGLE pass leaves this test green, because ``ast.walk`` happens to reach
    ``auth_header`` before ``token`` here. The loop is defensive against walk
    order (BFS depth, not source order) and no fixture exercises it; do not read
    this test as proof that it is needed.
    """
    source = textwrap.dedent(
        """
        async def authenticate(request):
            auth_header = request.headers.get("Authorization", "")
            token = auth_header.removeprefix("Bearer ").strip()
            claims = await introspect_license(token)
            return claims
        """
    )
    findings = conformance.scan_carriage_source(source, filename="middleware.py")
    assert len(findings) == 1
    (finding,) = findings
    assert finding.rule == "R1"
    assert finding.symbol == "introspect_license"
    assert finding.lineno == _line_of(source, "await introspect_license(token)")
    assert "extract_license_token" in str(finding)


def test_carriage_passes_a_licence_taken_from_the_tenant_header():
    """NEGATIVE CONTROL for R1 — the correct source is `X-Tenant-Id: Bearer`."""
    source = textwrap.dedent(
        """
        async def authenticate(request):
            token = extract_license_token(request)
            claims = await introspect_license(token)
            return claims
        """
    )
    assert conformance.scan_carriage_source(source, filename="middleware.py") == []


def test_carriage_flags_a_header_subject_overwriting_the_introspected_one():
    """POSITIVE CONTROL for R2 — a caller-supplied subject renames the principal.

    MUTATION: drop ``"x-subject-id"`` from ``_SUBJECT_HEADERS`` and this fails
    with a real assertion (``0 == 1``) — verified, not asserted. Dropping the
    ``authenticated_subject_line is not None`` precondition instead (so ANY
    header-sourced ``subject_id`` is flagged) leaves this test green and is
    killed by ``test_carriage_ignores_a_header_subject_with_no_authenticated_one``
    — the two directions need two tests.
    """
    source = textwrap.dedent(
        """
        async def authenticate(request, token):
            claims = await introspect_license(token)
            tenant_id = claims.get("tenant_id")
            subject_id = claims.get("sub")
            subject_id = request.headers.get("X-Subject-Id", "").strip()
            return tenant_id, subject_id
        """
    )
    findings = conformance.scan_carriage_source(source, filename="middleware.py")
    assert len(findings) == 1
    (finding,) = findings
    assert finding.rule == "R2"
    assert finding.symbol == "subject_id"
    assert finding.lineno == _line_of(source, 'request.headers.get("X-Subject-Id"')
    # It must name WHICH binding it clobbered, or the report is unactionable.
    assert str(_line_of(source, 'claims.get("sub")')) in str(finding)


def test_carriage_flags_an_overwrite_one_hop_from_the_header():
    """The same defect with a temp var between the header and the rebinding.

    MUTATION: delete the ``header_sourced`` propagation in ``_r2_findings`` and
    this fails with a real assertion (``0 == 1``) while the direct shape above
    still passes — which is exactly the silent half-pass to avoid.
    """
    source = textwrap.dedent(
        """
        async def authenticate(request, token):
            claims = await introspect_license(token)
            subject_id = claims.get("sub")
            fwd_subject = request.headers.get("X-Subject-Id", "").strip()
            subject_id = fwd_subject
            return subject_id
        """
    )
    findings = conformance.scan_carriage_source(source, filename="middleware.py")
    assert len(findings) == 1
    assert findings[0].rule == "R2"


def test_carriage_passes_the_sanctioned_forwarded_subject_fallback():
    """NEGATIVE CONTROL for R2 — `fwd_subject or subject_id` is CORRECT.

    This is what ``kag_common.auth.apply_effective_tenant`` does: the header is a
    fallback for when introspection produced no subject, and the authenticated
    value can still win. Flagging it would be a false positive on the one
    reference implementation, which is how a check gets disabled.
    """
    source = textwrap.dedent(
        """
        async def authenticate(request, token):
            claims = await introspect_license(token)
            subject_id = claims.get("sub")
            fwd_subject = request.headers.get("X-Subject-Id", "").strip()
            subject_id = fwd_subject or subject_id
            return subject_id
        """
    )
    assert conformance.scan_carriage_source(source, filename="middleware.py") == []


def test_carriage_ignores_a_header_subject_with_no_authenticated_one():
    """A service that only ever has the forwarded subject is not overwriting it.

    MUTATION: drop the ``authenticated_subject_line is not None`` precondition in
    ``_r2_findings`` and this fails — R2 becomes "reads X-Subject-Id", which is
    every audit path in the fleet.
    """
    source = textwrap.dedent(
        """
        def audit(request):
            subject_id = request.headers.get("X-Subject-Id", "").strip()
            return subject_id
        """
    )
    assert conformance.scan_carriage_source(source, filename="audit.py") == []


def test_documented_blind_spot_a_cross_function_subject_overwrite():
    """CHARACTERIZATION, not an endorsement — pins a stated limitation.

    The introspection and the overwrite live in DIFFERENT functions, so nothing
    links them and the check reports clean. Listed in ``_r2_findings``'s
    docstring as the realistic miss. If someone widens the rule, this fails and
    forces the docstring to be corrected in the same change.
    """
    source = textwrap.dedent(
        """
        def _apply(identity, request):
            identity.subject_id = request.headers.get("X-Subject-Id", "").strip()


        async def authenticate(request, token):
            claims = await introspect_license(token)
            identity = Identity(subject_id=claims.get("sub"))
            _apply(identity, request)
            return identity
        """
    )
    assert conformance.scan_carriage_source(source, filename="split.py") == []


# --------------------------------------------------------------------------- #
# Carriage vacuity — a check that examined nothing must never report "clean".
# --------------------------------------------------------------------------- #
def test_carriage_scanning_no_paths_is_an_error():
    with pytest.raises(conformance.VacuousScanError):
        conformance.assert_licence_token_carriage()


def test_carriage_scanning_an_empty_directory_is_an_error(tmp_path):
    """MUTATION: return ``[]`` instead of raising and this fails."""
    with pytest.raises(conformance.VacuousScanError, match="zero .py files"):
        conformance.assert_licence_token_carriage(tmp_path)


def test_carriage_scanning_zero_candidate_nodes_is_an_error(tmp_path):
    """Files resolved and parsed, but not one dict / call / assignment in them.

    The floor is on what was EXAMINED, not on what was found: a run that walked
    real files but reached none of the node kinds these rules key on has proved
    nothing, and must say so rather than going green.

    MUTATION: delete the ``candidates == 0`` guard in ``scan_carriage_paths``
    and this fails.
    """
    (tmp_path / "empty.py").write_text('"""Docstring only — no code."""\n')
    with pytest.raises(conformance.VacuousScanError, match="zero candidate nodes"):
        conformance.assert_licence_token_carriage(tmp_path)


def test_carriage_an_unparseable_file_is_an_error_not_a_clean_file(tmp_path):
    (tmp_path / "broken.py").write_text("def (:::\n")
    with pytest.raises(conformance.VacuousScanError, match="could not be parsed"):
        conformance.assert_licence_token_carriage(tmp_path)


def test_carriage_a_nul_byte_cannot_hide_a_file_from_the_scan(tmp_path):
    """A single raw NUL hides a whole file from grep/ripgrep — but not from AST."""
    (tmp_path / "hidden.py").write_bytes(UNVOUCHED_TENANT_SOURCE.encode() + b"\x00")
    with pytest.raises(conformance.VacuousScanError, match="could not be parsed"):
        conformance.assert_licence_token_carriage(tmp_path)


def test_kag_common_itself_carries_licences_correctly():
    """Dogfood: this library must not contain the shapes it lints for.

    Also proves the carriage scan is non-vacuous against a real tree — it
    resolves files, parses every one, and reaches real candidate nodes, or it
    raises.
    """
    conformance.assert_licence_token_carriage("src/kag_common")


# --------------------------------------------------------------------------- #
# R5/R8 — the on-behalf-of allowlist cross-check. Separate function, REQUIRED
# manifests root: it cannot be called where the manifests do not exist, so it
# can never "pass" by finding nothing to contradict it.
# --------------------------------------------------------------------------- #
ONBEHALF_READER_SOURCE = textwrap.dedent(
    """
    import os

    DISCOVERY = os.getenv("DISCOVERY_ENGINE_ONBEHALF_SUBJECTS", "")
    SCIENTIFIC = os.getenv("SCIENTIFIC_PROCESSOR_ONBEHALF_SUBJECTS", "")
    KAG = os.getenv("KAG_ONBEHALF_SUBJECTS", "")
    """
)


def _write_manifest(root, name: str, env_block: str):
    """Write a minimal Deployment whose one container carries ``env_block``.

    ``env_block`` is dedented and re-indented explicitly rather than interpolated
    into the template — an f-string placeholder indents only the FIRST line of a
    multi-line value, which silently produces a manifest whose second line sits
    at the wrong depth and a parser result that looks like a real finding.
    """
    entries = textwrap.indent(textwrap.dedent(env_block).strip("\n"), " " * 12)
    body = textwrap.dedent(
        f"""\
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: {name}
        spec:
          template:
            spec:
              containers:
                - name: {name}
                  image: registry.example:5000/{name}:latest
                  env:
        """
    )
    directory = root / name
    directory.mkdir(parents=True, exist_ok=True)
    manifest = directory / "deployment.yaml"
    manifest.write_text(body + entries + "\n")
    return manifest


def _onbehalf_tree(tmp_path, env_block: str):
    code = tmp_path / "code"
    code.mkdir()
    (code / "settings.py").write_text(ONBEHALF_READER_SOURCE)
    manifests = tmp_path / "manifests"
    manifests.mkdir()
    _write_manifest(manifests, "kag", env_block)
    return code, manifests


def test_onbehalf_allowlist_flags_a_var_set_in_no_manifest(tmp_path):
    """POSITIVE CONTROL — the two REAL findings this check was built to catch.

    ``DISCOVERY_ENGINE_ONBEHALF_SUBJECTS`` and
    ``SCIENTIFIC_PROCESSOR_ONBEHALF_SUBJECTS`` are read in code and set in NO
    manifest, so both allowlists are empty at runtime: the receiver vouches for
    nobody and refuses every on-behalf-of call it is supposed to accept.

    MUTATION: treat a name absent from every manifest as satisfied and this
    fails — ``OnBehalfAllowlistError`` is never raised at all.
    """
    code, manifests = _onbehalf_tree(
        tmp_path,
        """
        - name: KAG_ONBEHALF_SUBJECTS
          value: "svc-kag,svc-orchestrator"
        """,
    )
    with pytest.raises(conformance.OnBehalfAllowlistError) as excinfo:
        conformance.assert_onbehalf_allowlists_are_set(code, manifests)
    message = str(excinfo.value)
    assert "DISCOVERY_ENGINE_ONBEHALF_SUBJECTS" in message
    assert "SCIENTIFIC_PROCESSOR_ONBEHALF_SUBJECTS" in message
    # The one that IS set must not be reported, or the check is a constant fail.
    assert "`KAG_ONBEHALF_SUBJECTS`" not in message


def test_onbehalf_allowlist_passes_when_every_var_is_set(tmp_path):
    """NEGATIVE CONTROL — without it, a constant `fail` passes the test above."""
    code, manifests = _onbehalf_tree(
        tmp_path,
        """
        - name: KAG_ONBEHALF_SUBJECTS
          value: "svc-kag"
        - name: DISCOVERY_ENGINE_ONBEHALF_SUBJECTS
          value: "svc-discovery"
        - name: SCIENTIFIC_PROCESSOR_ONBEHALF_SUBJECTS
          value: 'svc-sci'
        """,
    )
    conformance.assert_onbehalf_allowlists_are_set(code, manifests)


@pytest.mark.parametrize(
    ("label", "entry"),
    [
        ("empty string", '- name: KAG_ONBEHALF_SUBJECTS\n  value: ""\n'),
        (
            "secret ref",
            "- name: KAG_ONBEHALF_SUBJECTS\n"
            "  valueFrom:\n"
            "    secretKeyRef:\n"
            "      name: kag\n"
            "      key: subjects\n",
        ),
    ],
)
def test_onbehalf_allowlist_treats_an_unreadable_value_as_unset(tmp_path, label, entry):
    """``value: ""`` is an empty allowlist; a ``valueFrom:`` cannot be read.

    Calling either "set" would be the vacuous pass this module exists to
    prevent — the check cannot open a Secret, so it must not claim the value is
    non-empty.
    """
    code = tmp_path / "code"
    code.mkdir()
    (code / "settings.py").write_text('import os\n\nKAG = os.getenv("KAG_ONBEHALF_SUBJECTS", "")\n')
    manifests = tmp_path / "manifests"
    manifests.mkdir()
    _write_manifest(manifests, "kag", entry)
    with pytest.raises(conformance.OnBehalfAllowlistError, match="KAG_ONBEHALF_SUBJECTS"):
        conformance.assert_onbehalf_allowlists_are_set(code, manifests)


def test_onbehalf_allowlist_does_not_steal_a_value_from_the_container_name(tmp_path):
    """A container's ``- name:`` must not absorb its first env var's ``value:``.

    Otherwise a container literally named after an allowlist would be reported
    set by the value of an unrelated variable.
    """
    code = tmp_path / "code"
    code.mkdir()
    (code / "settings.py").write_text('import os\n\nKAG = os.getenv("KAG_ONBEHALF_SUBJECTS", "")\n')
    manifests = tmp_path / "manifests"
    manifests.mkdir()
    manifest = _write_manifest(
        manifests, "kag", "- name: SOMETHING_ELSE\n  value: not-an-allowlist\n"
    )
    parsed = conformance._manifest_env_values(manifest)
    assert parsed["SOMETHING_ELSE"] == "not-an-allowlist"
    assert parsed["kag"] == ""  # the container name, not its child's value
    with pytest.raises(conformance.OnBehalfAllowlistError, match="KAG_ONBEHALF_SUBJECTS"):
        conformance.assert_onbehalf_allowlists_are_set(code, manifests)


# --------------------------------------------------------------------------- #
# The SECOND read shape. `discovery_engine` writes `os.getenv("FOO_...")`;
# `kag/src/core/config.py:453` declares a pydantic-settings FIELD. Matching only
# the first reported `kag/src` as "zero reads" — caught by the vacuity guard,
# which is the only reason the false negative surfaced instead of going green.
# --------------------------------------------------------------------------- #
SETTINGS_FIELD_SOURCE = textwrap.dedent(
    """
    from pydantic import Field
    from pydantic_settings import BaseSettings


    class Settings(BaseSettings):
        KAG_ONBEHALF_SUBJECTS: str = Field(default="")
    """
)

# Both shapes in one tree — the regression anchor for the widening.
BOTH_READ_SHAPES_SOURCE = textwrap.dedent(
    """
    import os

    from pydantic import Field
    from pydantic_settings import BaseSettings

    DISCOVERY = os.getenv("DISCOVERY_ENGINE_ONBEHALF_SUBJECTS", "")


    class Settings(BaseSettings):
        KAG_ONBEHALF_SUBJECTS: str = Field(default="")
    """
)


def _onbehalf_case(tmp_path, source: str, env_block: str):
    """Build a ``(code_root, manifests_root)`` pair from one source + env block."""
    code = tmp_path / "code"
    code.mkdir()
    (code / "config.py").write_text(source)
    manifests = tmp_path / "manifests"
    manifests.mkdir()
    _write_manifest(manifests, "kag", env_block)
    return code, manifests


def test_onbehalf_allowlist_reads_a_pydantic_settings_field(tmp_path):
    """POSITIVE CONTROL for the pydantic-settings shape — the `kag` false negative.

    Before the widening this raised ``VacuousScanError`` ("zero reads") on a
    codebase that reads exactly one allowlist. Most FastAPI services on this
    fleet are pydantic-settings, so the check was blind to the majority of
    consumers — and blind in the direction that reports success.

    MUTATION: drop the ``ast.Assign``/``ast.AnnAssign`` branch from
    ``_onbehalf_env_reads`` and this fails — with ``VacuousScanError``, not with
    a clean pass, which is the one thing the vacuity floor buys.
    """
    code, manifests = _onbehalf_case(
        tmp_path,
        SETTINGS_FIELD_SOURCE,
        '- name: SOMETHING_ELSE\n  value: "unrelated"\n',
    )
    with pytest.raises(conformance.OnBehalfAllowlistError, match="KAG_ONBEHALF_SUBJECTS"):
        conformance.assert_onbehalf_allowlists_are_set(code, manifests)


def test_onbehalf_allowlist_passes_a_pydantic_settings_field_that_is_set(tmp_path):
    """NEGATIVE CONTROL — without it, "always report the field" passes the above."""
    code, manifests = _onbehalf_case(
        tmp_path,
        SETTINGS_FIELD_SOURCE,
        '- name: KAG_ONBEHALF_SUBJECTS\n  value: "svc-kag,svc-orchestrator"\n',
    )
    conformance.assert_onbehalf_allowlists_are_set(code, manifests)


def test_onbehalf_allowlist_still_reads_the_getenv_shape_after_widening(tmp_path):
    """REGRESSION ANCHOR — the widening must ADD a shape, not trade one for it.

    Both shapes live in one tree and neither is set, so both must be reported.
    Asserting only the new one would let a rewrite that broke ``os.getenv``
    detection (and with it discovery-engine and scientific_processor) go green.
    """
    code, manifests = _onbehalf_case(
        tmp_path,
        BOTH_READ_SHAPES_SOURCE,
        '- name: SOMETHING_ELSE\n  value: "unrelated"\n',
    )
    with pytest.raises(conformance.OnBehalfAllowlistError) as excinfo:
        conformance.assert_onbehalf_allowlists_are_set(code, manifests)
    message = str(excinfo.value)
    assert "DISCOVERY_ENGINE_ONBEHALF_SUBJECTS" in message  # the os.getenv shape
    assert "KAG_ONBEHALF_SUBJECTS" in message  # the pydantic-settings shape


def test_documented_blind_spot_a_validation_alias_is_attributed_to_the_field_name(tmp_path):
    """CHARACTERIZATION, not an endorsement — pins a stated limitation.

    The field is READ from ``KAG_VOUCH_SUBJECTS`` (its ``validation_alias``) and
    the manifest sets exactly that, correctly. But this check matches on the
    IDENTIFIER, so it reports ``KAG_ONBEHALF_SUBJECTS`` missing — a FALSE
    POSITIVE against a correctly-configured service, and it never checks the var
    the process actually reads.

    There is a measured incident on this fleet of a ``validation_alias``
    silently discarding a field name. Resolving the alias is welcome; until then
    a finding on an aliased field is a name to verify by hand, not a verdict.
    If someone teaches ``_onbehalf_env_reads`` to resolve aliases, this test
    fails and forces its docstring to be corrected in the same change.
    """
    source = textwrap.dedent(
        """
        from pydantic import Field
        from pydantic_settings import BaseSettings


        class Settings(BaseSettings):
            KAG_ONBEHALF_SUBJECTS: str = Field(
                default="", validation_alias="KAG_VOUCH_SUBJECTS"
            )
        """
    )
    code, manifests = _onbehalf_case(
        tmp_path,
        source,
        '- name: KAG_VOUCH_SUBJECTS\n  value: "svc-kag"\n',
    )
    with pytest.raises(conformance.OnBehalfAllowlistError, match="KAG_ONBEHALF_SUBJECTS"):
        conformance.assert_onbehalf_allowlists_are_set(code, manifests)


# --------------------------------------------------------------------------- #
# Allowlist vacuity — three separate ways this cross-check could examine
# nothing, all of which must raise rather than go green.
# --------------------------------------------------------------------------- #
def test_onbehalf_allowlist_with_no_python_is_an_error(tmp_path):
    code = tmp_path / "code"
    code.mkdir()
    (code / "README.md").write_text("no python here")
    manifests = tmp_path / "manifests"
    manifests.mkdir()
    _write_manifest(manifests, "kag", '- name: KAG_ONBEHALF_SUBJECTS\n  value: "svc-kag"\n')
    with pytest.raises(conformance.VacuousScanError, match="zero .py files"):
        conformance.assert_onbehalf_allowlists_are_set(code, manifests)


def test_onbehalf_allowlist_with_no_reads_is_an_error(tmp_path):
    """Code that names no allowlist means the cross-check verified nothing.

    MUTATION: return early instead of raising and this fails.
    """
    code = tmp_path / "code"
    code.mkdir()
    (code / "settings.py").write_text('import os\n\nX = os.getenv("SOMETHING_ELSE", "")\n')
    manifests = tmp_path / "manifests"
    manifests.mkdir()
    _write_manifest(manifests, "kag", '- name: KAG_ONBEHALF_SUBJECTS\n  value: "svc-kag"\n')
    with pytest.raises(conformance.VacuousScanError, match="_ONBEHALF_SUBJECTS` reads"):
        conformance.assert_onbehalf_allowlists_are_set(code, manifests)


def test_onbehalf_allowlist_with_no_manifests_is_an_error(tmp_path):
    """The failure mode this function's required argument exists to prevent.

    Pointed at a tree with no Deployments, it must NOT report every allowlist
    satisfied (nor every one missing) — it must say it could not check.
    """
    code = tmp_path / "code"
    code.mkdir()
    (code / "settings.py").write_text(ONBEHALF_READER_SOURCE)
    manifests = tmp_path / "manifests"
    manifests.mkdir()
    (manifests / "kustomization.yaml").write_text("resources: []\n")
    with pytest.raises(conformance.VacuousScanError, match="zero deployment.yaml"):
        conformance.assert_onbehalf_allowlists_are_set(code, manifests)


def test_onbehalf_allowlist_with_a_missing_manifests_root_is_an_error(tmp_path):
    code = tmp_path / "code"
    code.mkdir()
    (code / "settings.py").write_text(ONBEHALF_READER_SOURCE)
    with pytest.raises(conformance.VacuousScanError, match="does not exist"):
        conformance.assert_onbehalf_allowlists_are_set(code, tmp_path / "nope")
