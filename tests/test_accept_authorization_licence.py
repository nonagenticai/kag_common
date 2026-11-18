"""0.37.0 — opt-in licence in ``Authorization`` + plain ``X-Tenant-Id`` binding.

Behaviour table mirrors requirements_management #222 / #223
(``src/auth/middleware.py``: ``_authorization_bearer``, ``_plain_tenant_header``,
``_require_own_tenant``, ``_principal_from_license``).
"""

from __future__ import annotations

import warnings

import pytest
from starlette.requests import Request

from kag_common import auth
from kag_common.auth import conformance

LICENCE_TENANT = "11111111-1111-1111-1111-111111111111"
OTHER_TENANT = "22222222-2222-2222-2222-222222222222"
SA_SUBJECT = "svc-fr"
ENV = auth.ACCEPT_AUTHORIZATION_LICENCE_ENV


def _req(headers: dict[str, str]) -> Request:
    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    return Request({"type": "http", "headers": raw})


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv(ENV, raising=False)
    monkeypatch.delenv("AUTH_DELEGATING_SUBJECTS", raising=False)


async def _resolver(value: str) -> str:
    """Names resolve to uuids; uuids resolve to themselves (lower-cased)."""
    names = {"acme": LICENCE_TENANT, "other": OTHER_TENANT}
    return names.get(value.strip().lower(), value.strip().lower())


# --------------------------------------------------------------------------- #
# Carrier extraction
# --------------------------------------------------------------------------- #
def test_gateway_shape_yields_licence_from_authorization():
    req = _req({"Authorization": "Bearer lic-abc", "X-Tenant-Id": LICENCE_TENANT})
    got = auth.extract_license_token_with_source(req, accept_authorization=True)
    assert got == ("lic-abc", "authorization")


def test_x_tenant_id_bearer_keeps_precedence():
    req = _req({"Authorization": "Bearer jwt-xyz", "X-Tenant-Id": "Bearer lic-abc"})
    got = auth.extract_license_token_with_source(req, accept_authorization=True)
    assert got == ("lic-abc", "x_tenant_id")


def test_lowercase_scheme_is_accepted():
    req = _req({"Authorization": "bearer lic-abc"})
    assert auth.extract_license_token_with_source(req, accept_authorization=True) == (
        "lic-abc",
        "authorization",
    )


@pytest.mark.parametrize("value", ["Bearer ", "Bearer    ", "Bearer", "Basic dXNlcg==", ""])
def test_empty_or_non_bearer_authorization_is_none(value):
    req = _req({"Authorization": value})
    assert auth.extract_license_token_with_source(req, accept_authorization=True) == (None, None)


def test_flag_off_ignores_authorization_exactly_as_0_36():
    req = _req({"Authorization": "Bearer lic-abc", "X-Tenant-Id": LICENCE_TENANT})
    assert auth.extract_license_token(req) is None
    assert auth.extract_license_token_with_source(req) == (None, None)
    assert auth.extract_license_token_with_source(req, accept_authorization=False) == (None, None)


def test_flag_off_still_returns_x_tenant_id_bearer():
    req = _req({"X-Tenant-Id": "Bearer lic-abc"})
    assert auth.extract_license_token_with_source(req) == ("lic-abc", "x_tenant_id")


def test_env_flag_exact_true_enables(monkeypatch):
    monkeypatch.setenv(ENV, "true")
    req = _req({"Authorization": "Bearer lic-abc"})
    assert auth.extract_license_token_with_source(req) == ("lic-abc", "authorization")


@pytest.mark.parametrize("raw", ["True", "TRUE", "1", "yes", "on", " true", "false", ""])
def test_env_flag_anything_but_exact_true_is_off(monkeypatch, raw):
    monkeypatch.setenv(ENV, raw)
    req = _req({"Authorization": "Bearer lic-abc"})
    assert auth.extract_license_token_with_source(req) == (None, None)


def test_explicit_false_beats_env_true(monkeypatch):
    monkeypatch.setenv(ENV, "true")
    req = _req({"Authorization": "Bearer lic-abc"})
    assert auth.extract_license_token_with_source(req, accept_authorization=False) == (None, None)


def test_extract_license_token_unchanged_never_reads_authorization(monkeypatch):
    monkeypatch.setenv(ENV, "true")
    assert auth.extract_license_token(_req({"Authorization": "Bearer lic-abc"})) is None


# --------------------------------------------------------------------------- #
# Plain tenant header
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (LICENCE_TENANT, LICENCE_TENANT),
        (f"  {LICENCE_TENANT}  ", LICENCE_TENANT),
        ("bearerco", "bearerco"),
        ("Bearer", ""),
        ("bearer", ""),
        ("Bearer lic-abc", ""),
        ("", ""),
    ],
)
def test_plain_tenant_header(value, expected):
    assert auth.plain_tenant_header(_req({"X-Tenant-Id": value})) == expected


def test_plain_tenant_header_absent():
    assert auth.plain_tenant_header(_req({})) == ""


# --------------------------------------------------------------------------- #
# Binding (non-delegating)
# --------------------------------------------------------------------------- #
async def _bind(headers, *, source, subject="user-1", resolve=_resolver):
    return await auth.bind_plain_tenant(
        _req(headers),
        credential_tenant=LICENCE_TENANT,
        subject_id=subject,
        source=source,
        resolve=resolve,
    )


async def test_gateway_plain_header_equal_to_licence_tenant_binds():
    assert await _bind({"X-Tenant-Id": LICENCE_TENANT}, source="authorization") == ""


async def test_plain_header_other_tenant_is_mismatch():
    with pytest.raises(auth.LicenceTenantMismatch):
        await _bind({"X-Tenant-Id": OTHER_TENANT}, source="authorization")


async def test_plain_header_case_differs_is_same_tenant():
    assert await _bind({"X-Tenant-Id": LICENCE_TENANT.upper()}, source="authorization") == ""


async def test_plain_header_name_resolving_to_own_tenant_binds():
    assert await _bind({"X-Tenant-Id": "acme"}, source="authorization") == ""


async def test_plain_header_name_resolving_elsewhere_is_mismatch():
    with pytest.raises(auth.LicenceTenantMismatch):
        await _bind({"X-Tenant-Id": "other"}, source="authorization")


async def test_bearerco_is_a_tenant_claim_and_mismatches():
    with pytest.raises(auth.LicenceTenantMismatch):
        await _bind({"X-Tenant-Id": "bearerco"}, source="authorization")


async def test_no_resolver_textual_mismatch_fails_closed():
    with pytest.raises(auth.LicenceTenantMismatch):
        await _bind({"X-Tenant-Id": "acme"}, source="authorization", resolve=None)


async def test_effective_header_other_tenant_mismatch_for_any_source():
    for source in ("authorization", "x_tenant_id"):
        with pytest.raises(auth.LicenceTenantMismatch):
            await _bind({"X-Effective-Tenant-Id": OTHER_TENANT}, source=source)


async def test_effective_header_equal_tenant_is_noop():
    got = await _bind({"X-Effective-Tenant-Id": LICENCE_TENANT}, source="x_tenant_id")
    assert got == LICENCE_TENANT  # apply_effective_tenant treats equal as a no-op


async def test_plain_header_ignored_when_licence_came_from_x_tenant_id():
    # With the licence in X-Tenant-Id there is no plain header; a stray value is moot.
    req_headers = {"X-Tenant-Id": "Bearer lic-abc"}
    assert await _bind(req_headers, source="x_tenant_id") == ""


async def test_pure_helper_ignores_plain_unless_source_is_authorization():
    got = await auth.bind_licence_tenant_claims(
        credential_tenant=LICENCE_TENANT,
        subject_id="user-1",
        source="x_tenant_id",
        plain_tenant=OTHER_TENANT,
        effective_tenant="",
    )
    assert got == ""


async def test_resolver_errors_propagate():
    async def _boom(_v: str) -> str:
        raise RuntimeError("registry down")

    with pytest.raises(RuntimeError, match="registry down"):
        await _bind({"X-Tenant-Id": "acme"}, source="authorization", resolve=_boom)


# --------------------------------------------------------------------------- #
# Binding (delegating)
# --------------------------------------------------------------------------- #
async def test_delegating_plain_header_stands_in_for_effective(monkeypatch):
    monkeypatch.setenv("AUTH_DELEGATING_SUBJECTS", SA_SUBJECT)
    got = await _bind({"X-Tenant-Id": OTHER_TENANT}, source="authorization", subject=SA_SUBJECT)
    assert got == OTHER_TENANT
    req = _req({"X-Tenant-Id": OTHER_TENANT})
    tenant, _subj, _lic = auth.apply_effective_tenant(
        req, SA_SUBJECT, LICENCE_TENANT, SA_SUBJECT, "lic-1", requested=got
    )
    assert tenant == OTHER_TENANT


async def test_delegating_explicit_effective_wins(monkeypatch):
    monkeypatch.setenv("AUTH_DELEGATING_SUBJECTS", SA_SUBJECT)
    got = await _bind(
        {"X-Tenant-Id": OTHER_TENANT, "X-Effective-Tenant-Id": "33333333"},
        source="authorization",
        subject=SA_SUBJECT,
    )
    assert got == "33333333"


async def test_delegating_plain_equal_own_is_not_a_delegation(monkeypatch):
    monkeypatch.setenv("AUTH_DELEGATING_SUBJECTS", SA_SUBJECT)
    got = await _bind({"X-Tenant-Id": LICENCE_TENANT}, source="authorization", subject=SA_SUBJECT)
    assert got == ""


async def test_delegation_keyed_on_subject_not_header(monkeypatch):
    monkeypatch.setenv("AUTH_DELEGATING_SUBJECTS", SA_SUBJECT)
    with pytest.raises(auth.LicenceTenantMismatch):
        await _bind({"X-Tenant-Id": OTHER_TENANT}, source="authorization", subject="user-1")


# --------------------------------------------------------------------------- #
# apply_effective_tenant(requested=) keeps 0.36 behaviour when omitted
# --------------------------------------------------------------------------- #
def test_apply_effective_tenant_requested_none_reads_header(monkeypatch):
    monkeypatch.setenv("AUTH_DELEGATING_SUBJECTS", SA_SUBJECT)
    req = _req({"X-Effective-Tenant-Id": OTHER_TENANT})
    assert auth.apply_effective_tenant(req, SA_SUBJECT, LICENCE_TENANT, SA_SUBJECT, None)[0] == (
        OTHER_TENANT
    )


def test_apply_effective_tenant_requested_empty_overrides_header(monkeypatch):
    monkeypatch.setenv("AUTH_DELEGATING_SUBJECTS", SA_SUBJECT)
    req = _req({"X-Effective-Tenant-Id": OTHER_TENANT})
    got = auth.apply_effective_tenant(
        req, SA_SUBJECT, LICENCE_TENANT, SA_SUBJECT, None, requested=""
    )
    assert got[0] == LICENCE_TENANT


# --------------------------------------------------------------------------- #
# Report-only conformance rule
# --------------------------------------------------------------------------- #
_OPT_IN_BY_HAND = """
def dispatch(request, host):
    if is_trusted_identity_source(host):
        tenant = request.headers.get("X-Tenant-Id", "").strip()
        return tenant
"""

_VIA_SEAM = """
def dispatch(request, host):
    tenant = resolve_tokenless_tenant(host, request.headers)
    if tenant is not None:
        return tenant
"""

_SEAM_IN_BODY = """
def dispatch(request, host):
    if is_trusted_network(host):
        return resolve_tokenless_tenant(host, request.headers)
"""


def test_unseamed_rule_flags_opt_in_gate_with_hand_read_header():
    found = conformance.scan_unseamed_admission_source(_OPT_IN_BY_HAND)
    assert [f.gate for f in found] == ["is_trusted_identity_source"]
    # ...which the FAILING lint deliberately clears — the new rule is the delta.
    assert conformance.scan_source(_OPT_IN_BY_HAND) == []


@pytest.mark.parametrize("src", [_VIA_SEAM, _SEAM_IN_BODY])
def test_unseamed_rule_clears_the_seam(src):
    assert conformance.scan_unseamed_admission_source(src) == []


def test_report_never_raises_on_findings_only_warns(tmp_path):
    (tmp_path / "mw.py").write_text(_OPT_IN_BY_HAND)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        found = conformance.report_unseamed_tenant_admission(tmp_path)
    assert len(found) == 1
    assert [w.category for w in caught] == [conformance.UnseamedTenantAdmissionWarning]


def test_report_is_not_vacuous(tmp_path):
    with pytest.raises(conformance.VacuousScanError):
        conformance.report_unseamed_tenant_admission(tmp_path)
    with pytest.raises(conformance.VacuousScanError):
        conformance.report_unseamed_tenant_admission()


_ADOPTED_DISPATCH = """
async def dispatch(request):
    token, source = extract_license_token_with_source(request)
    if token:
        intro = await introspect_license(token)
        return intro, source
"""

_HAND_ROLLED = """
async def dispatch(request):
    raw = request.headers.get("Authorization", "")
    token = raw.removeprefix("Bearer ")
    return await introspect_license(token)
"""


def test_r1_does_not_flag_the_library_carrier_but_still_flags_hand_rolled():
    assert conformance.scan_carriage_source(_ADOPTED_DISPATCH) == []
    rules = [f.rule for f in conformance.scan_carriage_source(_HAND_ROLLED)]
    assert "R1" in rules
