"""Tests for the outbound_headers helper."""

from __future__ import annotations

from kag_common.auth import outbound_headers


def test_only_content_type_when_no_tenant_info() -> None:
    assert outbound_headers() == {"Content-Type": "application/json"}


def test_bare_tenant_id_fallback() -> None:
    headers = outbound_headers("tenant-uuid")
    assert headers["X-Tenant-Id"] == "tenant-uuid"
    assert "X-Subject-Id" not in headers
    assert "X-Tenant-Name" not in headers


def test_caller_jwt_is_bearer_prefixed() -> None:
    headers = outbound_headers("tid", tenant_token="header.payload.sig")
    assert headers["X-Tenant-Id"] == "Bearer header.payload.sig"


def test_caller_opaque_token_is_bare() -> None:
    headers = outbound_headers("tid", tenant_token="opaque-token-no-dots")
    assert headers["X-Tenant-Id"] == "opaque-token-no-dots"


def test_caller_one_dot_token_still_bare() -> None:
    # JWT requires at least 2 dots (header.payload.sig) — one dot is opaque.
    headers = outbound_headers("tid", tenant_token="a.b")
    assert headers["X-Tenant-Id"] == "a.b"


def test_service_token_is_always_bearer_even_when_opaque() -> None:
    headers = outbound_headers("tid", service_token="opaque-service-token")
    assert headers["X-Tenant-Id"] == "Bearer opaque-service-token"


def test_caller_token_wins_over_service_token_and_tenant_id() -> None:
    headers = outbound_headers(
        "tenant-uuid",
        tenant_token="a.b.c",
        service_token="should-not-appear",
    )
    assert headers["X-Tenant-Id"] == "Bearer a.b.c"


def test_service_token_wins_over_bare_tenant_id() -> None:
    headers = outbound_headers("tenant-uuid", service_token="svc")
    assert headers["X-Tenant-Id"] == "Bearer svc"


def test_optional_headers_only_when_truthy() -> None:
    headers = outbound_headers(
        "tid",
        subject_id="sub",
        tenant_name="acme",
        idempotency_key="job-1_karma_2",
    )
    assert headers["X-Subject-Id"] == "sub"
    assert headers["X-Tenant-Name"] == "acme"
    assert headers["Idempotency-Key"] == "job-1_karma_2"


def test_empty_optional_headers_skipped() -> None:
    headers = outbound_headers(
        "tid",
        subject_id="",
        tenant_name="",
        idempotency_key="",
    )
    assert "X-Subject-Id" not in headers
    assert "X-Tenant-Name" not in headers
    assert "Idempotency-Key" not in headers


def test_authorization_service_token_does_not_touch_tenant_ladder() -> None:
    # WS-4 on-behalf-of: the service identity rides Authorization; the bare
    # customer tenant stays in X-Tenant-Id (NOT clobbered like service_token).
    headers = outbound_headers(
        "customer-tenant-uuid",
        authorization_service_token="opaque-svc-token",
    )
    assert headers["X-Tenant-Id"] == "customer-tenant-uuid"
    assert headers["Authorization"] == "Bearer opaque-svc-token"


def test_authorization_service_token_coexists_with_caller_token() -> None:
    # A caller may forward a per-request tenant_token AND its own svc identity.
    headers = outbound_headers(
        "tid",
        tenant_token="opaque-tenant",
        authorization_service_token="svc",
    )
    assert headers["X-Tenant-Id"] == "opaque-tenant"
    assert headers["Authorization"] == "Bearer svc"


def test_authorization_service_token_absent_when_falsy() -> None:
    assert "Authorization" not in outbound_headers("tid")
    assert "Authorization" not in outbound_headers("tid", authorization_service_token="")


def test_extra_can_override_authorization() -> None:
    headers = outbound_headers(
        "tid",
        authorization_service_token="svc",
        extra={"Authorization": "Bearer override"},
    )
    assert headers["Authorization"] == "Bearer override"


def test_extra_merges_last_and_wins_on_conflict() -> None:
    headers = outbound_headers(
        "tid",
        extra={"X-Custom": "v", "X-Tenant-Id": "override"},
    )
    assert headers["X-Custom"] == "v"
    assert headers["X-Tenant-Id"] == "override"


def test_extra_none_is_noop() -> None:
    headers = outbound_headers("tid", extra=None)
    assert headers == {"Content-Type": "application/json", "X-Tenant-Id": "tid"}


def test_no_tenant_id_no_token_no_x_tenant_id_header() -> None:
    # All three ladder branches inactive — X-Tenant-Id is omitted entirely
    # (caller bug, but we don't synthesize a value).
    headers = outbound_headers()
    assert "X-Tenant-Id" not in headers


# ---------------------------------------------------------------------------
# X-License-Id — licence attribution for downstream cost events
# ---------------------------------------------------------------------------
#
# Every KAG inter-service hop is built here, and until 2026-08-11 this builder
# had no branch that emitted X-License-Id at all. Downstreams that authenticate
# on a service token therefore had no way to learn which customer licence the
# work belonged to, and their cost events landed unattributable: measured at
# 100% of karma (5,011), hirag (1,243) and kag-graph (6,038) events over 30 days
# on prod. The receive side (auth.apply_effective_tenant) already read the
# header; only the send side was missing.


def test_license_id_is_forwarded_bare() -> None:
    headers = outbound_headers("tid", license_id="11111111-2222-4333-8444-555555555555")
    # Bare, never Bearer-prefixed: this is attribution data, not a credential.
    assert headers["X-License-Id"] == "11111111-2222-4333-8444-555555555555"


def test_license_id_omitted_when_absent() -> None:
    assert "X-License-Id" not in outbound_headers("tid")


def test_license_id_omitted_when_empty() -> None:
    # An unlicensed hop must send no header at all rather than an empty one:
    # billing distinguishes "no licence" from "a licence that is the empty
    # string", and only the former is an honest NULL.
    assert "X-License-Id" not in outbound_headers("tid", license_id="")


def test_license_id_does_not_disturb_the_tenant_ladder() -> None:
    headers = outbound_headers(
        "tid", service_token="opaque-svc-token", license_id="lic-1", subject_id="sub-1"
    )
    assert headers["X-Tenant-Id"] == "Bearer opaque-svc-token"
    assert headers["X-License-Id"] == "lic-1"
    assert headers["X-Subject-Id"] == "sub-1"


def test_extra_still_wins_over_license_id() -> None:
    headers = outbound_headers(
        "tid", license_id="lic-1", extra={"X-License-Id": "explicit-override"}
    )
    assert headers["X-License-Id"] == "explicit-override"


# ---------------------------------------------------------------------------
# X-App-Id — application attribution for downstream cost events
# ---------------------------------------------------------------------------
#
# Same shape as the X-License-Id gap above, one column over, and structural:
# until this parameter existed the builder had no branch that could emit
# X-App-Id, so NO KAG-family caller could assert one — the only escape was
# hand-rolling extra={"X-App-Id": ...} at each call site, which none did.
#
# ⚠️ The ledger is the wrong instrument for grading this. Measured 2026-09-10:
# 68.3% of inference calls carried no app_id ON THE WIRE, while only 0.26% of
# billing_cost_events rows read as app_id-missing — because billing_service's
# cost_flusher DERIVES the app from the licence when the emitter asserted
# nothing (42-83% of attributed dollars per day were derived, not asserted).
# The derivation is the safety net and must stay; the fix is to make the
# derived share FALL by letting emitters assert. Grade on
# billing_app_resolved_total, never on cost_source (the app_id derivation
# deliberately does not suffix it).
#
# The receive side is NOT in this library: karma_service's
# auth.dependencies.get_app_id and nlp_service's identity_context.APP_ID_HEADER
# already read this header, and both feed kag_common.metering.emit_cost_event's
# existing app_id field. This closes the producer half of a live contract.


def test_app_id_is_forwarded_bare() -> None:
    headers = outbound_headers("tid", app_id="portal")
    # Bare, never Bearer-prefixed: attribution data, not a credential.
    assert headers["X-App-Id"] == "portal"


def test_app_id_omitted_when_absent() -> None:
    assert "X-App-Id" not in outbound_headers("tid")


def test_app_id_omitted_when_empty() -> None:
    # ABSENT, not empty. Billing distinguishes "no app" from "an app that is the
    # empty string"; only the former is an honest NULL that can be counted and
    # chased. An empty-valued header would read as coverage.
    assert "X-App-Id" not in outbound_headers("tid", app_id="")


def test_app_id_is_never_defaulted_or_self_named() -> None:
    # ⛔ The regression this guards: a builder that substitutes ANY placeholder
    # ("unknown", the calling service's own name) when the caller resolved
    # nothing. That collapses every distinct upstream origin into one bucket
    # while reading as 100% coverage — strictly worse than an absence, because a
    # collapsed bucket cannot be un-collapsed. No value in, no header out.
    headers = outbound_headers("tid", service_token="svc", license_id="lic-1")
    assert not [k for k in headers if k.lower() == "x-app-id"]
    assert "unknown" not in str(headers).lower()


def test_app_id_is_independent_of_license_id() -> None:
    # The two attribution headers are separate columns in billing: an app with
    # no licence, and a licence with no app, must each carry only what was
    # actually resolved rather than one standing in for the other.
    assert outbound_headers("tid", app_id="portal") == {
        "Content-Type": "application/json",
        "X-Tenant-Id": "tid",
        "X-App-Id": "portal",
    }
    assert outbound_headers("tid", license_id="lic-1") == {
        "Content-Type": "application/json",
        "X-Tenant-Id": "tid",
        "X-License-Id": "lic-1",
    }


def test_app_id_does_not_disturb_the_tenant_ladder() -> None:
    headers = outbound_headers(
        "tid",
        service_token="opaque-svc-token",
        license_id="lic-1",
        app_id="portal",
        subject_id="sub-1",
    )
    assert headers["X-Tenant-Id"] == "Bearer opaque-svc-token"
    assert headers["X-License-Id"] == "lic-1"
    assert headers["X-App-Id"] == "portal"
    assert headers["X-Subject-Id"] == "sub-1"


def test_extra_still_wins_over_app_id() -> None:
    headers = outbound_headers("tid", app_id="portal", extra={"X-App-Id": "explicit-override"})
    assert headers["X-App-Id"] == "explicit-override"
