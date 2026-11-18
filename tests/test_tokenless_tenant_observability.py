"""The silent credential-less tenant-assertion path must emit a counter.

WHAT IS BEING GUARDED, AND WHY IT NEEDS A TEST AT ALL
-----------------------------------------------------
``DEFAULT_TRUSTED_CIDRS`` ships ``10.0.0.0/8``, a superset of the k3s pod CIDR
``10.42.0.0/16``. Seven consumers branch on ``is_trusted_network()`` alone and
then take the tenant off a bare ``X-Tenant-Id``, so any pod in the cluster can
assert any tenant with no credential — and until 0.30.0 that path emitted no
counter, no log and no alert. An exposure nobody can measure cannot be sized,
and enforcement cannot be armed against an unmeasured population.

⚠️ Every assertion below is written to be able to FAIL. A test that reads a
counter must pin the exact label set and take a DELTA across the call, because
``prometheus_client`` counters are process-global and monotonic: asserting
``> 0`` on a shared registry passes on a series some earlier test incremented,
which is a test that cannot fail for the mutation it exists to catch. Each test
here was mutation-checked by deleting its ``record_*`` call and confirming it
goes red — see the PR body for the transcript.

⛔ These tests assert OBSERVATION, never ENFORCEMENT. Each one also asserts the
return value is unchanged, so a future "while we are here" tightening of the
auth decision cannot land under cover of an observability test.
"""

from __future__ import annotations

import pytest
from prometheus_client import REGISTRY

from kag_common import auth, metrics

BYPASS_METRIC = "kag_trusted_network_bypass_total"
ASSERTION_METRIC = "kag_tokenless_tenant_assertion_total"

SERVICE = "kag_common_test_service"


@pytest.fixture(autouse=True)
def _pin_service_label(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the ``service`` label so assertions name an exact series.

    Also clears ``SERVICE_NAME`` so the fallback arm cannot leak a value from
    the ambient environment and silently widen the label being asserted.
    """
    monkeypatch.setenv("OTEL_SERVICE_NAME", SERVICE)
    monkeypatch.delenv("SERVICE_NAME", raising=False)


def _read(metric: str, **labels: str) -> float:
    """Current value of one exact series, or 0.0 if it does not exist yet."""
    value = REGISTRY.get_sample_value(metric, {"service": SERVICE, **labels})
    return 0.0 if value is None else value


# --------------------------------------------------------------------------- #
# resolve_tokenless_tenant — BOTH header branches.
#
# These are the two DIFFERENT exposures, and instrumenting only the first is the
# gap in ``worker_management_unauthenticated_tenant_assertion_total``:
#   * header PRESENT — the caller reads/writes under a tenant name it chose.
#   * header ABSENT  — the consumer's own ``or DEFAULT_TENANT_ID`` fallback picks
#     the tenant, so the request lands in a tenant nobody chose per request. This
#     is the worse case and it is the one nothing counted.
# --------------------------------------------------------------------------- #
def test_header_present_branch_increments_with_has_header_true(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AUTH_TRUST_INCLUSTER_IDENTITY", "true")
    before = _read(ASSERTION_METRIC, has_header="true", outcome=metrics.TOKENLESS_ADMITTED)

    resolved = auth.resolve_tokenless_tenant("10.42.6.7", {"X-Tenant-Id": "victim-tenant"})

    after = _read(ASSERTION_METRIC, has_header="true", outcome=metrics.TOKENLESS_ADMITTED)
    assert after - before == 1.0
    # Behaviour unchanged: the header is still honoured exactly as before.
    assert resolved == "victim-tenant"


def test_header_absent_branch_increments_with_has_header_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ``procedure_management`` case: a caller that sends NO tenant header.

    The library refuses (returns ``None``) — but the consumer that wired its own
    ``raw_tenant or DEFAULT_TENANT_ID`` does not, which is precisely why this
    population has to be countable separately from the header-present one.
    """
    monkeypatch.setenv("AUTH_TRUST_INCLUSTER_IDENTITY", "true")
    before = _read(
        ASSERTION_METRIC, has_header="false", outcome=metrics.TOKENLESS_REFUSED_NO_HEADER
    )

    resolved = auth.resolve_tokenless_tenant("10.42.6.7", {"X-Request-ID": "abc"})

    after = _read(ASSERTION_METRIC, has_header="false", outcome=metrics.TOKENLESS_REFUSED_NO_HEADER)
    assert after - before == 1.0
    assert resolved is None


def test_blank_header_counts_as_absent_not_present() -> None:
    """``X-Tenant-Id: "   "`` is the header-ABSENT case, not a present one.

    A whitespace-only header is how a misconfigured caller expresses "I did not
    send a tenant". Bucketing it as present would move the dangerous population
    into the safer-looking bucket and understate exactly the number the operator
    is about to make a decision on.
    """
    before = _read(ASSERTION_METRIC, has_header="false", outcome=metrics.TOKENLESS_REFUSED_PEER)

    assert auth.resolve_tokenless_tenant("10.42.6.7", {"X-Tenant-Id": "   "}) is None

    after = _read(ASSERTION_METRIC, has_header="false", outcome=metrics.TOKENLESS_REFUSED_PEER)
    assert after - before == 1.0


def test_refused_peer_still_counted_and_carries_has_header() -> None:
    """A refusal must be counted too — a numerator needs its denominator.

    With ``AUTH_TRUST_INCLUSTER_IDENTITY`` unset (the default) every call lands
    here, so a series that counted only admissions would read a flat zero and be
    indistinguishable from "the exposure is not being exercised".
    """
    before = _read(ASSERTION_METRIC, has_header="true", outcome=metrics.TOKENLESS_REFUSED_PEER)

    assert auth.resolve_tokenless_tenant("10.42.6.7", {"X-Tenant-Id": "t"}) is None

    after = _read(ASSERTION_METRIC, has_header="true", outcome=metrics.TOKENLESS_REFUSED_PEER)
    assert after - before == 1.0


def test_bearer_in_tenant_header_gets_its_own_outcome(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AUTH_TRUST_INCLUSTER_IDENTITY", "true")
    before = _read(ASSERTION_METRIC, has_header="true", outcome=metrics.TOKENLESS_REFUSED_BEARER)

    assert auth.resolve_tokenless_tenant("10.42.6.7", {"X-Tenant-Id": "Bearer abc"}) is None

    after = _read(ASSERTION_METRIC, has_header="true", outcome=metrics.TOKENLESS_REFUSED_BEARER)
    assert after - before == 1.0


# --------------------------------------------------------------------------- #
# is_trusted_network — the seam that actually fires in the seven consumers.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("host", "peer_class", "trusted"),
    [
        ("10.42.6.7", "k8s_pod", "true"),  # any pod in the mesh, and the gateway SNAT
        ("192.168.1.9", "lan_192", "true"),  # the 2026-04-18 SSR-proxy vector
        ("172.17.0.2", "docker_172", "true"),  # a dind/sidecar container on a node
        ("127.0.0.1", "loopback", "true"),
        ("100.64.0.1", "tailnet", "false"),  # tailnet is NOT in the default list
        ("8.8.8.8", "public", "false"),
        (None, "unparseable", "false"),  # ASGI scope with no client
    ],
)
def test_trusted_network_predicate_is_counted_on_both_outcomes(
    host: str | None, peer_class: str, trusted: str
) -> None:
    """Both outcomes are counted, so the ratio has a denominator.

    ``trusted="false"`` rows are what make the series readable: without them a
    reader cannot tell a service whose traffic is entirely in-mesh from one that
    simply serves no traffic.
    """
    before = _read(BYPASS_METRIC, peer_class=peer_class, trusted=trusted)

    result = auth.is_trusted_network(host)

    after = _read(BYPASS_METRIC, peer_class=peer_class, trusted=trusted)
    assert after - before == 1.0
    # Behaviour unchanged: the counter reports the decision, it does not make it.
    assert result is (trusted == "true")


def test_counter_failure_cannot_break_the_auth_decision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A broken metric must never change an authentication outcome.

    This is the one failure mode that would make the instrumentation worse than
    the silence it replaces: an observability bug that 500s the auth path.
    """

    def _boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("registry exploded")

    monkeypatch.setattr(metrics.trusted_network_bypass_total, "labels", _boom)
    assert auth.is_trusted_network("10.42.6.7") is True
    assert auth.is_trusted_network("8.8.8.8") is False
