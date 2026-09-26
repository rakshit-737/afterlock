"""Adversarial API review (docs/security/review-2026-09-26-adversarial-api.md): regression tests."""

from __future__ import annotations

import time
from typing import Any

import pytest

from afterlock_api.storage import MemoryStorage, build_manifest

jwt = pytest.importorskip("jwt")

from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from jwt.algorithms import RSAAlgorithm  # noqa: E402

from afterlock_api.oidc import OIDCConfig, OIDCError, OIDCValidator  # noqa: E402

ISS, AUD, JWKS_URL = "https://idp.example.test", "afterlock", "https://idp.example.test/jwks"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class CountingJWKS:
    def __init__(self) -> None:
        d = RSAAlgorithm.to_jwk(KEY.public_key(), as_dict=True)
        d.update(kid="rsa1", use="sig")
        self.doc = {"keys": [d]}
        self.calls = 0
        self.fail = False

    def __call__(self, url: str) -> dict[str, Any]:
        self.calls += 1
        if self.fail:
            raise OSError("idp down")
        return self.doc


def _token(kid: str) -> str:
    now = int(time.time())
    c = {"iss": ISS, "aud": AUD, "sub": "alice", "iat": 0, "exp": now + 300,  # iat=0: validator clock is fake
         "afterlock_role": "analyst", "afterlock_clusters": ["lab-local"]}
    return str(jwt.encode(c, KEY, algorithm="RS256", headers={"kid": kid}))


# A-1: a failed JWKS refresh was retried on every request (under the global validator lock),
# so during an IdP outage any unauthenticated client could make the API fetch the JWKS URL
# once per request, each fetch blocking all OIDC validation for up to the 5 s timeout.
def test_failed_jwks_refresh_is_rate_limited() -> None:
    now = [1_000.0]
    fetch = CountingJWKS()
    v = OIDCValidator(OIDCConfig(issuer=ISS, audience=AUD, jwks_url=JWKS_URL, jwks_ttl=300, jwks_min_refresh=30),
                      fetch=fetch, clock=lambda: now[0])
    assert v.validate(_token("rsa1")).subject == "alice"
    fetch.fail = True
    now[0] += 301  # cache stale, IdP down
    for i in range(50):
        v.validate(_token("rsa1"))  # cached keys keep working
        with pytest.raises(OIDCError):
            v.validate(_token(f"attacker-{i}"))
    assert fetch.calls <= 2, fetch.calls
    now[0] += 31  # after the back-off, one retry is allowed again
    v.validate(_token("rsa1"))
    assert fetch.calls <= 3


def test_jwks_outage_at_start_is_rate_limited_too() -> None:
    now = [1_000.0]
    fetch = CountingJWKS()
    fetch.fail = True
    v = OIDCValidator(OIDCConfig(issuer=ISS, audience=AUD, jwks_url=JWKS_URL), fetch=fetch, clock=lambda: now[0])
    for _ in range(20):
        with pytest.raises(OIDCError):
            v.validate(_token("rsa1"))
    assert fetch.calls == 1
    fetch.fail = False
    now[0] += 31
    assert v.validate(_token("rsa1")).subject == "alice"


# A-2: leases were identified by (job, owner) only. A worker whose lease expired and whose job
# was re-claimed under the same owner name (the in-process API drains all use "api-inprocess";
# a restarted container keeps hostname-pid) could still heartbeat, fail, cancel or publish
# against the *new* attempt's lease.
def _stale_and_fresh() -> tuple[MemoryStorage, Any, Any]:
    now = [0.0]
    s = MemoryStorage(clock=lambda: now[0])
    s.create_case({"case_id": "c1", "cluster_id": "lab-local", "input": {"x": 1}, "diagnostics": {}})
    s.enqueue(build_manifest("lab-local", "c1", "analysis", {"input": {"x": 1}, "mode": "full"}), created_by="t")
    stale = s.claim("api-inprocess", 30)
    assert stale is not None
    now[0] = 31  # lease expired
    fresh = s.claim("api-inprocess", 30)
    assert fresh is not None and fresh.attempt == stale.attempt + 1
    return s, stale, fresh


def test_stale_lease_cannot_publish_over_a_reclaimed_attempt() -> None:
    s, stale, fresh = _stale_and_fresh()
    assert s.complete(stale, {"from": "stale"}) is None
    assert s.heartbeat(stale, 30) == "lost"
    assert s.fail(stale, "boom") is None
    rid = s.complete(fresh, {"from": "fresh"})
    assert rid is not None and s.results[rid]["result"] == {"from": "fresh"}


def test_stale_lease_cannot_requeue_a_running_attempt() -> None:
    s, stale, fresh = _stale_and_fresh()
    assert s.fail(stale, "transient", retryable=True) is None
    assert s.mark_running(fresh, 30) == "ok"
