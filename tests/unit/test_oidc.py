"""OIDC bearer-JWT validation with locally generated keys and a fake JWKS (no network)."""

from __future__ import annotations

import base64
import json
import time
from typing import Any

import pytest

jwt = pytest.importorskip("jwt", reason="BLOCKED: optional extra 'oidc' not installed (not a pass)")
from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from jwt.algorithms import ECAlgorithm, RSAAlgorithm  # noqa: E402

from afterlock_api.app import Settings, create_app  # noqa: E402
from afterlock_api.oidc import OIDCConfig, OIDCError, OIDCValidator  # noqa: E402
from afterlock_api.storage import MemoryStorage  # noqa: E402

ISS = "https://idp.example.test"
AUD = "afterlock"
JWKS_URL = "https://idp.example.test/jwks"
RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
EC_KEY = ec.generate_private_key(ec.SECP256R1())
OTHER_RSA = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def jwk(key: Any, kid: str) -> dict[str, Any]:
    alg = RSAAlgorithm if isinstance(key, rsa.RSAPrivateKey) else ECAlgorithm
    d = alg.to_jwk(key.public_key(), as_dict=True)
    d.update(kid=kid, use="sig")
    return d


class FakeJWKS:
    def __init__(self, *keys: dict[str, Any]) -> None:
        self.doc: dict[str, Any] = {"keys": list(keys)}
        self.calls = 0
        self.fail = False

    def __call__(self, url: str) -> dict[str, Any]:
        assert url == JWKS_URL
        self.calls += 1
        if self.fail:
            raise OSError("idp down")
        return json.loads(json.dumps(self.doc))


def claims(**over: Any) -> dict[str, Any]:
    now = int(time.time())
    base = {"iss": ISS, "aud": AUD, "sub": "alice", "iat": now, "nbf": now, "exp": now + 300,
            "afterlock_role": "analyst", "afterlock_clusters": ["lab-local"]}
    base.update(over)
    return {k: v for k, v in base.items() if v is not None}


def sign(c: dict[str, Any], key: Any = RSA_KEY, alg: str = "RS256", kid: str = "rsa1") -> str:
    return jwt.encode(c, key, algorithm=alg, headers={"kid": kid})


def validator(fetch: FakeJWKS | None = None, **cfg: Any) -> OIDCValidator:
    config = OIDCConfig(issuer=ISS, audience=AUD, jwks_url=JWKS_URL, **cfg)
    return OIDCValidator(config, fetch=fetch or FakeJWKS(jwk(RSA_KEY, "rsa1"), jwk(EC_KEY, "ec1")))


def b64(obj: Any) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def test_valid_rs256_and_es256() -> None:
    v = validator()
    ident = v.validate(sign(claims()))
    assert (ident.subject, ident.role, ident.clusters) == ("alice", "analyst", frozenset({"lab-local"}))
    assert v.validate(sign(claims(afterlock_role="viewer"), EC_KEY, "ES256", "ec1")).role == "viewer"


@pytest.mark.parametrize("bad", [
    {"iss": "https://evil.test"},
    {"aud": "someone-else"},
    {"exp": -120},  # seconds relative to when the test runs
    {"nbf": 120},  # seconds relative to when the test runs
    {"iat": 120},  # seconds relative to when the test runs
    {"exp": None},
    {"iat": None},
    {"afterlock_role": "root"},
    {"afterlock_role": None},
    {"afterlock_clusters": None},
    {"afterlock_clusters": []},
    {"afterlock_clusters": ["*"]},
])
def test_rejected_claims(bad: dict[str, Any]) -> None:
    # Time claims are offsets resolved now: parametrize values are built at collection time,
    # which can be minutes before this test runs on a slow CI suite.
    now = int(time.time())
    resolved = {k: now + v if k in ("exp", "nbf", "iat") and isinstance(v, int) else v for k, v in bad.items()}
    with pytest.raises(OIDCError):
        validator().validate(sign(claims(**resolved)))


def test_small_leeway_accepts_slight_clock_skew() -> None:
    v = validator(leeway=30)
    assert v.validate(sign(claims(exp=int(time.time()) - 5, nbf=int(time.time()) + 5, iat=int(time.time()) + 5))).subject == "alice"


def test_alg_none_and_hmac_are_rejected() -> None:
    v = validator()
    unsigned = f"{b64({'alg': 'none', 'kid': 'rsa1'})}.{b64(claims())}."
    with pytest.raises(OIDCError, match="not allowed"):
        v.validate(unsigned)
    # Key-confusion attack: HS256 "signed" with the RSA public key's PEM as the HMAC secret.
    import hashlib
    import hmac

    from cryptography.hazmat.primitives import serialization

    pem = RSA_KEY.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    signing_input = f"{b64({'alg': 'HS256', 'kid': 'rsa1', 'typ': 'JWT'})}.{b64(claims())}"
    sig = base64.urlsafe_b64encode(hmac.new(pem, signing_input.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    with pytest.raises(OIDCError, match="not allowed"):
        v.validate(f"{signing_input}.{sig}")
    for alg in ("HS384", "HS512", "PS256", "EdDSA"):
        with pytest.raises(OIDCError):
            v.validate(f"{b64({'alg': alg, 'kid': 'rsa1'})}.{b64(claims())}.AAAA")


def test_wrong_key_and_key_type_mismatch() -> None:
    v = validator()
    with pytest.raises(OIDCError):
        v.validate(sign(claims(), OTHER_RSA))  # right kid, wrong key: bad signature
    with pytest.raises(OIDCError, match="key type"):
        v.validate(sign(claims(), EC_KEY, "ES256", "rsa1"))  # EC alg against an RSA key
    with pytest.raises(OIDCError):
        v.validate("not-a-jwt")


def test_jwks_cache_and_rotation() -> None:
    now = [1_000.0]
    fetch = FakeJWKS(jwk(RSA_KEY, "rsa1"))
    v = OIDCValidator(OIDCConfig(issuer=ISS, audience=AUD, jwks_url=JWKS_URL, jwks_ttl=300, jwks_min_refresh=30), fetch=fetch,
                      clock=lambda: now[0])
    tok = sign(claims(iat=0, nbf=0, exp=int(time.time()) + 300))
    v.validate(tok)
    v.validate(tok)
    assert fetch.calls == 1  # cached
    # Rotation: unknown kid triggers a refetch, but at most once per jwks_min_refresh.
    fetch.doc["keys"].append(jwk(OTHER_RSA, "rsa2"))
    rotated = sign(claims(iat=0, nbf=0, exp=int(time.time()) + 300), OTHER_RSA, kid="rsa2")
    with pytest.raises(OIDCError, match="unknown signing key"):
        v.validate(rotated)  # too soon after the first fetch
    now[0] += 31
    assert v.validate(rotated).subject == "alice" and fetch.calls == 2
    with pytest.raises(OIDCError):
        v.validate(sign(claims(iat=0, nbf=0), OTHER_RSA, kid="nope"))
    assert fetch.calls == 2  # unknown kid storm does not hammer the IdP
    # IdP outage after the first fetch: the cached key set keeps working after the TTL.
    fetch.fail = True
    now[0] += 1_000
    assert v.validate(tok).subject == "alice"


def test_jwks_unavailable_at_start_is_rejection() -> None:
    fetch = FakeJWKS()
    fetch.fail = True
    with pytest.raises(OIDCError, match="JWKS unavailable"):
        validator(fetch).validate(sign(claims()))


def test_role_map_string_clusters_and_wildcard_opt_in() -> None:
    v = validator(role_map={"afterlock-analysts": "analyst", "afterlock-readers": "viewer"}, role_claim="groups")
    ident = v.validate(sign(claims(groups=["unrelated", "afterlock-readers", "afterlock-analysts"], afterlock_clusters="a|b")))
    assert ident.role == "analyst" and ident.clusters == frozenset({"a", "b"})
    with pytest.raises(OIDCError):
        v.validate(sign(claims(groups=["analyst"])))  # with a map, raw role names are not trusted
    assert validator(allow_wildcard=True).validate(sign(claims(afterlock_clusters=["*"]))).clusters == frozenset({"*"})


def test_config_validation_and_env() -> None:
    with pytest.raises(ValueError, match="https"):
        OIDCConfig(issuer=ISS, audience=AUD, jwks_url="http://idp/jwks")
    with pytest.raises(ValueError):
        OIDCConfig(issuer=ISS, audience="", jwks_url=JWKS_URL)
    with pytest.raises(ValueError):
        OIDCConfig(issuer=ISS, audience=AUD, jwks_url=JWKS_URL, role_map={"g": "root"})
    assert OIDCConfig.from_env({}) is None
    cfg = OIDCConfig.from_env({"AFTERLOCK_OIDC_ISSUER": ISS, "AFTERLOCK_OIDC_AUDIENCE": AUD, "AFTERLOCK_OIDC_JWKS_URL": JWKS_URL,
                               "AFTERLOCK_OIDC_ROLE_MAP": "team:ops:analyst", "AFTERLOCK_OIDC_ROLE_CLAIM": "groups"})
    assert cfg is not None and cfg.role_map == {"team:ops": "analyst"} and cfg.role_claim == "groups"


def test_api_accepts_oidc_and_static_tokens_side_by_side() -> None:
    static = "static-analyst-token-0123"
    app = create_app(f"{static}:viewer:lab-local", storage=MemoryStorage(), settings=Settings(), oidc=validator())
    client = TestClient(app)
    assert client.get("/v1/cases", headers={"Authorization": f"Bearer {static}"}).status_code == 200
    ok = sign(claims(afterlock_clusters=["other"]))
    assert client.get("/v1/cases", headers={"Authorization": f"Bearer {ok}"}).status_code == 200
    body = {"case_id": "x", "cluster_id": "lab-local", "inventory": {}, "case": {}, "events": []}
    # OIDC principal is analyst only for "other": creating in lab-local is forbidden.
    assert client.post("/v1/cases", json=body, headers={"Authorization": f"Bearer {ok}"}).status_code == 403
    expired = sign(claims(exp=int(time.time()) - 600))
    r = client.get("/v1/cases", headers={"Authorization": f"Bearer {expired}"})
    assert r.status_code == 401 and r.json()["detail"] == "invalid token"  # no validation detail leaks
