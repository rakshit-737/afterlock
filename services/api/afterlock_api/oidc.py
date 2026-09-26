"""Optional OIDC bearer-JWT validation for the API (extra ``afterlock[oidc]``).

Only asymmetric signatures are accepted (``RS256``, ``ES256``). ``alg=none`` and every
``HS*`` algorithm are rejected before any key is consulted, so a public JWKS key can never be
used as an HMAC secret. The token must carry ``iss``, ``aud``, ``exp``, ``iat`` (and ``nbf``
is honoured when present), checked with a small leeway.

The JWKS document is fetched from a configured HTTPS URL, cached for ``jwks_ttl`` seconds,
and re-fetched early at most once per ``jwks_min_refresh`` seconds when an unknown ``kid``
appears (key rotation). The fetcher is injectable so tests never touch the network.

Role and cluster claims are mapped via configuration:

* ``role_claim`` (default ``afterlock_role``): a string or list of strings. Each value is
  mapped through ``role_map`` (``claim-value -> role``) when one is configured, otherwise it
  must itself be a role name. Unknown values are ignored. When several roles result, the most
  privileged of ``analyst`` > ``viewer`` > ``lab-operator`` wins. No role -> rejected.
* ``clusters_claim`` (default ``afterlock_clusters``): a list of strings or a ``|``-separated
  string. The wildcard ``*`` is refused unless ``allow_wildcard`` is set.
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

ALLOWED_ALGS = {"RS256": "RSA", "ES256": "EC"}
ROLE_PRIORITY = ("analyst", "viewer", "lab-operator")
MAX_JWKS_BYTES = 256 * 1024
MAX_TOKEN_BYTES = 16 * 1024


class OIDCError(Exception):
    """Token rejected. The message is for logs/tests; clients only see a generic 401."""


def _http_fetch(url: str) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310 - https enforced in OIDCConfig
        body = resp.read(MAX_JWKS_BYTES + 1)
    if len(body) > MAX_JWKS_BYTES:
        raise OIDCError("JWKS document too large")
    doc = json.loads(body)
    if not isinstance(doc, dict):
        raise OIDCError("JWKS document is not an object")
    return doc


@dataclass
class OIDCConfig:
    issuer: str
    audience: str
    jwks_url: str
    role_claim: str = "afterlock_role"
    clusters_claim: str = "afterlock_clusters"
    role_map: dict[str, str] = field(default_factory=dict)
    allow_wildcard: bool = False
    leeway: float = 30.0
    jwks_ttl: float = 300.0
    jwks_min_refresh: float = 30.0
    allow_insecure_jwks_url: bool = False  # tests / localhost only

    def __post_init__(self) -> None:
        if not (self.issuer and self.audience and self.jwks_url):
            raise ValueError("OIDC issuer, audience and JWKS URL are all required")
        if not self.jwks_url.startswith("https://") and not self.allow_insecure_jwks_url:
            raise ValueError("AFTERLOCK_OIDC_JWKS_URL must use https")
        if not 0 <= self.leeway <= 300:
            raise ValueError("OIDC leeway must be within 0..300 seconds")
        for k, v in self.role_map.items():
            if v not in ROLE_PRIORITY or not k:
                raise ValueError(f"AFTERLOCK_OIDC_ROLE_MAP entry {k!r} -> {v!r} is invalid")

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> OIDCConfig | None:
        e = dict(os.environ if env is None else env)
        issuer = e.get("AFTERLOCK_OIDC_ISSUER", "")
        if not issuer:
            return None
        role_map: dict[str, str] = {}
        for entry in (x.strip() for x in e.get("AFTERLOCK_OIDC_ROLE_MAP", "").split(",") if x.strip()):
            claim_value, sep, role = entry.rpartition(":")
            if not sep:
                raise ValueError(f"AFTERLOCK_OIDC_ROLE_MAP entry {entry!r} must be <claim-value>:<role>")
            role_map[claim_value] = role
        return cls(
            issuer=issuer,
            audience=e.get("AFTERLOCK_OIDC_AUDIENCE", ""),
            jwks_url=e.get("AFTERLOCK_OIDC_JWKS_URL", ""),
            role_claim=e.get("AFTERLOCK_OIDC_ROLE_CLAIM", "afterlock_role"),
            clusters_claim=e.get("AFTERLOCK_OIDC_CLUSTERS_CLAIM", "afterlock_clusters"),
            role_map=role_map,
            allow_wildcard=e.get("AFTERLOCK_OIDC_ALLOW_WILDCARD_CLUSTER", "") == "1",
            leeway=float(e.get("AFTERLOCK_OIDC_LEEWAY_SECONDS", "30")),
            jwks_ttl=float(e.get("AFTERLOCK_OIDC_JWKS_TTL_SECONDS", "300")),
        )


@dataclass(frozen=True)
class Identity:
    subject: str
    role: str
    clusters: frozenset[str]


class OIDCValidator:
    def __init__(self, config: OIDCConfig, fetch: Callable[[str], dict[str, Any]] | None = None,
                 clock: Callable[[], float] = time.time) -> None:
        try:
            import jwt  # optional dependency: pip install 'afterlock[oidc]'
        except ImportError as exc:  # pragma: no cover - depends on installed extras
            raise RuntimeError("OIDC is configured but PyJWT is missing; install 'afterlock[oidc]'") from exc
        self._jwt = jwt
        self.config = config
        self._fetch = fetch or _http_fetch
        self._clock = clock
        self._lock = threading.Lock()
        self._keys: dict[str, Any] = {}
        self._fetched_at: float | None = None
        self._attempted_at: float | None = None

    # JWKS cache -------------------------------------------------------------
    def _refresh(self) -> None:
        doc = self._fetch(self.config.jwks_url)
        keys: dict[str, Any] = {}
        for jwk in doc.get("keys", []) if isinstance(doc.get("keys"), list) else []:
            if not isinstance(jwk, dict) or jwk.get("kty") not in ("RSA", "EC") or jwk.get("use", "sig") != "sig":
                continue
            kid = jwk.get("kid")
            if not isinstance(kid, str) or not kid:
                continue
            try:
                keys[kid] = self._jwt.PyJWK.from_dict(jwk)
            except Exception:  # malformed or unsupported key: skip it, never fall back
                continue
        self._keys = keys
        self._fetched_at = self._clock()

    def _key(self, kid: str) -> Any:
        with self._lock:
            now = self._clock()
            stale = self._fetched_at is None or now - self._fetched_at >= self.config.jwks_ttl
            # Every fetch attempt (successful or not) starts the back-off, so neither an unknown-kid
            # storm nor an IdP outage can make each request hit the JWKS URL under this lock.
            recently_tried = self._attempted_at is not None and now - self._attempted_at < self.config.jwks_min_refresh
            if not recently_tried and (stale or kid not in self._keys):
                self._attempted_at = now
                try:
                    self._refresh()
                except Exception as exc:
                    if self._fetched_at is None:
                        raise OIDCError(f"JWKS unavailable: {type(exc).__name__}") from exc
                    # keep serving the previous key set; it is retried after jwks_min_refresh
            key = self._keys.get(kid)
        if key is None:
            raise OIDCError("unknown signing key")
        return key

    # validation ---------------------------------------------------------------
    def validate(self, token: str) -> Identity:
        jwt = self._jwt
        if len(token) > MAX_TOKEN_BYTES or token.count(".") != 2:
            raise OIDCError("not a compact JWS")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise OIDCError("malformed header") from exc
        alg = header.get("alg")
        if alg not in ALLOWED_ALGS:  # rejects none, HS256/384/512, PS*, EdDSA, ...
            raise OIDCError(f"algorithm {alg!r} not allowed")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise OIDCError("missing kid")
        jwk = self._key(kid)
        if jwk.key_type != ALLOWED_ALGS[alg]:
            raise OIDCError("key type does not match algorithm")
        try:
            claims = jwt.decode(
                token,
                key=jwk.key,
                algorithms=[alg],
                audience=self.config.audience,
                issuer=self.config.issuer,
                leeway=self.config.leeway,
                options={"require": ["exp", "iat", "iss", "aud", "sub"], "verify_signature": True},
            )
        except jwt.PyJWTError as exc:
            raise OIDCError(f"{type(exc).__name__}") from exc
        iat = claims.get("iat")
        if not isinstance(iat, int | float) or iat > self._clock() + self.config.leeway:
            raise OIDCError("iat in the future")
        return Identity(str(claims["sub"]), self._role(claims), self._clusters(claims))

    def _role(self, claims: dict[str, Any]) -> str:
        raw = claims.get(self.config.role_claim)
        values = [raw] if isinstance(raw, str) else [v for v in raw if isinstance(v, str)] if isinstance(raw, list) else []
        roles = {self.config.role_map.get(v) if self.config.role_map else v for v in values}
        for role in ROLE_PRIORITY:
            if role in roles:
                return role
        raise OIDCError("no recognised role claim")

    def _clusters(self, claims: dict[str, Any]) -> frozenset[str]:
        raw = claims.get(self.config.clusters_claim)
        if isinstance(raw, str):
            values = raw.split("|")
        elif isinstance(raw, list) and all(isinstance(v, str) for v in raw):
            values = list(raw)
        else:
            raise OIDCError("missing clusters claim")
        clusters = frozenset(v for v in values if v and len(v) <= 128)
        if not clusters:
            raise OIDCError("empty clusters claim")
        if "*" in clusters and not self.config.allow_wildcard:
            raise OIDCError("wildcard cluster claim refused")
        return clusters
