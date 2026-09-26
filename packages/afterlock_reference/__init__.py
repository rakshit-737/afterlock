"""Independent reference checker for AFTERLOCK.

INDEPENDENCE RULE: this package must not import ``afterlock``. It parses the
raw ``afterlock.analysis-input/1`` JSON itself and re-implements the supported
semantics in a deliberately different style (explicit states, single-step
transitions, breadth-first search). Shared code would let one bug agree
with itself. See docs/architecture/reference-checker.md.

Two entry points:

  explore(raw_input)            explicit-state BFS over every interleaving of
                                single attacker actions and defender steps
  verify_witnesses(raw, bundle) replay each witness in a result bundle step by
                                step against independently recomputed state
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from typing import Any

__all__ = ["explore", "verify_witnesses", "ReferenceLimits"]

SA_PREFIX = "system:serviceaccount:"


class ReferenceLimits:
    def __init__(self, max_states: int = 200_000, max_live_attacker_workloads_per_sa: int = 2) -> None:
        self.max_states = max_states
        self.max_live = max_live_attacker_workloads_per_sa


# ---------------------------------------------------------------------------
# frozen environment encoding
#
# env = (time, sas, pods, ctrls, bindings, secrets, services, counters)
#   sas      frozenset[(ns, name, uid)]
#   pods     frozenset[(uid, ns, name, sa, auds, ctrl_uid|None)]
#   ctrls    frozenset[(uid, ns, name, sa, auds)]
#   bindings frozenset[(ns|None, name)]           (binding bodies are static)
#   secrets  frozenset[(ns, name, version)]
#   services frozenset[(name, src_ns, src_name, accepted, delay, old)]
#            delay = seconds a rotation takes to reach the service (0: atomic)
#            old   = frozenset[(version, deadline)]: superseded versions the
#                    service keeps honouring while time < deadline
#   counters frozenset[(ctrl_uid, k)]


def _env0(inv: dict[str, Any], t: int) -> tuple:
    return (
        t,
        frozenset((s["namespace"], s["name"], s["uid"]) for s in inv.get("service_accounts", [])),
        frozenset(
            (p["uid"], p["namespace"], p["name"], p["service_account"], tuple(p.get("token_audiences", [])), p.get("controller_uid"))
            for p in inv.get("pods", [])
        ),
        frozenset(
            (c["uid"], c["namespace"], c["name"], c["service_account"], tuple(c.get("token_audiences", [])))
            for c in inv.get("controllers", [])
        ),
        frozenset((b.get("namespace"), b["name"]) for b in inv.get("bindings", [])),
        frozenset((s["namespace"], s["name"], s["version"]) for s in inv.get("secrets", [])),
        frozenset(
            (s["name"], s["source_namespace"], s["source_secret"], s["accepted_version"], int(s.get("rotation_propagation_seconds") or 0), frozenset())
            for s in inv.get("services", [])
        ),
        frozenset(),
    )


class _Static:
    """Parts of the input that never change during exploration."""

    def __init__(self, raw: dict[str, Any]) -> None:
        inv = raw["inventory"]
        self.roles = {(r.get("namespace"), r["name"]): r.get("rules", []) for r in inv.get("roles", [])}
        self.binding_body = {(b.get("namespace"), b["name"]): b for b in inv.get("bindings", [])}
        self.admission = list(inv.get("admission_policies", []))
        prof = raw["profile"]
        self.api_auds = list(prof["api_audiences"])
        self.ttl = int(prof["projected_token_ttl_seconds"])
        self.creds = {c["id"]: c for c in raw.get("credentials", [])}


def _sa_of(username: str) -> tuple[str, str] | None:
    if not username.startswith(SA_PREFIX):
        return None
    bits = username[len(SA_PREFIX):].split(":")
    return (bits[0], bits[1]) if len(bits) == 2 and all(bits) else None


def _rule_allows(rule: dict[str, Any], verb: str, resource: str, name: str | None) -> bool:
    verbs, res = rule["verbs"], rule["resources"]
    if not ("*" in verbs or verb in verbs):
        return False
    if not ("*" in res or resource in res):
        return False
    names = rule.get("resource_names")
    if names is None:
        return True
    return name is not None and name in names


def _granting(st: _Static, env: tuple, user: str, verb: str, resource: str, ns: str, name: str | None) -> set[str]:
    sa = _sa_of(user)
    out = set()
    for key in env[4]:
        b = st.binding_body[key]
        bns = b.get("namespace")
        if bns is not None and bns != ns:
            continue
        subject_ok = False
        for s in b.get("subjects", []):
            k = s["kind"]
            if k == "User" and s["name"] == user:
                subject_ok = True
            elif k == "ServiceAccount" and sa == (s.get("namespace"), s["name"]):
                subject_ok = True
            elif k == "Group" and (
                s["name"] == "system:authenticated"
                or (sa is not None and s["name"] in ("system:serviceaccounts", "system:serviceaccounts:" + sa[0]))
            ):
                subject_ok = True
        if not subject_ok:
            continue
        rules = st.roles.get((bns if b["role_kind"] == "Role" else None, b["role_name"]))
        if rules is None:
            continue
        if any(_rule_allows(r, verb, resource, name) for r in rules):
            out.add(f"{bns or '<cluster>'}/{b['name']}")
    return out


def _can_read(st: _Static, env: tuple, user: str, ns: str, name: str) -> bool:
    """S-SEC-1: Kubernetes returns Secret data for get, list and watch (list/watch can be
    narrowed to one object with a metadata.name field selector, so resourceNames apply)."""
    return any(_granting(st, env, user, v, "secrets", ns, name) for v in ("watch", "list", "get"))


def _cred_ok(st: _Static, env: tuple, cred: tuple) -> str:
    """'ok' | 'bad' | 'unsupported'. cred = (id, kind, user, sa_uid, pod_uid, aud, exp)."""
    _, kind, user, sa_uid, pod_uid, aud, exp = cred
    if kind != "sa_token":
        return "unsupported"
    sa = _sa_of(user)
    if sa is None:
        return "unsupported"
    if exp is not None and env[0] >= exp:
        return "bad"
    if aud not in st.api_auds:
        return "bad"
    match = [s for s in env[1] if (s[0], s[1]) == sa]
    if not match or (sa_uid is not None and match[0][2] != sa_uid):
        return "bad"
    if pod_uid is not None:
        pods = [p for p in env[2] if p[0] == pod_uid]
        if not pods or (pods[0][1], pods[0][3]) != sa:
            return "bad"
    return "ok"


def _admission(st: _Static, creator: str, ns: str, sa: str) -> str:
    verdict = "allow"
    for p in st.admission:
        if p["namespace"] != ns:
            continue
        if p["kind"] != "service-account-restriction":
            return "unsupported"
    for p in st.admission:
        if p["namespace"] != ns:
            continue
        allowed = p.get("allowed_service_accounts") or {}
        names = allowed.get(creator, allowed.get("*"))
        if names is not None and "*" not in names and sa not in names:
            verdict = "deny"
    return verdict


def _honours(env: tuple, svc: tuple, version: int) -> bool:
    """Does downstream service ``svc`` accept credential ``version`` at env time?"""
    if svc[3] == version:
        return True
    for old_version, deadline in svc[5]:
        if old_version == version and env[0] < deadline:
            return True
    return False


def _reconcile(env: tuple) -> tuple:
    t, sas, pods, ctrls, binds, secs, svcs, counters = env
    pods = set(pods)
    cnt = dict(counters)
    for c in sorted(ctrls):
        if any(p[5] == c[0] for p in pods):
            continue
        k = cnt.get(c[0], 0) + 1
        taken = {p[0] for p in pods}
        while f"{c[0]}-p{k}" in taken:  # never shadow an existing Pod's UID
            k += 1
        cnt[c[0]] = k
        pods.add((f"{c[0]}-p{k}", c[1], f"{c[2]}-p{k}", c[3], c[4], c[0]))
    return (t, sas, frozenset(pods), ctrls, binds, secs, svcs, frozenset(cnt.items()))


def _defend(env: tuple, a: dict[str, Any]) -> tuple:
    t, sas, pods, ctrls, binds, secs, svcs, counters = env
    k = a["kind"]
    if k == "remove_binding":
        binds = binds - {(a.get("namespace"), a["name"])}
    elif k == "delete_pod":
        pods = frozenset(p for p in pods if p[0] != a["uid"])
    elif k == "delete_controller":
        ctrls = frozenset(c for c in ctrls if c[0] != a["uid"])
        pods = frozenset(p for p in pods if p[5] != a["uid"])
    elif k == "delete_pods_except":
        keep = set(a.get("keep_uids", []))
        pods = frozenset(p for p in pods if not (p[1] == a["namespace"] and p[3] == a["service_account"] and p[0] not in keep))
    elif k == "delete_controllers_except":
        keep = set(a.get("keep_uids", []))
        gone = {c[0] for c in ctrls if c[1] == a["namespace"] and c[3] == a["service_account"] and c[0] not in keep}
        ctrls = frozenset(c for c in ctrls if c[0] not in gone)
        pods = frozenset(p for p in pods if p[5] not in gone)
    elif k == "delete_service_account":
        sas = frozenset(s for s in sas if (s[0], s[1]) != (a["namespace"], a["name"]))
    elif k == "rotate_downstream_credential":
        svc = [s for s in svcs if s[0] == a["service"]]
        if svc:
            name, sns, sname, acc, delay, old = svc[0]
            cur = [s for s in secs if (s[0], s[1]) == (sns, sname)]
            new = max([acc] + [c[2] for c in cur]) + 1
            secs = frozenset(s for s in secs if (s[0], s[1]) != (sns, sname)) | ({(sns, sname, new)} if cur else set())
            if delay:
                old = old | {(acc, t + delay)}
            svcs = (svcs - {svc[0]}) | {(name, sns, sname, new, delay, old)}
    elif k == "wait":
        t = t + int(a["seconds"])
    else:
        raise ValueError(f"reference checker: unsupported defender action {k}")
    return (t, sas, pods, ctrls, binds, secs, svcs, counters)


# ---------------------------------------------------------------------------
# explicit-state exploration

# attacker = (creds, controlled_pods, controlled_ctrls, knowledge)
#   creds frozenset[(id, kind, user, sa_uid, pod_uid, aud, exp)]


def _attacker_steps(st: _Static, env: tuple, att: tuple, lim: ReferenceLimits, creation: bool, unknown: set) -> Iterable[tuple[tuple, tuple]]:
    creds, cpods, cctrls, know = att
    live_pods = {p[0]: p for p in env[2]}
    # obtain projected tokens from controlled live pods
    for uid in sorted(cpods):
        p = live_pods.get(uid)
        if p is None:
            continue
        sa = [s for s in env[1] if (s[0], s[1]) == (p[1], p[3])]
        if not sa:
            continue
        for aud in p[4] or (st.api_auds[0],):
            c = (f"projected:{uid}:{aud}", "sa_token", SA_PREFIX + p[1] + ":" + p[3], sa[0][2], uid, aud, env[0] + st.ttl)
            if c not in creds:
                yield env, (creds | {c}, cpods, cctrls, know)
    # pods owned by controlled controllers
    for p in sorted(env[2]):
        if p[5] is not None and p[5] in cctrls and p[0] not in cpods:
            yield env, (creds, cpods | {p[0]}, cctrls, know)
    namespaces = sorted({s[0] for s in env[1]} | {p[1] for p in env[2]})
    for c in sorted(creds, key=lambda x: (x[0], x[6] or 0)):
        ok = _cred_ok(st, env, c)
        if ok == "unsupported":
            unknown.add(("unsupported_credential", c[0]))
            continue
        if ok != "ok":
            continue
        user = c[2]
        for s in sorted(env[5]):
            if _can_read(st, env, user, s[0], s[1]):
                fact = (s[0], s[1], s[2])
                if fact not in know:
                    yield env, (creds, cpods, cctrls, know | {fact})
        for p in sorted(env[2]):
            if p[0] not in cpods and _granting(st, env, user, "create", "pods/exec", p[1], p[2]):
                yield env, (creds, cpods | {p[0]}, cctrls, know)
        if not creation:
            continue
        for ns in namespaces:
            for kind, resource in (("pod", "pods"), ("ctrl", "deployments")):
                if not _granting(st, env, user, "create", resource, ns, None):
                    continue
                for (sns, sname, _) in sorted(env[1]):
                    if sns != ns:
                        continue
                    verdict = _admission(st, user, ns, sname)
                    if verdict == "unsupported":
                        unknown.add(("unsupported_admission", ns, user, sname))
                        continue
                    if verdict == "deny":
                        continue
                    if kind == "pod":
                        mine = [p for p in env[2] if p[0].startswith("ref-pod:") and p[1] == ns and p[3] == sname]
                        if len(mine) >= lim.max_live:
                            continue
                        n = dict(env[7]).get("ref-pod-seq", 0)
                        uid = f"ref-pod:{ns}:{sname}:{n}"
                        new_env = env[:2] + (env[2] | {(uid, ns, uid, sname, (), None)},) + env[3:7] + (
                            frozenset((dict(env[7]) | {"ref-pod-seq": dict(env[7]).get("ref-pod-seq", 0) + 1}).items()),
                        )
                        yield new_env, (creds, cpods | {uid}, cctrls, know)
                    else:
                        mine_c = [x for x in env[3] if x[0].startswith("ref-deploy:") and x[1] == ns and x[3] == sname]
                        if len(mine_c) >= lim.max_live:
                            continue
                        n = dict(env[7]).get("ref-deploy-seq", 0)
                        cuid = f"ref-deploy:{ns}:{sname}:{n}"
                        cnt = dict(env[7])
                        cnt["ref-deploy-seq"] = n + 1
                        new_env = env[:3] + (env[3] | {(cuid, ns, cuid, sname, ())},) + env[4:7] + (frozenset(cnt.items()),)
                        new_env = _reconcile(new_env)
                        yield new_env, (creds, cpods, cctrls | {cuid}, know)


def _goals(st: _Static, env: tuple, att: tuple, raw: dict[str, Any]) -> set[tuple]:
    creds, _, _, know = att
    out = set()
    for o in raw["objectives"]:
        if o["kind"] == "no_secret_read":
            ns, name = o["namespace"], o["secret"]
            if not any((s[0], s[1]) == (ns, name) for s in env[5]):
                continue
            for c in creds:
                if _cred_ok(st, env, c) == "ok" and _can_read(st, env, c[2], ns, name):
                    out.add(o["id"])
                    break
        else:
            for svc in env[6]:
                if svc[0] != o["service"]:
                    continue
                if any((k[0], k[1]) == (svc[1], svc[2]) and _honours(env, svc, k[2]) for k in know):
                    out.add(o["id"])
    return out


def _initial(raw: dict[str, Any], view: str) -> tuple[tuple, list[tuple]]:
    creds, cpods, cctrls, know = set(), set(), set(), set()
    hist = []
    table = {c["id"]: c for c in raw.get("credentials", [])}
    for f in raw.get("initial_facts", []):
        if view == "evidence_supported" and f["status"] == "inferred":
            continue
        a = f["args"]
        if f["kind"] == "possesses_credential":
            c = table[a[0]]
            creds.add((c["id"], c["kind"], c["username"], c.get("sa_uid"), c.get("bound_pod_uid"), c["audience"], c.get("expires_at")))
        elif f["kind"] == "controls_pod":
            cpods.add(a[0])
        elif f["kind"] == "controls_controller":
            cctrls.add(a[0])
        elif f["kind"] == "knows_secret":
            know.add((a[0], a[1], int(a[2])))
        elif f["kind"] == "historical_pod":
            hist.append(tuple(a))
    return (frozenset(creds), frozenset(cpods), frozenset(cctrls), frozenset(know)), hist


def explore(raw: dict[str, Any], limits: ReferenceLimits | None = None) -> dict[str, Any]:
    """Explore all interleavings. Returns per-view reachable objectives at the final phase."""
    lim = limits or ReferenceLimits()
    st = _Static(raw)
    actions = raw.get("remediation", [])
    out: dict[str, Any] = {"views": {}}
    for view in ("evidence_supported", "conservative_possible"):
        unknown: set = set()
        att, hist = _initial(raw, view)
        env = _env0(raw["inventory"], int(raw["analysis_time"]))
        if view == "conservative_possible" and hist:
            henv = env[:2] + (env[2] | {(u, ns, u, sa, (), None) for (u, ns, sa) in hist if u not in {p[0] for p in env[2]}},) + env[3:]
            creds, cpods, cctrls, know = att
            att = (creds, cpods | {h[0] for h in hist}, cctrls, know)
            # saturate history phase without workload creation
            # Possible history: every supported action, creation included. Objects
            # created here are not in today's inventory, so only the attacker-side
            # union carries forward; the main phase starts from the inventory env.
            history_complete = True
            hseen = {(henv, att)}
            hq = deque([(henv, att)])
            union = att
            while hq:
                e, a = hq.popleft()
                union = (union[0] | a[0], union[1] | a[1], union[2] | a[2], union[3] | a[3])
                for e2, a2 in _attacker_steps(st, e, a, lim, True, unknown):
                    if len(hseen) >= lim.max_states:
                        history_complete = False
                        break
                    if (e2, a2) not in hseen:
                        hseen.add((e2, a2))
                        hq.append((e2, a2))
            att = union
        else:
            history_complete = True
        env = _reconcile(env)
        start = (0, env, att)
        seen = {start}
        q = deque([start])
        final_goals: set[Any] = set()
        complete = True
        while q:
            phase, e, a = q.popleft()
            if phase == len(actions):
                final_goals |= _goals(st, e, a, raw)
            nxt = []
            for e2, a2 in _attacker_steps(st, e, a, lim, True, unknown):
                nxt.append((phase, e2, a2))
            if phase < len(actions):
                nxt.append((phase + 1, _reconcile(_defend(e, actions[phase])), a))
            for s in nxt:
                if s in seen:
                    continue
                if len(seen) >= lim.max_states:
                    complete = False
                    break
                seen.add(s)
                q.append(s)
            if not complete:
                break
        out["views"][view] = {
            "reachable_objectives": sorted(final_goals),
            "states": len(seen),
            "complete": complete and history_complete,
            "unknown": sorted(str(u) for u in unknown),
        }
    return out


# ---------------------------------------------------------------------------
# witness verification


def _timeline(raw: dict[str, Any], created: dict[int, list[tuple[str, tuple]]]) -> list[tuple]:
    """Env at each interval, with witness-declared model objects added when created."""
    envs = []
    env = _reconcile(_env0(raw["inventory"], int(raw["analysis_time"])))
    actions = raw.get("remediation", [])
    for i in range(len(actions) + 1):
        if i > 0:
            env = _reconcile(_defend(env, actions[i - 1]))
        for kind, obj in created.get(i, []):
            if kind == "pod":
                env = env[:2] + (env[2] | {obj},) + env[3:]
            else:
                cnt = dict(env[7])
                cnt[obj[0]] = -1
                env = env[:3] + (env[3] | {obj},) + env[4:7] + (frozenset(cnt.items()),)
                env = _reconcile(env)
        envs.append(env)
    return envs


def _history_env(raw: dict[str, Any], facts_in: dict[tuple, Any], created: list[tuple[str, tuple]]) -> tuple:
    env = _reconcile(_env0(raw["inventory"], int(raw["analysis_time"])))
    hist = [k[1] for k in facts_in if k[0] == "historical_pod"]
    env = env[:2] + (env[2] | {(u, ns, u, sa, (), None) for (u, ns, sa) in hist},) + env[3:]
    for kind, obj in created:
        if kind == "pod":
            env = env[:2] + (env[2] | {obj},) + env[3:]
        else:
            cnt = dict(env[7])
            cnt[obj[0]] = -1
            env = _reconcile(env[:3] + (env[3] | {obj},) + env[4:7] + (frozenset(cnt.items()),))
    return env


def _parse_model_uid(uid: str) -> tuple[str, str, int]:
    _, ns, sa, i = uid.split(":")
    return ns, sa, int(i[1:])


def verify_witnesses(raw: dict[str, Any], bundle: dict[str, Any]) -> dict[str, Any]:
    st = _Static(raw)
    facts_in = {(f["kind"], tuple(f["args"])): f for f in raw.get("initial_facts", [])}
    n = len(raw.get("remediation", []))
    report: dict[str, Any] = {}
    for w in bundle.get("witnesses", []):
        problems: list[str] = []
        created: dict[int, list[tuple[str, tuple]]] = {}
        for s in w["steps"]:
            f = s["fact"]
            if s["rule"] == "R-CREATE-POD":
                ns, sa, i = _parse_model_uid(f[1])
                created.setdefault(i, []).append(("pod", (f[1], ns, f[1], sa, (), None)))
            elif s["rule"] == "R-CREATE-CONTROLLER":
                ns, sa, i = _parse_model_uid(f[1])
                created.setdefault(i, []).append(("ctrl", (f[1], ns, f[1], sa, ())))
        envs = _timeline(raw, created)
        established: set[tuple] = set()
        derived_creds: dict[str, tuple] = {}
        for s in w["steps"]:
            fact = tuple(s["fact"])
            i = s["interval"]
            for p in s["premises"]:
                if tuple(p) not in established:
                    problems.append(f"{fact}: premise {p} not established earlier")
            if s["rule"] == "EVIDENCE":
                mapping = {"possesses": "possesses_credential", "controls_pod": "controls_pod",
                           "controls_controller": "controls_controller", "knows_secret": "knows_secret"}
                src = facts_in.get((mapping.get(fact[0], "?"), fact[1:]))
                if src is None:
                    problems.append(f"{fact}: not present in input evidence")
                elif src is not None and w["view"] == "evidence_supported" and src["status"] == "inferred":
                    problems.append(f"{fact}: inferred fact used in evidence-supported witness")
                established.add(fact)
                continue
            if i < -1 or i > n:
                problems.append(f"{fact}: interval {i} out of range")
                continue
            env = envs[i] if i >= 0 else _history_env(raw, facts_in, created.get(-1, []))
            for c in s["conditions"]:
                problems += _check(st, env, c, fact, derived_creds)
            if s["rule"] == "R-OBTAIN-PROJECTED-TOKEN":
                pod = [p for p in env[2] if p[0] == s["premises"][0][1]]
                if not pod:
                    problems.append(f"{fact}: source pod absent")
                else:
                    p = pod[0]
                    sa_rows = [x for x in env[1] if (x[0], x[1]) == (p[1], p[3])]
                    aud = fact[1][len("projected:" + p[0] + ":"):]
                    if not sa_rows:
                        problems.append(f"{fact}: service account absent")
                    else:
                        derived_creds[fact[1]] = (fact[1], "sa_token", SA_PREFIX + p[1] + ":" + p[3], sa_rows[0][2], p[0], aud, env[0] + st.ttl)
            if s["rule"] == "R-READ-SECRET":
                sec = [x for x in env[5] if (x[0], x[1]) == (fact[1], fact[2])]
                if not sec or (fact[0] == "knows_secret" and str(sec[0][2]) != fact[3]):
                    problems.append(f"{fact}: secret/version mismatch at interval {i}")
            established.add(fact)
        goal = tuple(w["goal"])
        if goal not in established:
            problems.append("goal not derived by witness")
        goal_steps = [s for s in w["steps"] if tuple(s["fact"]) == goal]
        if goal_steps and goal_steps[-1]["interval"] != n:
            problems.append(f"goal derived at interval {goal_steps[-1]['interval']}, not the final interval {n}")
        report[w["id"]] = {"valid": not problems, "problems": problems}
    return report


def _check(st: _Static, env: tuple, c: dict[str, Any], fact: tuple, derived: dict[str, tuple]) -> list[str]:
    k = c["check"]
    if k == "credential_usable":
        cid = c["credential"]
        if cid in derived:
            cred = derived[cid]
        elif cid in st.creds:
            x = st.creds[cid]
            cred = (x["id"], x["kind"], x["username"], x.get("sa_uid"), x.get("bound_pod_uid"), x["audience"], x.get("expires_at"))
        else:
            return [f"{fact}: credential {cid} unknown to checker"]
        return [] if _cred_ok(st, env, cred) == "ok" else [f"{fact}: credential {cid} not usable at t={env[0]}"]
    if k == "authorized":
        grants = _granting(st, env, c["username"], c["verb"], c["resource"], c["namespace"], c["name"])
        if not grants:
            return [f"{fact}: {c['username']} not authorized to {c['verb']} {c['resource']}"]
        if not set(c["via"]) <= grants:
            return [f"{fact}: claimed bindings {c['via']} not all granting ({sorted(grants)})"]
        return []
    if k == "admission_allows":
        v = _admission(st, c["creator"], c["namespace"], c["service_account"])
        return [] if v == "allow" else [f"{fact}: admission verdict {v}"]
    if k == "service_account_exists":
        ok = any((s[0], s[1]) == (c["namespace"], c["name"]) and ("uid" not in c or s[2] == c["uid"]) for s in env[1])
        return [] if ok else [f"{fact}: service account {c['namespace']}/{c['name']} absent"]
    if k == "pod_exists":
        return [] if any(p[0] == c["pod"] for p in env[2]) else [f"{fact}: pod {c['pod']} absent"]
    if k == "pod_owned_by_controller":
        return [] if any(p[0] == c["pod"] and p[5] == c["controller"] for p in env[2]) else [f"{fact}: ownership mismatch"]
    if k == "secret_version":
        return [] if (c["namespace"], c["name"], c["version"]) in env[5] else [f"{fact}: secret version mismatch"]
    if k == "service_sources":
        return [] if any(s[0] == c["service"] and (s[1], s[2]) == (c["namespace"], c["secret"]) for s in env[6]) else [f"{fact}: service does not source secret"]
    if k == "service_accepts":
        return [] if any(s[0] == c["service"] and _honours(env, s, int(c["version"])) for s in env[6]) else [f"{fact}: service does not accept version"]
    return [f"{fact}: unknown condition {k}"]
