from __future__ import annotations

import itertools

from afterlock.engine import MODE_FINAL_STATE, MODE_NO_LIFECYCLE, MODE_SNAPSHOT
from afterlock.planner import PlannerConfig, action_cost, candidate_actions, plan
from afterlock.results import analyze

from conftest import case


def test_flagship_plan_is_targeted_and_preserves_release() -> None:
    p = plan(case("residual-token"))
    assert p["search"]["status"] == "optimal_within_bounds"
    kinds = [a["kind"] for a in p["best_plan"]["actions"]]
    assert kinds == ["remove_binding", "delete_pods_except", "rotate_downstream_credential"]
    assert all(p["best_plan"]["legitimate_operations"].values())
    # the naive baseline breaks the legitimate workload and still misses the copied credential
    assert not all(p["naive_containment"]["legitimate_operations"].values())
    assert p["naive_containment"]["objectives"]["protect-canary"] == "violated"
    # the proposed (single-step) remediation is not a containment
    assert p["proposed_remediation"]["model_conclusion"] == "residual_path"


def test_plan_matches_exhaustive_optimum_on_small_candidate_set() -> None:
    inp = case("residual-token")
    cands = candidate_actions(inp)
    p = plan(inp, PlannerConfig(max_length=3))
    best = None
    for n in range(1, 4):
        for seq in itertools.permutations(cands, n):
            b = analyze(inp.with_remediation(seq))
            if b["conclusion"]["model"] == "contained_within_scope" and all(o["preserved"] for o in b["legitimate_operations"]):
                c = sum(action_cost(a, {}) for a in seq)
                best = c if best is None else min(best, c)
    assert best is not None and p["best_plan"]["cost"] == best


def test_incomplete_search_is_labelled() -> None:
    p = plan(case("residual-token"), PlannerConfig(max_evaluations=1))
    assert p["search"]["status"] == "incomplete_search"
    assert p["best_plan"] is None
    assert "not evidence" in p["search"]["statement"]


def test_candidates_are_deterministic() -> None:
    assert candidate_actions(case("residual-token")) == candidate_actions(case("residual-token"))


def test_baselines_make_the_false_containment_visible() -> None:
    inp = case("residual-token")
    assert analyze(inp)["conclusion"]["model"] == "residual_path"
    # snapshot-only analysis discards history and wrongly reports containment
    assert analyze(inp, MODE_SNAPSHOT)["conclusion"]["model"] == "contained_within_scope"
    # ignoring action ordering misses the defender race
    race = case("defender-race")
    assert analyze(race)["conclusion"]["model"] == "residual_path"
    assert analyze(race, MODE_FINAL_STATE)["conclusion"]["model"] == "contained_within_scope"
    # ignoring credential lifecycle over-reports residual access after expiry
    wait = case("token-expiry-wait")
    assert analyze(wait)["conclusion"]["model"] == "contained_within_scope"
    assert analyze(wait, MODE_NO_LIFECYCLE)["conclusion"]["model"] == "residual_path"
