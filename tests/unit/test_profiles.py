from conftest import ROOT


def test_reviewed_profile_matches_packaged_profile() -> None:
    a = (ROOT / "semantic_profiles/kubernetes/k8s-1.31-core-v1.json").read_bytes()
    b = (ROOT / "packages/afterlock/profiles/k8s-1.31-core-v1.json").read_bytes()
    assert a == b
