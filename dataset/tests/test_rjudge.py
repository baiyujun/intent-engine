import pathlib
from src import normalize_utils
from scripts import normalize_rjudge
from src.schema import validate_record

def test_normalize_rjudge(monkeypatch, tmp_path):
    monkeypatch.setattr(normalize_rjudge, "RAW_DIR", pathlib.Path("tests/fixtures/rjudge"))
    monkeypatch.setattr(normalize_rjudge, "DATA_DIR", pathlib.Path("tests/fixtures/rjudge"))
    monkeypatch.setattr(normalize_utils, "ROOT", tmp_path, raising=False)
    normalize_rjudge.main()
    recs = normalize_utils.read_slice("rjudge")
    assert len(recs) == 2
    unsafe = [r for r in recs if r["label"]["is_malicious"]]
    safe = [r for r in recs if not r["label"]["is_malicious"]]
    assert unsafe and safe
    # purpose_capability_consistent tracks label: False for unsafe, True for safe
    assert all(r["label"]["purpose_capability_consistent"] is False for r in unsafe)
    assert all(r["label"]["purpose_capability_consistent"] is True for r in safe)
    # is_malicious matches label semantics (unsafe=True, safe=False)
    assert all(r["modality"] == "multi_turn" for r in recs)
    assert all(r["license_status"] == "needs_confirmation" for r in recs)
    assert all(r["label"]["confidence"] == "high" for r in recs)
    assert all(r["label"]["risk_category"] in ("unauthorized_action", "benign") for r in recs)
    # attack_family populated (real attack_type or goal_hijack/benign fallback)
    assert all(r["label"]["attack_family"] for r in recs)
    assert all(validate_record(r) == [] for r in recs)
    # turns are non-empty and have valid roles
    for r in recs:
        assert r["turns"], "record must have at least one turn"
        for t in r["turns"]:
            assert t["role"] in ("user", "agent_plan")
            assert t["instruction_origin"] == "user_direct"
