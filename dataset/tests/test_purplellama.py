import pathlib
from src import normalize_utils
from scripts import normalize_purplellama
from src.schema import validate_record

def test_normalize_purplellama(monkeypatch, tmp_path):
    monkeypatch.setattr(normalize_purplellama, "RAW_DIR", pathlib.Path("tests/fixtures/purplellama"))
    monkeypatch.setattr(normalize_utils, "ROOT", tmp_path, raising=False)
    normalize_purplellama.main()
    recs = normalize_utils.read_slice("purplellama")
    assert len(recs) == 2
    assert all(r["label"]["is_malicious"] for r in recs)
    assert all(r["license_status"] == "needs_confirmation" for r in recs)
    fams = {r["label"]["attack_family"] for r in recs}
    assert fams <= {"indirect_injection", "goal_hijack", "prompt_injection", "agent_misalignment"}
    assert all(validate_record(r) == [] for r in recs)
