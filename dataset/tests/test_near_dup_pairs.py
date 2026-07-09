from src import normalize_utils
from scripts import build_near_dup_pairs
from src.schema import validate_record

def test_near_dup_pairs(monkeypatch, tmp_path):
    monkeypatch.setattr(normalize_utils, "ROOT", tmp_path, raising=False)
    build_near_dup_pairs.main()
    recs = normalize_utils.read_slice("near_dup_pairs")
    benign = [r for r in recs if r["label"]["attack_family"] == "benign"]
    prec = [r for r in recs if r["label"]["attack_stage_precursor"] is True]
    assert benign and prec
    assert all(not r["label"]["is_malicious"] for r in recs)
    assert all(r["license_status"] == "ok" for r in recs)
    assert all(r["label"]["confidence"] in ("high", "medium") for r in recs)
    assert all(validate_record(r) == [] for r in recs)
    # a suspicious-but-benign example
    assert any("env" in (r["turns"][0]["raw_text"]) for r in benign)
    # a precursor example
    assert any("whoami" in (r["turns"][0]["raw_text"]) for r in prec)
