import pathlib
from src import normalize_utils
from scripts import normalize_jailbreakbench
from src.schema import validate_record

FIX = pathlib.Path("tests/fixtures/jailbreakbench")


def test_normalize_jailbreakbench(monkeypatch, tmp_path):
    # Point RAW_DIR at the real-format fixture tree (artifact JSONs, no CSVs).
    monkeypatch.setattr(normalize_jailbreakbench, "RAW_DIR", FIX)
    monkeypatch.setattr(normalize_utils, "ROOT", tmp_path, raising=False)
    normalize_jailbreakbench.main()
    recs = normalize_utils.read_slice("jailbreakbench")
    # GCG has 2 unique prompts, PAIR has 1 -> 3 records total.
    assert len(recs) == 3
    assert all(r["license_status"] == "ok" for r in recs)
    assert all(r["label"]["attack_family"].startswith("jailbreak_") for r in recs)
    assert all(r["label"]["is_malicious"] is True for r in recs)
    assert all(r["label"]["confidence"] == "high" for r in recs)
    assert all(r["modality"] == "single_turn" for r in recs)
    assert all(r["turns"][0]["instruction_origin"] == "user_direct" for r in recs)
    assert all("domain-gap" in (r["notes"] or "") for r in recs)
    # method names should appear in notes + attack_family.
    fams = {r["label"]["attack_family"] for r in recs}
    assert "jailbreak_gcg" in fams
    assert "jailbreak_pair" in fams
    assert all(validate_record(r) == [] for r in recs)
