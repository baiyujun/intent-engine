import pathlib
from src import normalize_utils
from scripts import normalize_mitre_attack
from src.schema import validate_record

def test_normalize_mitre_attack(monkeypatch, tmp_path):
    monkeypatch.setattr(normalize_mitre_attack, "RAW_DIR", pathlib.Path("tests/fixtures/mitre_attack"))
    monkeypatch.setattr(normalize_utils, "ROOT", tmp_path, raising=False)
    normalize_mitre_attack.main()
    recs = normalize_utils.read_slice("mitre_attack_samples")
    assert recs
    assert all(r["label"]["confidence"] == "low" for r in recs)
    assert all(r["license_status"] == "needs_confirmation" for r in recs)
    assert all("needs review" in (r["notes"] or "") for r in recs)
    assert all(validate_record(r) == [] for r in recs)
