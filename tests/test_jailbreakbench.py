import pathlib
from src import normalize_utils
from scripts import normalize_jailbreakbench
from src.schema import validate_record

def test_normalize_jailbreakbench(monkeypatch, tmp_path):
    monkeypatch.setattr(normalize_jailbreakbench, "RAW_DIR", pathlib.Path("tests/fixtures/jailbreakbench"))
    monkeypatch.setattr(normalize_utils, "ROOT", tmp_path, raising=False)
    normalize_jailbreakbench.main()
    recs = normalize_utils.read_slice("jailbreakbench")
    assert len(recs) == 2
    assert all(r["license_status"] == "ok" for r in recs)
    assert all(r["label"]["attack_family"].startswith("jailbreak_") for r in recs)
    assert all("domain-gap" in (r["notes"] or "") for r in recs)
    assert all(validate_record(r) == [] for r in recs)
