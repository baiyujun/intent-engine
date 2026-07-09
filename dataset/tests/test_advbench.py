import pathlib
from src import normalize_utils
from scripts import normalize_advbench
from src.schema import validate_record

def test_normalize_advbench(monkeypatch, tmp_path):
    monkeypatch.setattr(normalize_advbench, "RAW_DIR", pathlib.Path("tests/fixtures/advbench"))
    monkeypatch.setattr(normalize_utils, "ROOT", tmp_path, raising=False)
    normalize_advbench.main()
    recs = normalize_utils.read_slice("advbench")
    assert len(recs) == 2
    assert all(r["license_status"] == "ok" for r in recs)
    assert all(r["label"]["attack_family"] in ("advbench_gcg", "harmful_intent") for r in recs)
    assert all("domain-gap" in (r["notes"] or "") for r in recs)
    assert all(validate_record(r) == [] for r in recs)
