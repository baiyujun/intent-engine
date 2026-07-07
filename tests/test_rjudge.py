import pathlib
from src import normalize_utils
from scripts import normalize_rjudge
from src.schema import validate_record

def test_normalize_rjudge(monkeypatch, tmp_path):
    monkeypatch.setattr(normalize_rjudge, "RAW_DIR", pathlib.Path("tests/fixtures/rjudge"))
    monkeypatch.setattr(normalize_utils, "ROOT", tmp_path, raising=False)
    normalize_rjudge.main()
    recs = normalize_utils.read_slice("rjudge")
    assert len(recs) == 2
    unsafe = [r for r in recs if r["label"]["is_malicious"]]
    safe = [r for r in recs if not r["label"]["is_malicious"]]
    assert unsafe and safe
    # purpose_capability_consistent should be False for the unsafe rm example
    assert any(r["label"]["purpose_capability_consistent"] is False for r in unsafe)
    assert all(r["modality"] == "multi_turn" for r in recs)
    assert all(r["license_status"] == "needs_confirmation" for r in recs)
    assert all(validate_record(r) == [] for r in recs)
