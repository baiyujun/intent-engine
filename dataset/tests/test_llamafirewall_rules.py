import pathlib
from src import normalize_utils
from scripts import normalize_llamafirewall_rules
from src.schema import validate_record

def test_llamafirewall_held_out(monkeypatch, tmp_path):
    monkeypatch.setattr(normalize_llamafirewall_rules, "RAW_DIR", pathlib.Path("tests/fixtures/clawsentry_rules"))
    monkeypatch.setattr(normalize_utils, "ROOT", tmp_path, raising=False)
    normalize_llamafirewall_rules.main()
    recs = normalize_utils.read_slice("llamafirewall_rules")
    assert recs
    assert all(r["license_status"] == "needs_confirmation" for r in recs)
    assert all(r["label"]["confidence"] == "medium" for r in recs)
    assert all(validate_record(r) == [] for r in recs)
