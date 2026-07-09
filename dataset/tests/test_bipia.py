import pathlib
from src import normalize_utils
from scripts import normalize_bipia
from src.schema import validate_record

def test_normalize_bipia_held_out(monkeypatch, tmp_path):
    monkeypatch.setattr(normalize_bipia, "RAW_DIR", pathlib.Path("tests/fixtures/bipia"))
    monkeypatch.setattr(normalize_utils, "ROOT", tmp_path, raising=False)
    normalize_bipia.main()
    recs = normalize_utils.read_slice("bipia")
    assert recs
    assert all(r["label"]["attack_family"].startswith("indirect_injection") for r in recs)
    assert all(r["license_status"] == "needs_confirmation" for r in recs)
    assert any(r["label"]["attack_family"] == "indirect_injection_multimodal" for r in recs)
    assert all(validate_record(r) == [] for r in recs)
