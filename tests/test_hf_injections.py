import pathlib
from src import normalize_utils
from scripts import normalize_hf_injections
from src.schema import validate_record

def test_normalize_hf_injections(monkeypatch, tmp_path):
    monkeypatch.setattr(normalize_hf_injections, "RAW_DIR", pathlib.Path("tests/fixtures/hf"))
    monkeypatch.setattr(normalize_utils, "ROOT", tmp_path, raising=False)
    normalize_hf_injections.main()
    recs = normalize_utils.read_slice("hf_injections")
    by_src = {}
    for r in recs: by_src.setdefault(r["source_dataset"], []).append(r)
    assert set(by_src) == {"hf_deepset", "hf_jayavibhav", "hf_imoxto"}
    assert all(r["license_status"] == "ok" for r in by_src["hf_deepset"])
    assert all(r["license_status"] == "needs_confirmation" for r in by_src["hf_jayavibhav"])
    assert all(r["license_status"] == "needs_confirmation" for r in by_src["hf_imoxto"])
    assert all(r["modality"] == "single_turn" for r in recs)
    assert all(r["turns"][0]["instruction_origin"] == "user_direct" for r in recs)
    assert all(validate_record(r) == [] for r in recs)
