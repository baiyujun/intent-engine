import pathlib
from src import normalize_utils
from scripts import normalize_lolbas
from src.schema import validate_record

def test_normalize_lolbas(monkeypatch, tmp_path):
    monkeypatch.setattr(normalize_lolbas, "RAW_DIR", pathlib.Path("tests/fixtures/lolbas"))
    monkeypatch.setattr(normalize_utils, "ROOT", tmp_path, raising=False)
    normalize_lolbas.main()
    recs = normalize_utils.read_slice("lolbas")
    fams = {r["label"]["attack_family"] for r in recs}
    assert "network_request" in fams and "defense_evasion" in fams
    assert all(r["structured_action"]["action_type"] == "exec" for r in recs)
    assert all(r["license_status"] == "ok" for r in recs)
    assert all(validate_record(r) == [] for r in recs)
