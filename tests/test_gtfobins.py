import pathlib
from src import normalize_utils
from scripts import normalize_gtfobins
from src.schema import validate_record

def test_normalize_gtfobins(monkeypatch, tmp_path):
    monkeypatch.setattr(normalize_gtfobins, "RAW_DIR", pathlib.Path("tests/fixtures/gtfobins"))
    monkeypatch.setattr(normalize_utils, "ROOT", tmp_path, raising=False)
    normalize_gtfobins.main()
    recs = normalize_utils.read_slice("gtfobins")
    fams = {r["label"]["attack_family"] for r in recs}
    assert {"shell_spawn", "privilege_escalation", "file_read"} <= fams
    assert all(r["structured_action"]["action_type"] == "exec" for r in recs)
    assert all(r["license_status"] == "ok" for r in recs)
    assert all(r["label"]["confidence"] == "medium" for r in recs)
    assert all(validate_record(r) == [] for r in recs)
