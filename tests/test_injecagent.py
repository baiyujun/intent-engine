import pathlib
from src import normalize_utils
from scripts import normalize_injecagent
from src.schema import validate_record

def test_normalize_injecagent(monkeypatch, tmp_path):
    monkeypatch.setattr(normalize_injecagent, "RAW_DIR", pathlib.Path("tests/fixtures/injecagent"))
    monkeypatch.setattr(normalize_utils, "ROOT", tmp_path, raising=False)
    normalize_injecagent.main()
    recs = normalize_utils.read_slice("injecagent")
    assert len(recs) == 3
    fams = {r["label"]["attack_family"] for r in recs}
    assert {"goal_hijack", "credential_exfil", "indirect_injection"} <= fams
    assert all(r["license_status"] == "ok" for r in recs)
    assert all(r["turns"][-1]["instruction_origin"] in ("tool_output", "retrieved_content") for r in recs)
    assert all(validate_record(r) == [] for r in recs)
