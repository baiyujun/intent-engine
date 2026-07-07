import pathlib
from src import normalize_utils
from scripts import normalize_agentdojo
from src.schema import validate_record

def test_normalize_agentdojo_fixture(monkeypatch, tmp_path):
    # point normalize at the committed fixture instead of raw/agentdojo
    monkeypatch.setattr(normalize_agentdojo, "RAW_DIR",
                        pathlib.Path("tests/fixtures/agentdojo"))
    monkeypatch.setattr(normalize_utils, "ROOT", tmp_path, raising=False)
    normalize_agentdojo.main()
    recs = normalize_utils.read_slice("agentdojo")
    assert len(recs) >= 2
    mal = [r for r in recs if r["label"]["is_malicious"]]
    ben = [r for r in recs if not r["label"]["is_malicious"]]
    assert mal and ben
    assert all(r["license_status"] == "ok" for r in recs)
    assert all(r["label"]["confidence"] == "high" for r in recs)
    assert all(validate_record(r) == [] for r in recs)
    inj = mal[0]
    assert inj["label"]["attack_family"].startswith("indirect_injection")
    assert inj["turns"][-1]["instruction_origin"] in ("tool_output", "retrieved_content")
