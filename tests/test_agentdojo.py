import pathlib
from src import normalize_utils
from scripts import normalize_agentdojo
from src.schema import validate_record

def test_normalize_agentdojo_fixture(monkeypatch, tmp_path):
    # point normalize at the committed real-shape fixture (class-based suites)
    monkeypatch.setattr(normalize_agentdojo, "RAW_DIR",
                        pathlib.Path("tests/fixtures/agentdojo"))
    monkeypatch.setattr(normalize_utils, "ROOT", tmp_path, raising=False)
    normalize_agentdojo.main()
    recs = normalize_utils.read_slice("agentdojo")
    assert len(recs) >= 2
    mal = [r for r in recs if r["label"]["is_malicious"]]
    ben = [r for r in recs if not r["label"]["is_malicious"]]
    assert mal and ben
    # f-string PROMPT/GOAL must be resolved (not the raw template).
    assert all("{URL}" not in t["raw_text"] and "{" not in t["raw_text"]
               for t in ben[0]["turns"])
    assert all("{" not in t["raw_text"] for r in mal for t in r["turns"])
    assert all(r["license_status"] == "ok" for r in recs)
    assert all(r["label"]["confidence"] == "high" for r in recs)
    assert all(validate_record(r) == [] for r in recs)
    assert all(r["turns"][-1]["instruction_origin"] == "user_direct" for r in ben)
    assert all(r["turns"][-1]["instruction_origin"] in ("tool_output", "retrieved_content")
               for r in mal)
    assert all(r["label"]["attack_family"].startswith("indirect_injection") for r in mal)
    assert all(r["label"]["attack_family"] == "benign" for r in ben)
    # suite name resolved to the directory under v1*/ (workspace)
    assert all(r["structured_action"]["target_resource"] == "workspace" for r in recs)
