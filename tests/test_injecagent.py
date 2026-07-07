import pathlib
from src import normalize_utils
from scripts import normalize_injecagent
from src.schema import validate_record


def test_normalize_injecagent(monkeypatch, tmp_path):
    monkeypatch.setattr(normalize_injecagent, "RAW_DIR",
                       pathlib.Path("tests/fixtures/injecagent"))
    monkeypatch.setattr(normalize_utils, "ROOT", tmp_path, raising=False)
    normalize_injecagent.main()
    recs = normalize_utils.read_slice("injecagent")
    assert len(recs) == 3
    # All records are indirect injection (the InjecAgent spec).
    assert all(r["label"]["attack_family"] == "indirect_injection" for r in recs)
    assert all(r["label"]["is_malicious"] is True for r in recs)
    assert all(r["label"]["risk_category"] == "prompt_injection" for r in recs)
    # The injection is embedded in tool output (turn 1).
    assert all(r["turns"][-1]["instruction_origin"] == "tool_output" for r in recs)
    assert all(len(r["turns"]) == 2 for r in recs)
    assert all(r["turns"][0]["instruction_origin"] == "user_direct" for r in recs)
    # Gate-driven license: injecagent -> ok (MIT).
    assert all(r["license_status"] == "ok" for r in recs)
    # structured_action carries User Tool / User Instruction.
    assert all(r["structured_action"]["target_resource"] for r in recs)
    assert all(r["structured_action"]["stated_purpose"] for r in recs)
    # Deterministic ids (derived from _raw_id = "<file_stem>#<idx>"), all unique.
    assert len({r["id"] for r in recs}) == 3
    assert all(r["id"].startswith("injecagent_test_cases_sample#") for r in recs)
    assert all(validate_record(r) == [] for r in recs)
