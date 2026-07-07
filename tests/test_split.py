import json, pathlib
from src import normalize_utils
from scripts import split

def _rec(i, cat, afam, malicious=False):
    return {"id": f"s_{i}", "source_dataset": "s", "license": "MIT", "license_status": "ok",
            "modality": "single_turn",
            "turns": [{"turn_index":0,"role":"user","raw_text":f"t {i} {afam}","instruction_origin":"user_direct"}],
            "structured_action": {"action_type":"unknown","target_resource":None,"stated_purpose":None},
            "label": {"risk_category":cat,"is_malicious":malicious,"attack_family":afam,
                      "purpose_capability_consistent":True,"confidence":"high","attack_stage_precursor":False},
            "notes": None}

def test_split_stratified_and_holdout(monkeypatch, tmp_path):
    monkeypatch.setattr(normalize_utils, "ROOT", tmp_path, raising=False)
    recs = [_rec(i, "prompt_injection", "indirect_injection") for i in range(8)]
    recs += [_rec(i+100, "tool_misuse", "shell_spawn") for i in range(6)]   # holdout family
    recs += [_rec(i+200, "benign", "benign") for i in range(6)]
    (tmp_path/"processed").mkdir(parents=True)
    normalize_utils.write_jsonl(tmp_path/"processed"/"unified_dedup.jsonl", recs)
    split.main()
    train = list(normalize_utils.iter_jsonl(tmp_path/"processed"/"train.jsonl"))
    val = list(normalize_utils.iter_jsonl(tmp_path/"processed"/"val.jsonl"))
    testi = list(normalize_utils.iter_jsonl(tmp_path/"processed"/"test_indist.jsonl"))
    hold = list(normalize_utils.iter_jsonl(tmp_path/"processed"/"test_holdout_family.jsonl"))
    # holdout family fully excluded from train/val
    assert all(r["label"]["attack_family"] != "shell_spawn" for r in train+val)
    assert all(r["label"]["attack_family"] == "shell_spawn" for r in hold)
    # only ok license enters
    assert all(r["license_status"] == "ok" for r in train+val+testi+hold)
    rep = json.loads((tmp_path/"reports"/"split_report.json").read_text())
    assert rep["holdout_families"] == ["shell_spawn","privilege_escalation","advbench_gcg"]
