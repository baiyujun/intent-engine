import json, pathlib
from src import normalize_utils
from scripts import build_report

def test_build_report_writes_files(monkeypatch, tmp_path):
    monkeypatch.setattr(normalize_utils, "ROOT", tmp_path, raising=False)
    monkeypatch.setattr(build_report, "ROOT", tmp_path, raising=False)
    proc = tmp_path/"processed"; proc.mkdir()
    rec = lambda i, ls: {"id":f"r{i}","source_dataset":"agentdojo","license":"MIT","license_status":ls,
        "modality":"single_turn",
        "turns":[{"turn_index":0,"role":"user","raw_text":f"t{i}","instruction_origin":"user_direct"}],
        "structured_action":{"action_type":"unknown","target_resource":None,"stated_purpose":None},
        "label":{"risk_category":"benign","is_malicious":False,"attack_family":"benign",
                 "purpose_capability_consistent":True,"confidence":"high","attack_stage_precursor":False},
        "notes":None}
    normalize_utils.write_jsonl(proc/"unified.jsonl", [rec(0,"ok"), rec(1,"needs_confirmation")])
    for n in ("train","val","test_indist","test_holdout_family"):
        normalize_utils.write_jsonl(proc/f"{n}.jsonl", [rec(0,"ok")])
    (tmp_path/"reports").mkdir()
    (tmp_path/"reports"/"fetch_manifest.json").write_text(json.dumps({"agentdojo":{"fetched_at":"x"}}))
    (tmp_path/"reports"/"dedup_report.json").write_text(json.dumps({"method":"tfidf","removed":1,"kept":1}))
    (tmp_path/"reports"/"split_report.json").write_text(json.dumps({"sizes":{"train":1}}))
    build_report.main()
    dc = (tmp_path/"reports"/"data_card.md").read_text()
    cg = (tmp_path/"reports"/"coverage_gaps.md").read_text()
    assert "agentdojo" in dc and "license_status" in dc
    assert "coverage" in cg.lower() or "gap" in cg.lower()
