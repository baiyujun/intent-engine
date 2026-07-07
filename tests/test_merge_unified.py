import json, pathlib
from src import normalize_utils
from scripts import merge_unified

def test_merge(monkeypatch, tmp_path):
    # set up two fake slices
    monkeypatch.setattr(normalize_utils, "ROOT", tmp_path, raising=False)
    rec = lambda i: {"id": f"s_{i}", "source_dataset": "s", "license": "MIT", "license_status": "ok",
                    "modality": "single_turn",
                    "turns": [{"turn_index": 0, "role": "user", "raw_text": str(i), "instruction_origin": "user_direct"}],
                    "structured_action": {"action_type": "unknown", "target_resource": None, "stated_purpose": None},
                    "label": {"risk_category": "benign", "is_malicious": False, "attack_family": "benign",
                              "purpose_capability_consistent": True, "confidence": "high", "attack_stage_precursor": False},
                    "notes": None}
    normalize_utils.write_slice("a", [rec(1), rec(2)])
    normalize_utils.write_slice("b", [rec(3)])
    out = merge_unified.main()
    lines = pathlib.Path(out).read_text().strip().splitlines()
    assert len(lines) == 3
    assert all(json.loads(l)["id"].startswith("s_") for l in lines)
    counts = json.loads((tmp_path / "reports" / "unified_count.json").read_text())
    assert counts == {"a": 2, "b": 1}
