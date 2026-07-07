import json, pathlib
from src import normalize_utils
from src.schema import validate_record

def _rec(i):
    return {
        "id": f"x_{i}", "source_dataset": "x", "license": "MIT", "license_status": "ok",
        "modality": "single_turn",
        "turns": [{"turn_index": 0, "role": "user", "raw_text": f"t{i}", "instruction_origin": "user_direct"}],
        "structured_action": {"action_type": "unknown", "target_resource": None, "stated_purpose": None},
        "label": {"risk_category": "benign", "is_malicious": False, "attack_family": "benign",
                  "purpose_capability_consistent": True, "confidence": "high", "attack_stage_precursor": False},
        "notes": None,
    }

def test_write_slice_overwrites(tmp_path, monkeypatch):
    monkeypatch.setattr(normalize_utils, "ROOT", tmp_path)
    normalize_utils.write_slice("x", [_rec(1), _rec(2)])
    normalize_utils.write_slice("x", [_rec(3)])  # overwrite -> only 1 line
    recs = normalize_utils.read_slice("x")
    assert len(recs) == 1 and recs[0]["id"] == "x_3"

def test_iter_jsonl_roundtrips(tmp_path):
    p = tmp_path / "f.jsonl"
    normalize_utils.write_jsonl(p, [_rec(1), _rec(2)])
    assert [r["id"] for r in normalize_utils.iter_jsonl(p)] == ["x_1", "x_2"]

def test_make_turn_shape():
    t = normalize_utils.make_turn("user", "hi", "user_direct")
    assert t == {"turn_index": 0, "role": "user", "raw_text": "hi", "instruction_origin": "user_direct"}
