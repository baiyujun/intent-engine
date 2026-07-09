import hashlib
from src.schema import validate_record, canonical_text, deterministic_id, make_record

def _base():
    return {
        "id": "agentdojo_1",
        "source_dataset": "agentdojo",
        "license": "MIT",
        "license_status": "ok",
        "source_ref": "abc123",
        "modality": "single_turn",
        "turns": [{"turn_index": 0, "role": "user", "raw_text": "hi", "instruction_origin": "user_direct"}],
        "structured_action": {"action_type": "unknown", "target_resource": None, "stated_purpose": None},
        "label": {
            "risk_category": "benign",
            "is_malicious": False,
            "attack_family": "benign",
            "purpose_capability_consistent": True,
            "confidence": "high",
            "attack_stage_precursor": False,
        },
        "notes": None,
    }

def test_valid_record_passes():
    errs = validate_record(_base())
    assert errs == []

def test_missing_required_field_fails():
    r = _base(); r.pop("source_dataset")
    assert any("source_dataset" in e for e in validate_record(r))

def test_bad_enum_fails():
    r = _base(); r["label"]["confidence"] = "very"
    assert any("confidence" in e for e in validate_record(r))

def test_canonical_text_concatenates():
    r = _base(); r["turns"].append({"turn_index":1,"role":"agent_plan","raw_text":"do x","instruction_origin":"user_direct"})
    r["structured_action"]["target_resource"] = "/tmp/f"
    assert "hi" in canonical_text(r) and "do x" in canonical_text(r) and "/tmp/f" in canonical_text(r)

def test_deterministic_id_stable():
    a = deterministic_id("agentdojo", "send_email")
    b = deterministic_id("agentdojo", "send_email")
    assert a == b and a.startswith("agentdojo_")

def test_deterministic_id_from_text():
    h = deterministic_id("gtfobins", None, canonical="tar --checkpoint")
    assert h.startswith("gtfobins_") and len(h.split("_",1)[1]) >= 8

def test_make_record_defaults():
    r = make_record(source_dataset="x", license="MIT", license_status="ok",
                    turns=[{"turn_index":0,"role":"user","raw_text":"y","instruction_origin":"user_direct"}],
                    label={"risk_category":"benign","is_malicious":False,"attack_family":"benign",
                           "purpose_capability_consistent":True,"confidence":"high"})
    assert validate_record(r) == []
    assert r["label"]["attack_stage_precursor"] is False
    assert r["structured_action"]["action_type"] == "unknown"
