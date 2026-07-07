"""Normalize R-Judge -> unified records. license_status=needs_confirmation (no LICENSE)."""
import json, pathlib
from src.schema import make_record, validate_record
from src.normalize_utils import write_slice, make_turn
from src.licenses import license_status, license_spdx
SRC_KEY = "rjudge"
RAW_DIR = pathlib.Path("raw/rjudge")

def _consistent(critique: str, unsafe: bool) -> bool:
    c = (critique or "").lower()
    if unsafe:
        return False
    if any(k in c for k in ["match", "consistent", "appropriate", "correct"]):
        return True
    return True

def main():
    d = RAW_DIR if RAW_DIR.exists() else pathlib.Path("tests/fixtures/rjudge")
    recs = []
    for f in d.rglob("*.json"):
        try: data = json.loads(f.read_text())
        except Exception: continue
        rows = data if isinstance(data, list) else data.get("data", data)
        for o in rows:
            unsafe = (o.get("safety_label") or "").lower() in ("unsafe", "1", "malicious")
            turns = []
            for i, m in enumerate(o.get("conversations", [])):
                role = "user" if m.get("role") == "user" else "agent_plan"
                turns.append(make_turn(role, m.get("content", ""), "user_direct", i))
            if not turns: turns = [make_turn("user", o.get("intent", ""), "user_direct")]
            recs.append(make_record(
                _raw_id=o.get("id"), source_dataset=SRC_KEY,
                license=license_spdx(SRC_KEY), license_status=license_status(SRC_KEY),
                modality="multi_turn", turns=turns,
                structured_action={"action_type": "exec", "target_resource": o.get("target_tool"),
                                  "stated_purpose": o.get("intent")},
                label={"risk_category": "unauthorized_action" if unsafe else "benign",
                       "is_malicious": unsafe, "attack_family": "goal_hijack" if unsafe else "benign",
                       "purpose_capability_consistent": _consistent(o.get("critique", ""), unsafe),
                       "confidence": "high", "attack_stage_precursor": False},
                notes=f"rjudge critique={o.get('critique','')[:60]}"))
    recs = [r for r in recs if validate_record(r) == []]
    return write_slice(SRC_KEY, recs)
if __name__ == "__main__": main()
