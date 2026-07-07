"""Normalize MITRE ATT&CK -> weak-labeled technique rewrites. confidence=low, needs_confirmation."""
import json, pathlib
from src.schema import make_record, validate_record
from src.normalize_utils import write_slice, make_turn
from src.licenses import license_status, license_spdx
SRC_KEY = "mitre_attack_samples"
RAW_DIR = pathlib.Path("raw/mitre_attack")

def main():
    d = RAW_DIR if RAW_DIR.exists() else pathlib.Path("tests/fixtures/mitre_attack")
    recs = []
    for f in d.rglob("*.json"):
        try: bundle = json.loads(f.read_text())
        except Exception: continue
        for o in bundle.get("objects", []):
            if o.get("type") != "attack-pattern": continue
            desc = o.get("description") or ""
            if not desc.strip(): continue
            tid = o.get("id", "").split("--")[-1] if o.get("id") else o.get("name", "tech")
            recs.append(make_record(
                _raw_id=tid, source_dataset=SRC_KEY,
                license=license_spdx(SRC_KEY), license_status=license_status(SRC_KEY),
                modality="single_turn",
                turns=[make_turn("user", desc, "user_direct")],
                structured_action={"action_type": "unknown", "target_resource": None, "stated_purpose": None},
                label={"risk_category": "other_unsafe", "is_malicious": True,
                       "attack_family": "mitre_technique_rewrite",
                       "purpose_capability_consistent": None, "confidence": "low",
                       "attack_stage_precursor": False},
                notes=f"MITRE technique {tid} {o.get('name','')[:40]}; weak label; needs review"))
    recs = [r for r in recs if validate_record(r) == []]
    return write_slice(SRC_KEY, recs)
if __name__ == "__main__": main()
