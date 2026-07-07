"""Normalize BIPIA -> unified records. license_status=needs_confirmation (custom)."""
import json, pathlib
from src.schema import make_record, validate_record
from src.normalize_utils import write_slice, make_turn
from src.licenses import license_status, license_spdx
SRC_KEY = "bipia"
RAW_DIR = pathlib.Path("raw/bipia")

def main():
    d = RAW_DIR if RAW_DIR.exists() else pathlib.Path("tests/fixtures/bipia")
    recs = []
    for f in d.rglob("*.jsonl"):
        with f.open() as fh:
            for line in fh:
                o = json.loads(line)
                payload = o.get("injected_instruction") or ""
                if not payload: continue
                fam = "indirect_injection_multimodal" if o.get("modality") == "multimodal" else "indirect_injection"
                origin = "retrieved_content" if o.get("external_document") else "tool_output"
                turns = []
                if o.get("external_document"):
                    turns.append(make_turn("retrieved_doc", o["external_document"], "retrieved_content", 0))
                turns.append(make_turn("tool_output", payload, origin, len(turns)))
                recs.append(make_record(
                    _raw_id=o.get("id") or payload[:16], source_dataset=SRC_KEY,
                    license=license_spdx(SRC_KEY), license_status=license_status(SRC_KEY),
                    modality="single_turn", turns=turns,
                    structured_action={"action_type": "unknown", "target_resource": None, "stated_purpose": None},
                    label={"risk_category": "prompt_injection", "is_malicious": True, "attack_family": fam,
                           "purpose_capability_consistent": False, "confidence": "high",
                           "attack_stage_precursor": False},
                    notes=f"bipia modality={o.get('modality')}"))
    recs = [r for r in recs if validate_record(r) == []]
    return write_slice(SRC_KEY, recs)
if __name__ == "__main__": main()
