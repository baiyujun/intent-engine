"""Normalize PurpleLlama CyberSecEval (injection/misalignment subsets) -> unified records.
license_status=needs_confirmation (Llama Community License)."""
import json, pathlib
from src.schema import make_record, validate_record
from src.normalize_utils import write_slice, make_turn
from src.licenses import license_status, license_spdx
SRC_KEY = "purplellama"
RAW_DIR = pathlib.Path("raw/purplellama")
RELEVANT = {"prompt_injection", "agent_misalignment", "injection", "misalignment"}
_FAM = {"prompt_injection": "indirect_injection", "agent_misalignment": "agent_misalignment",
        "injection": "indirect_injection", "misalignment": "agent_misalignment"}

def main():
    d = RAW_DIR if RAW_DIR.exists() else pathlib.Path("tests/fixtures/purplellama")
    recs = []
    for f in d.rglob("*.jsonl"):
        with f.open() as fh:
            for line in fh:
                o = json.loads(line)
                subset = (o.get("subset") or "").lower()
                if subset not in RELEVANT: continue
                prompt = o.get("prompt") or ""
                if not prompt: continue
                recs.append(make_record(
                    _raw_id=(o.get("id") or prompt[:16]), source_dataset=SRC_KEY,
                    license=license_spdx(SRC_KEY), license_status=license_status(SRC_KEY),
                    modality="single_turn",
                    turns=[make_turn("user", prompt, "user_direct")],
                    structured_action={"action_type": "unknown", "target_resource": None, "stated_purpose": None},
                    label={"risk_category": "prompt_injection", "is_malicious": True,
                           "attack_family": _FAM.get(subset, "prompt_injection"),
                           "purpose_capability_consistent": False, "confidence": "high",
                           "attack_stage_precursor": False},
                    notes=f"purplellama subset={subset}"))
    recs = [r for r in recs if validate_record(r) == []]
    return write_slice(SRC_KEY, recs)
if __name__ == "__main__": main()
