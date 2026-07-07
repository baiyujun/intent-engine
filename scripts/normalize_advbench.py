"""Normalize AdvBench (llm-attacks harmful_behaviors.csv) -> unified records. MIT, ok."""
import csv, pathlib
from src.schema import make_record, validate_record
from src.normalize_utils import write_slice, make_turn
from src.licenses import license_status, license_spdx
SRC_KEY = "advbench"
RAW_DIR = pathlib.Path("raw/advbench")
CAVEAT = "domain-gap: general content-safety harmful prompt, not Agent action-risk; ablation candidate"

def main():
    d = RAW_DIR if RAW_DIR.exists() else pathlib.Path("tests/fixtures/advbench")
    recs = []
    cands = list(d.rglob("harmful_behaviors.csv")) or list(d.rglob("*.csv"))
    for f in cands:
        with f.open() as fh:
            for i, row in enumerate(csv.DictReader(fh)):
                prompt = row.get("goal") or row.get("prompt") or ""
                if not prompt.strip(): continue
                recs.append(make_record(
                    _raw_id=f"adv_{i}", source_dataset=SRC_KEY,
                    license=license_spdx(SRC_KEY), license_status=license_status(SRC_KEY),
                    modality="single_turn",
                    turns=[make_turn("user", prompt, "user_direct")],
                    structured_action={"action_type": "unknown", "target_resource": None, "stated_purpose": None},
                    label={"risk_category": "goal_hijack", "is_malicious": True,
                           "attack_family": "advbench_gcg",
                           "purpose_capability_consistent": False, "confidence": "high",
                           "attack_stage_precursor": False},
                    notes=CAVEAT))
    recs = [r for r in recs if validate_record(r) == []]
    return write_slice(SRC_KEY, recs)
if __name__ == "__main__": main()
