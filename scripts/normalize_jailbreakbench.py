"""Normalize JailbreakBench -> unified records. MIT, ok. Domain-gap caveat in notes."""
import csv, pathlib
from src.schema import make_record, validate_record
from src.normalize_utils import write_slice, make_turn
from src.licenses import license_status, license_spdx
SRC_KEY = "jailbreakbench"
RAW_DIR = pathlib.Path("raw/jailbreakbench")
CAVEAT = "domain-gap: general content-safety jailbreak, not Agent action-risk; ablation candidate"

def main():
    d = RAW_DIR if RAW_DIR.exists() else pathlib.Path("tests/fixtures/jailbreakbench")
    recs = []
    for f in d.rglob("*.csv"):
        with f.open() as fh:
            for row in csv.DictReader(fh):
                prompt = row.get("jailbreak_prompt") or row.get("prompt") or ""
                if not prompt.strip(): continue
                method = (row.get("method") or "unknown").strip().lower()
                recs.append(make_record(
                    _raw_id=row.get("index") or prompt[:16], source_dataset=SRC_KEY,
                    license=license_spdx(SRC_KEY), license_status=license_status(SRC_KEY),
                    modality="single_turn",
                    turns=[make_turn("user", prompt, "user_direct")],
                    structured_action={"action_type": "unknown", "target_resource": None, "stated_purpose": None},
                    label={"risk_category": "goal_hijack", "is_malicious": True,
                           "attack_family": f"jailbreak_{method}",
                           "purpose_capability_consistent": False, "confidence": "high",
                           "attack_stage_precursor": False},
                    notes=CAVEAT + f"; method={method}"))
    recs = [r for r in recs if validate_record(r) == []]
    return write_slice(SRC_KEY, recs)
if __name__ == "__main__": main()
