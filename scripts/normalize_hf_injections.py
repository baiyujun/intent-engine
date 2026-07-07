"""Normalize 3 HF prompt-injection datasets -> one slice. deepset=ok, others needs_confirmation."""
import csv, json, pathlib
from src.schema import make_record, validate_record
from src.normalize_utils import write_slice, make_turn
from src.licenses import license_status, license_spdx
RAW_DIR = pathlib.Path("raw/hf_injections")

SPECS = [
    ("hf_deepset", "deepset.csv", "text", "label"),
    ("hf_jayavibhav", "jayavibhav.csv", "prompt", "is_injection"),
    ("hf_imoxto", "imoxto.csv", "text", "injection"),
]

def _truthy(v):
    return str(v).strip() in ("1", "true", "True", "yes", "injection")

def main():
    d = RAW_DIR if RAW_DIR.exists() else pathlib.Path("tests/fixtures/hf")
    recs = []
    for src_key, fname, text_col, lab_col in SPECS:
        f = d / fname
        if not f.exists(): continue
        with f.open() as fh:
            for i, row in enumerate(csv.DictReader(fh)):
                text = row.get(text_col) or ""
                if not text.strip(): continue
                mal = _truthy(row.get(lab_col))
                recs.append(make_record(
                    _raw_id=f"{src_key}_{i}", source_dataset=src_key,
                    license=license_spdx(src_key), license_status=license_status(src_key),
                    modality="single_turn",
                    turns=[make_turn("user", text, "user_direct")],
                    structured_action={"action_type": "unknown", "target_resource": None, "stated_purpose": None},
                    label={"risk_category": "prompt_injection" if mal else "benign",
                           "is_malicious": mal, "attack_family": "direct_injection" if mal else "benign",
                           "purpose_capability_consistent": True, "confidence": "high",
                           "attack_stage_precursor": False},
                    notes=f"{src_key} binary label"))
    recs = [r for r in recs if validate_record(r) == []]
    return write_slice("hf_injections", recs)
if __name__ == "__main__": main()
