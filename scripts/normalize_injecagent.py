"""Normalize InjecAgent CSVs -> unified records."""
import csv, pathlib
from src.schema import make_record, validate_record
from src.normalize_utils import write_slice, make_turn
from src.licenses import license_status, license_spdx
SRC_KEY = "injecagent"
RAW_DIR = pathlib.Path("raw/injecagent")

_AF = {"goal_hijack": "goal_hijack", "credential_exfil": "credential_exfil",
       "indirect_injection": "indirect_injection", "tool_poisoning": "indirect_injection"}

def _iter_csvs(d):
    return list(d.rglob("*.csv"))

def main():
    d = RAW_DIR if RAW_DIR.exists() else pathlib.Path("tests/fixtures/injecagent")
    recs = []
    for f in _iter_csvs(d):
        with f.open() as fh:
            for row in csv.DictReader(fh):
                payload = row.get("injection") or ""
                if not payload: continue
                af = _AF.get((row.get("injection_type") or "").strip().lower(), "indirect_injection")
                recs.append(make_record(
                    _raw_id=row.get("id") or payload[:16], source_dataset=SRC_KEY,
                    license=license_spdx(SRC_KEY), license_status=license_status(SRC_KEY),
                    modality="single_turn",
                    turns=[make_turn("tool_output", payload, "tool_output")],
                    structured_action={"action_type": "unknown", "target_resource": None, "stated_purpose": None},
                    label={"risk_category": "prompt_injection", "is_malicious": True, "attack_family": af,
                           "purpose_capability_consistent": False, "confidence": "high",
                           "attack_stage_precursor": False},
                    notes=f"injecagent type={row.get('injection_type')}"))
    recs = [r for r in recs if validate_record(r) == []]
    return write_slice(SRC_KEY, recs)
if __name__ == "__main__": main()
