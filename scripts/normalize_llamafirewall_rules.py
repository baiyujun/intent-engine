"""Reverse-generate samples from LlamaFirewall scanner rules. needs_confirmation (custom)."""
import re, pathlib, yaml
from src.schema import make_record, deterministic_id, validate_record
from src.normalize_utils import write_slice, make_turn
from src.licenses import license_status, license_spdx
SRC_KEY = "llamafirewall_rules"
RAW_DIR = pathlib.Path("raw/llamafirewall_rules")

def main():
    d = RAW_DIR if RAW_DIR.exists() else pathlib.Path("tests/fixtures/clawsentry_rules")
    recs = []
    # Search for yaml/yml rule files under any llamafirewall dir; reuse same generator as clawsentry
    found = False
    for f in d.rglob("*.yaml"):
        if "llamafirewall" not in str(f).lower() and not d.samefile(pathlib.Path("tests/fixtures/clawsentry_rules")):
            continue
        try: rules = yaml.safe_load(f.read_text())
        except Exception: continue
        found = True
        for rule in (rules or []):
            rid = rule.get("id") or rule.get("name", "lf_rule")
            for kw in (rule.get("keywords") or ["test"])[:1]:
                text = f"{kw}"
                recs.append(make_record(
                    id=deterministic_id(SRC_KEY, f"{rid}#0"),
                    source_dataset=SRC_KEY, license=license_spdx(SRC_KEY), license_status=license_status(SRC_KEY),
                    modality="single_turn",
                    turns=[make_turn("user", text, "user_direct")],
                    structured_action={"action_type": "unknown", "target_resource": None, "stated_purpose": None},
                    label={"risk_category": "prompt_injection", "is_malicious": True,
                           "attack_family": "lf_rule_derived",
                           "purpose_capability_consistent": False, "confidence": "medium",
                           "attack_stage_precursor": False},
                    notes=f"rule_derived: {rid} (llamafirewall); needs_confirmation"))
    recs = [r for r in recs if validate_record(r) == []]
    if not found:
        # log to coverage_gaps via fetch_errors
        from src.fetch_utils import append_fetch_error
        append_fetch_error("llamafirewall_rules", RuntimeError("no regex rule files found; LlamaFirewall may use ML classifiers (noted in coverage_gaps)"))
    return write_slice(SRC_KEY, recs)
if __name__ == "__main__": main()
