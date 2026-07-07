"""Normalize LOLBAS YAML -> unified records. Command patterns only."""
import pathlib, yaml, hashlib
from src.schema import make_record, deterministic_id, validate_record
from src.normalize_utils import write_slice, make_turn
from src.licenses import license_status, license_spdx
SRC_KEY = "lolbas"
RAW_DIR = pathlib.Path("raw/lolbas")
_FAM = {"Download": "network_request", "AWL Bypass": "defense_evasion", "Credentials": "credential_access",
        "Compile": "code_exec", "Scripts": "code_exec", "Execute": "code_exec",
        "Reconnaissance": "reconnaissance"}

def main():
    d = RAW_DIR if RAW_DIR.exists() else pathlib.Path("tests/fixtures/lolbas")
    recs = []
    for f in d.rglob("*.yml"):
        try: data = yaml.safe_load(f.read_text())
        except Exception: continue
        if isinstance(data, dict): data = [data]
        for entry in data:
            name = entry.get("Name", f.stem)
            for cmd in (entry.get("Commands") or []):
                code = cmd.get("Command") or ""
                if not code: continue
                cat = cmd.get("Category", "Execute")
                recs.append(make_record(
                    id=deterministic_id(SRC_KEY, f"{name}#{cat}#{hashlib.sha1(code.encode()).hexdigest()[:8]}"),
                    source_dataset=SRC_KEY, license=license_spdx(SRC_KEY), license_status=license_status(SRC_KEY),
                    modality="single_turn",
                    turns=[make_turn("agent_plan", code, "user_direct")],
                    structured_action={"action_type": "exec", "target_resource": name,
                                      "stated_purpose": cmd.get("Description")},
                    label={"risk_category": "tool_misuse", "is_malicious": True,
                           "attack_family": _FAM.get(cat, "code_exec"),
                           "purpose_capability_consistent": False, "confidence": "medium",
                           "attack_stage_precursor": False},
                    notes=f"lolbas name={name} category={cat}; command pattern only, no payload"))
    recs = [r for r in recs if validate_record(r) == []]
    return write_slice(SRC_KEY, recs)
if __name__ == "__main__": main()
