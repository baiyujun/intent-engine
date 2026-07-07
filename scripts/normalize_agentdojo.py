"""Normalize AgentDojo suites -> unified records. Parses suite .py with ast (no exec)."""
import ast, pathlib
from src.schema import make_record, deterministic_id, validate_record
from src.normalize_utils import write_slice, make_turn
from src.licenses import license_status, license_spdx

RAW_DIR = pathlib.Path("raw/agentdojo/src/agentdojo/agentdojo/default_suites/v1")
SRC_KEY = "agentdojo"

def _literal_lists(tree):
    out = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name) and t.id in ("USER_TASKS", "INJECTIONS"):
                    try: out[t.id] = ast.literal_eval(n.value)
                    except Exception: pass
    return out

def main():
    recs = []
    suite_dir = RAW_DIR
    if not suite_dir.exists():
        suite_dir = pathlib.Path("tests/fixtures/agentdojo")  # test path
    files = list(suite_dir.rglob("*.py"))
    for f in files:
        try:
            tree = ast.parse(f.read_text())
        except Exception:
            continue
        L = _literal_lists(tree)
        suite = f.stem
        for t in L.get("USER_TASKS", []):
            instr = t.get("instruction") or str(t)
            recs.append(make_record(
                _raw_id=str(t.get("id", instr[:20])), source_dataset=SRC_KEY,
                license=license_spdx(SRC_KEY), license_status=license_status(SRC_KEY),
                modality="multi_turn",
                turns=[make_turn("user", instr, "user_direct")],
                structured_action={"action_type": "unknown", "target_resource": None, "stated_purpose": None},
                label={"risk_category": "benign", "is_malicious": False, "attack_family": "benign",
                       "purpose_capability_consistent": True, "confidence": "high",
                       "attack_stage_precursor": False},
                notes=f"agentdojo benign task [{suite}]"))
        for inj in L.get("INJECTIONS", []):
            payload = inj.get("payload", "")
            af = "indirect_injection_" + str(inj.get("source", "x")).replace(" ", "_")
            recs.append(make_record(
                _raw_id=(payload[:24] or "inj"), source_dataset=SRC_KEY,
                license=license_spdx(SRC_KEY), license_status=license_status(SRC_KEY),
                modality="multi_turn",
                turns=[make_turn("user", "(user task)", "user_direct", 0),
                       make_turn("tool_output", payload, "tool_output", 1)],
                structured_action={"action_type": "unknown", "target_resource": None, "stated_purpose": None},
                label={"risk_category": "prompt_injection", "is_malicious": True, "attack_family": af,
                       "purpose_capability_consistent": False, "confidence": "high",
                       "attack_stage_precursor": False},
                notes=f"agentdojo injection [{suite}] source={inj.get('source')}"))
    recs = [r for r in recs if validate_record(r) == []]
    return write_slice(SRC_KEY, recs)

if __name__ == "__main__": main()
