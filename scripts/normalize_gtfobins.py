"""Normalize GTFOBins _gtfobins/*.md YAML frontmatter -> unified records.
Command patterns only. action_type=exec, attack_family from function category."""
import re, pathlib, yaml, hashlib
from src.schema import make_record, deterministic_id, validate_record
from src.normalize_utils import write_slice, make_turn
from src.licenses import license_status, license_spdx
SRC_KEY = "gtfobins"
RAW_DIR = pathlib.Path("raw/gtfobins")
_FAM = {"shell": "shell_spawn", "sudo": "privilege_escalation", "suid": "privilege_escalation",
        "file-read": "file_read", "file-write": "file_write", "download": "exfil",
        "upload": "exfil", "reverse-shell": "reverse_shell", "non-interactive-shell": "shell_spawn",
        "capabilities": "privilege_escalation"}

def _frontmatter(text):
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    return yaml.safe_load(m.group(1)) if m else {}

def _load_entries(f):
    """GTFOBins real files are _gtfobins/*.md with --- YAML frontmatter; fixtures are *.yml/*.yaml (pure YAML)."""
    text = f.read_text()
    if f.suffix.lower() == ".md":
        fm = _frontmatter(text)
        return [fm] if fm else []
    data = yaml.safe_load(text)
    if isinstance(data, dict):
        return [data]
    return data or []

def main():
    d = RAW_DIR if RAW_DIR.exists() else pathlib.Path("tests/fixtures/gtfobins")
    recs = []
    for f in d.rglob("*"):
        if f.suffix.lower() not in (".md", ".yml", ".yaml"):
            continue
        try:
            entries = _load_entries(f)
        except Exception:
            continue
        for entry in entries:
            binary = entry.get("name", f.stem)
            for func, items in (entry.get("functions") or {}).items():
                for it in (items or []):
                    code = it.get("code") or ""
                    if not code: continue
                    recs.append(make_record(
                        id=deterministic_id(SRC_KEY, f"{binary}#{func}#{hashlib.sha1(code.encode()).hexdigest()[:8]}"),
                        source_dataset=SRC_KEY, license=license_spdx(SRC_KEY), license_status=license_status(SRC_KEY),
                        modality="single_turn",
                        turns=[make_turn("agent_plan", code, "user_direct")],
                        structured_action={"action_type": "exec", "target_resource": binary,
                                          "stated_purpose": it.get("description")},
                        label={"risk_category": "tool_misuse", "is_malicious": True,
                               "attack_family": _FAM.get(func, "tool_misuse"),
                               "purpose_capability_consistent": False, "confidence": "medium",
                               "attack_stage_precursor": False},
                        notes=f"gtfobins binary={binary} func={func}; command pattern only, no payload"))
    recs = [r for r in recs if validate_record(r) == []]
    return write_slice(SRC_KEY, recs)
if __name__ == "__main__": main()
