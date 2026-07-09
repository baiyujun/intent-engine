"""Normalize GTFOBins _gtfobins/* extensionless YAML docs -> unified records.

Real data: raw/gtfobins/_gtfobins/<binary> files have NO extension; each is a
single YAML document delimited by ---/... with top-level `name`/`comment`/
`functions` (a dict: <function> -> list of {code, contexts:{...}}). Each item's
top-level `code` is the command pattern; some items also carry context-specific
`code` under `contexts.<ctx>.code`. We emit one record per distinct `code`.

Command patterns only. action_type=exec, attack_family from function category.
"""
import pathlib, yaml, hashlib
from src.schema import make_record, deterministic_id, validate_record
from src.normalize_utils import write_slice, make_turn
from src.licenses import license_status, license_spdx
SRC_KEY = "gtfobins"
RAW_DIR = pathlib.Path("raw/gtfobins")
_FAM = {"shell": "shell_spawn", "sudo": "privilege_escalation", "suid": "privilege_escalation",
        "file-read": "file_read", "file-write": "file_write", "download": "exfil",
        "upload": "exfil", "reverse-shell": "reverse_shell", "non-interactive-shell": "shell_spawn",
        "capabilities": "privilege_escalation"}

def _iter_entry_files(d):
    """Yield GTFOBins entry files. Real data: _gtfobins/* (extensionless); fixture: *.yml/*.yaml."""
    base = d / "_gtfobins"
    if base.is_dir():
        for f in sorted(base.iterdir()):
            if f.is_file():
                yield f
    for f in sorted(d.glob("*.yml")) + sorted(d.glob("*.yaml")):
        yield f

def _item_codes(item):
    """Extract command-pattern codes from one functions-list item.

    Emits the item's top-level `code` (if present), plus any nested `code`
    under `contexts.<ctx>` (a dict like {sudo:{code:...}, suid:{code:...}}).
    Returns an ordered list (deduped, preserving first-seen order)."""
    codes = []
    if isinstance(item, dict):
        c = item.get("code")
        if isinstance(c, str) and c.strip():
            codes.append(c)
        ctx = item.get("contexts")
        if isinstance(ctx, dict):
            for cv in ctx.values():
                if isinstance(cv, dict):
                    nc = cv.get("code")
                    if isinstance(nc, str) and nc.strip():
                        codes.append(nc)
    # dedupe (identical codes across top-level + a context collapse to one record)
    seen, out = set(), []
    for c in codes:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out

def main():
    d = RAW_DIR if RAW_DIR.exists() else pathlib.Path("tests/fixtures/gtfobins")
    recs = []
    for f in _iter_entry_files(d):
        try:
            data = yaml.safe_load(f.read_text())
        except Exception:
            continue
        if not isinstance(data, dict) or not data.get("functions"):
            continue
        binary = data.get("name", f.stem)
        for func, items in (data.get("functions") or {}).items():
            fam = _FAM.get(func, "tool_misuse")
            for it in (items or []):
                stated = it.get("comment") or it.get("description") if isinstance(it, dict) else None
                for code in _item_codes(it):
                    recs.append(make_record(
                        id=deterministic_id(SRC_KEY, f"{binary}#{func}#{hashlib.sha1(code.encode()).hexdigest()[:8]}"),
                        source_dataset=SRC_KEY, license=license_spdx(SRC_KEY), license_status=license_status(SRC_KEY),
                        modality="single_turn",
                        turns=[make_turn("agent_plan", code, "user_direct")],
                        structured_action={"action_type": "exec", "target_resource": binary,
                                          "stated_purpose": stated},
                        label={"risk_category": "tool_misuse", "is_malicious": True,
                               "attack_family": fam,
                               "purpose_capability_consistent": False, "confidence": "medium",
                               "attack_stage_precursor": False},
                        notes=f"gtfobins binary={binary} func={func}; command pattern only, no payload"))
    recs = [r for r in recs if validate_record(r) == []]
    return write_slice(SRC_KEY, recs)
if __name__ == "__main__": main()
