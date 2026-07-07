"""Reverse-generate samples from ClawSentry attack_patterns.yaml rules.
Each rule -> N template samples hitting its pattern. confidence=medium, rule_derived."""
import re, pathlib, yaml
from src.schema import make_record, deterministic_id, validate_record
from src.normalize_utils import write_slice, make_turn
from src.licenses import license_status, license_spdx
SRC_KEY = "clawsentry_rules"
RAW_DIR = pathlib.Path("raw/clawsentry_rules")
N_PER_RULE = 3
_TEMPLATES = {
    "command_injection": ["please run: {kw}", "execute the following: {kw}", "I need you to {kw}"],
    "prompt_injection": ["{kw}", "Important: {kw}", "System: {kw}"],
}
_DEFAULT = ["{kw}", "Remember: {kw}", "Now {kw}"]

def _regex_list(rule):
    """Extract regex pattern strings from a rule.

    Supports two shapes:
    - Real ClawSentry attack_patterns.yaml: rule has ``detection.regex_patterns``
      (list of ``{pattern, weight}`` dicts).
    - Fixture/legacy: rule has top-level ``patterns`` (list of regex strings).
    """
    det = rule.get("detection")
    if isinstance(det, dict):
        rp = det.get("regex_patterns") or []
        out = [p.get("pattern") for p in rp if isinstance(p, dict) and p.get("pattern")]
        if out:
            return out
    return [p for p in (rule.get("patterns") or []) if isinstance(p, str)]


def _keywords(rule):
    """Extract keyword strings from a rule (fixture/legacy) or derive from
    the real yaml's ``description``/``id`` so generated samples are non-empty."""
    kws = rule.get("keywords")
    if kws:
        return [k for k in kws if k]
    desc = rule.get("description") or ""
    rid = rule.get("id") or ""
    kws = []
    # mine a few distinctive words from the description as seed keywords
    for w in re.split(r"\W+", desc.lower()):
        if len(w) >= 4 and w not in {"ignore", "instructions", "injection", "hidden", "override"}:
            kws.append(w)
        if len(kws) >= 3:
            break
    if not kws and rid:
        kws = [rid.lower()]
    return kws or ["payload"]


def _gen(rule, cat):
    pats = [re.compile(p) for p in _regex_list(rule)]
    kws = _keywords(rule)
    tmpls = _TEMPLATES.get(cat, _DEFAULT)
    out = []
    for kw in kws:
        for t in tmpls:
            text = t.format(kw=kw)
            if any(p.search(text) for p in pats) or not pats:
                out.append(text)
    # de-dup + cap
    seen, res = set(), []
    for t in out:
        if t in seen: continue
        seen.add(t); res.append(t)
        if len(res) >= N_PER_RULE: break
    return res or [f"{kws[0] if kws else 'test'}"]

def main():
    d = RAW_DIR if RAW_DIR.exists() else pathlib.Path("tests/fixtures/clawsentry_rules")
    recs = []
    for f in d.rglob("*.yaml"):
        try: data = yaml.safe_load(f.read_text())
        except Exception: continue
        # Real ClawSentry yaml is a dict with a top-level "patterns" list of rules;
        # the fixture (and legacy) is a bare list of rules. Support both.
        if isinstance(data, dict) and "patterns" in data:
            rules = data.get("patterns") or []
        else:
            rules = data if isinstance(data, list) else []
        for rule in (rules or []):
            rid = rule.get("id") or rule.get("name", "rule")
            cat = (rule.get("category") or "other").lower()
            for i, text in enumerate(_gen(rule, cat)):
                recs.append(make_record(
                    id=deterministic_id(SRC_KEY, f"{rid}#{i}"),
                    source_dataset=SRC_KEY, license=license_spdx(SRC_KEY), license_status=license_status(SRC_KEY),
                    modality="single_turn",
                    turns=[make_turn("user", text, "user_direct")],
                    structured_action={"action_type": "unknown", "target_resource": None, "stated_purpose": None},
                    label={"risk_category": "prompt_injection" if "injection" in cat else "tool_misuse",
                           "is_malicious": True, "attack_family": cat or "rule_derived",
                           "purpose_capability_consistent": False, "confidence": "medium",
                           "attack_stage_precursor": False},
                    notes=f"rule_derived: {rid} ({rule.get('name','') or rule.get('description','')})"))
    recs = [r for r in recs if validate_record(r) == []]
    return write_slice(SRC_KEY, recs)
if __name__ == "__main__": main()
