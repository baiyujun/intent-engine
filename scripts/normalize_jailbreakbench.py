"""Normalize JailbreakBench -> unified records. MIT, ok. Domain-gap caveat in notes.

Real data source: raw/jailbreakbench/artifacts/attack-artifacts/<method>/
  - <variant>/<model>.json  -> {"parameters":..., "jailbreaks":[{index,goal,behavior,
      category,prompt,response,jailbroken,...}]}
  - submission.json (DSN)    -> {"summaries":{<model>:{"jailbreaks":[...]}}}
Each unique (method, prompt) -> one record. attack_family = jailbreak_<method>.
"""
import json, pathlib
from src.schema import make_record, validate_record
from src.normalize_utils import write_slice, make_turn
from src.licenses import license_status, license_spdx

SRC_KEY = "jailbreakbench"
RAW_DIR = pathlib.Path("raw/jailbreakbench")
ARTIFACTS = "artifacts/attack-artifacts"
CAVEAT = "domain-gap: general content-safety jailbreak, not Agent action-risk; ablation candidate"

# Skip the synthetic test-artifact (not a real attack method).
_SKIP_METHODS = {"test-artifact"}


def _iter_jailbreaks(artifacts_root: pathlib.Path):
    """Yield (method, jb_dict) for every jailbreak entry across all method dirs."""
    if not artifacts_root.exists():
        return
    for method_dir in sorted(p for p in artifacts_root.iterdir() if p.is_dir()):
        method = method_dir.name
        if method in _SKIP_METHODS:
            continue
        # submission.json (e.g. DSN): summaries.<model>.jailbreaks[]
        sub = method_dir / "submission.json"
        if sub.exists():
            try:
                d = json.loads(sub.read_text())
            except Exception:
                d = {}
            for mv in d.get("summaries", {}).values():
                for jb in mv.get("jailbreaks", []):
                    yield method, jb
        # <variant>/<model>.json: top-level jailbreaks[]
        for fp in method_dir.rglob("*.json"):
            if fp.name in ("submission.json", "attack-info.json"):
                continue
            try:
                d = json.loads(fp.read_text())
            except Exception:
                continue
            if isinstance(d, dict) and isinstance(d.get("jailbreaks"), list):
                for jb in d["jailbreaks"]:
                    yield method, jb


def _bool(v) -> bool:
    return str(v).strip().lower() in ("true", "1", "yes")


def main():
    base = RAW_DIR / ARTIFACTS
    root = base if base.exists() else pathlib.Path("tests/fixtures/jailbreakbench")
    # Dedup by (method, prompt); prefer a jailbroken instance when available.
    seen: dict[tuple, dict] = {}
    for method, jb in _iter_jailbreaks(root):
        prompt = (jb.get("prompt") or "").strip()
        if not prompt:
            continue
        key = (method, prompt)
        prev = seen.get(key)
        if prev is None or (_bool(jb.get("jailbroken")) and not _bool(prev.get("jailbroken"))):
            seen[key] = jb

    recs = []
    for (method, _prompt), jb in seen.items():
        prompt = jb["prompt"]
        goal = (jb.get("goal") or "").strip()
        behavior = (jb.get("behavior") or "").strip()
        category = (jb.get("category") or "uncategorized").strip()
        raw_id = f"{method}_{jb.get('index', '')}".strip("_") or None
        recs.append(make_record(
            _raw_id=raw_id, source_dataset=SRC_KEY,
            license=license_spdx(SRC_KEY), license_status=license_status(SRC_KEY),
            modality="single_turn",
            turns=[make_turn("user", prompt, "user_direct")],
            structured_action={"action_type": "unknown", "target_resource": None,
                               "stated_purpose": goal or None},
            label={"risk_category": "goal_hijack", "is_malicious": True,
                   "attack_family": f"jailbreak_{method.lower()}",
                   "purpose_capability_consistent": False, "confidence": "high",
                   "attack_stage_precursor": False},
            notes=f"{CAVEAT}; method={method}; behavior={behavior}; category={category}",
            source_ref=f"artifacts/attack-artifacts/{method}",
        ))
    recs = [r for r in recs if validate_record(r) == []]
    return write_slice(SRC_KEY, recs)


if __name__ == "__main__":
    main()
