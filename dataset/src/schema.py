"""Unified record schema + validation for the v0 Agent intent dataset."""
import hashlib

ALLOWED_MODALITY = {"single_turn", "multi_turn"}
ALLOWED_ROLE = {"user", "agent_plan", "tool_output", "retrieved_doc"}
ALLOWED_ORIGIN = {"user_direct", "tool_output", "retrieved_content", "sub_agent_output", "unknown"}
ALLOWED_LICENSE_STATUS = {"ok", "needs_confirmation", "excluded"}
ALLOWED_CONFIDENCE = {"high", "medium", "low"}

def deterministic_id(source: str, raw_id, canonical: str | None = None) -> str:
    # Treat None and empty-string raw_id the same: fall back to a hash of
    # canonical text so records without a native id still get a unique, stable id.
    if raw_id is None or str(raw_id).strip() == "":
        key = "h" + hashlib.sha1((canonical or "").encode()).hexdigest()[:12]
    else:
        key = str(raw_id)
    safe = key.replace("/", "_").replace(" ", "_")
    return f"{source}_{safe}"

def _canonical_key(kw) -> str:
    parts = [t.get("raw_text", "") for t in kw.get("turns", [])]
    sa = kw.get("structured_action", {})
    if sa.get("target_resource"): parts.append(str(sa["target_resource"]))
    if sa.get("stated_purpose"): parts.append(str(sa["stated_purpose"]))
    return " \n ".join(p for p in parts if p)

def make_record(**kw) -> dict:
    """Build a record filling schema defaults for optional fields."""
    sa = kw.setdefault("structured_action", {})
    sa.setdefault("action_type", "unknown")
    sa.setdefault("target_resource", None)
    sa.setdefault("stated_purpose", None)
    lab = kw.setdefault("label", {})
    lab.setdefault("purpose_capability_consistent", True)
    lab.setdefault("attack_stage_precursor", False)
    kw.setdefault("source_ref", None)
    kw.setdefault("notes", None)
    kw.setdefault("modality", "single_turn")
    if "id" not in kw and "source_dataset" in kw:
        rid = kw.get("_raw_id")
        # No usable raw id -> derive a canonical key from turns+action so the
        # generated id is unique per content (avoids id collisions for records
        # whose source has no native id, e.g. some R-Judge/MITRE rows).
        canonical = None if (rid is not None and str(rid) != "") else _canonical_key(kw)
        kw["id"] = deterministic_id(kw["source_dataset"], rid, canonical)
        kw.pop("_raw_id", None)
    return kw

def canonical_text(r: dict) -> str:
    parts = [t.get("raw_text", "") for t in r.get("turns", [])]
    sa = r.get("structured_action", {})
    if sa.get("target_resource"):
        parts.append(str(sa["target_resource"]))
    if sa.get("stated_purpose"):
        parts.append(str(sa["stated_purpose"]))
    return " \n ".join(p for p in parts if p)

def validate_record(r: dict) -> list[str]:
    errs = []
    for f in ("id", "source_dataset", "license", "license_status", "modality", "turns", "structured_action", "label"):
        if f not in r:
            errs.append(f"missing required field: {f}")
    if r.get("modality") not in ALLOWED_MODALITY:
        errs.append(f"modality must be one of {ALLOWED_MODALITY}")
    for i, t in enumerate(r.get("turns", [])):
        for f in ("turn_index", "role", "raw_text", "instruction_origin"):
            if f not in t:
                errs.append(f"turns[{i}] missing {f}")
        if t.get("role") not in ALLOWED_ROLE:
            errs.append(f"turns[{i}].role invalid")
        if t.get("instruction_origin") not in ALLOWED_ORIGIN:
            errs.append(f"turns[{i}].instruction_origin invalid")
    sa = r.get("structured_action", {})
    if "action_type" not in sa or "target_resource" not in sa or "stated_purpose" not in sa:
        errs.append("structured_action missing keys")
    lab = r.get("label", {})
    for f in ("risk_category", "is_malicious", "attack_family", "purpose_capability_consistent", "confidence"):
        if f not in lab:
            errs.append(f"label missing {f}")
    if lab.get("confidence") not in ALLOWED_CONFIDENCE:
        errs.append(f"label.confidence must be one of {ALLOWED_CONFIDENCE}")
    if not isinstance(lab.get("is_malicious"), bool):
        errs.append("label.is_malicious must be bool")
    if r.get("license_status") not in ALLOWED_LICENSE_STATUS:
        errs.append(f"license_status must be one of {ALLOWED_LICENSE_STATUS}")
    return errs
