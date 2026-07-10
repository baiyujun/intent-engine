"""Tier2 Evidence Capsule — isolates raw text and supplies structured signals.

Per v0.4 Part 2: the LLM must NOT judge "did scary words appear" but "is this
action reasonable given its stated purpose and actual capability". To force that:

  1. Raw user/turn text is passed inside an explicit EVIDENCE FENCE so the model
     treats it as observed text, not as instructions to act on, and so a single
     word inside it is never the sole basis.
  2. Structured lower-tier signals are provided as explicit fields:
       - tier0: verdict, vector_margin, rule_risk, matched patterns, escalation
         reasons (the WHY of the cheap layer's call)
       - tier1: probability, and the concrete trajectory features that fired
         (tool_diversity, action_burst, cumulative_risk, novelty flags, etc.)
     These are "known evidence" the judge reasons ON TOP OF, not from scratch.
  3. The structured_action (stated purpose vs action type) is provided so the
     judge can compare purpose vs capability directly.

The capsule is a plain dict serialized to JSON for the LLM user message; the
system prompt (in llm_judge.py) states the word-presence rule.
"""
from __future__ import annotations

from tier0.fusion import judge as _t0_judge
from tier1.features import (
    extract_features as _extract_features,
    build_benign_profile as _build_profile,
    FEATURE_NAMES as _FEATURE_NAMES,
)

_EVIDENCE_FENCE_OPEN = "<<<RAW_AGENT_INTERACTION_BEGIN>>>"
_EVIDENCE_FENCE_CLOSE = "<<<RAW_AGENT_INTERACTION_END>>>"

# Tier1 features that are semantically meaningful to expose to the judge (not the
# degenerate-length/keyword-count ones — those are noise for a semantic judge).
_MEANINGFUL_T1 = {
    "tool_file_read", "tool_network_request", "tool_exec",
    "tool_summarize", "tool_web_fetch", "task_tool_mismatch_flag",
    "has_external_content", "sensitive_resource_involved",
    "risky_action_after_external_input", "cumulative_risk_sum", "risk_delta",
    "monotonicity_flag", "action_burst_score", "novelty_recipient_flag",
    "novelty_filepath_flag", "context_exfil_gap", "session_length",
    "tool_diversity_score", "semantic_drift_score",
}


def _build_profile_once():
    import pathlib
    repo = pathlib.Path(__file__).resolve().parents[1]
    data = repo / "dataset"
    P = data / "processed"; S = data / "synthetic"
    recs = []
    for p in (P / "train.jsonl", S / "xgboost_paper_derived.jsonl", S / "promptfoo_redteam.jsonl"):
        if p.exists():
            for line in p.read_text().splitlines():
                if line.strip():
                    recs.append(__import__("json").loads(line))
    return _build_profile([r for r in recs if not r.get("label", {}).get("is_malicious")])


_PROFILE = None


def _profile():
    global _PROFILE
    if _PROFILE is None:
        _PROFILE = _build_profile_once()
    return _PROFILE


def _tier1_triggered(fv: list[float]) -> list[dict]:
    out = []
    for i, name in enumerate(_FEATURE_NAMES):
        if name in _MEANINGFUL_T1 and fv[i] not in (0.0, 0):
            out.append({"feature": name, "value": float(fv[i])})
    # keep only the most-informative few to keep the capsule compact
    return out


def build_capsule(record: dict, *, tier1_prob: float | None = None,
                  tier1_features: list[float] | None = None) -> dict:
    """Build the Evidence Capsule for one interaction.

    `tier1_prob` / `tier1_features` may be supplied by the caller (the pipeline
    already computes them); if None they are computed here. This keeps the
    capsule builder usable standalone for tests.
    """
    turns = record.get("turns", []) or []
    raw_turns = []
    for t in turns:
        if isinstance(t, dict):
            raw_turns.append(t.get("raw_text", "") or "")
        else:
            raw_turns.append(str(t or ""))

    full_text = "\n".join(f"[Turn {i}] {t}" for i, t in enumerate(raw_turns))

    # Tier0 signals
    t0 = _t0_judge(full_text, models_dir="tier0/models", text_only=True)
    t0_signals = {
        "final_verdict": t0.final_verdict,
        "escalated": t0.escalated,
        "escalation_reasons": list(t0.escalation_reasons),
        "vector_margin": round(t0.vector_margin, 4),
        "vector_margin_note": "negative = closer to malicious embedding space",
        "rule_risk": str(t0.rule_risk),
        "rule_scores": {"d1": t0.rule_d1, "d2": t0.rule_d2, "d3": t0.rule_d3},
        "matched_patterns": [
            {"id": p.get("id"), "category": p.get("category"), "max_weight": p.get("max_weight")}
            for p in (t0.rule_matched_patterns or [])
        ][:6],
    }

    # Tier1 signals
    if tier1_features is None:
        tier1_features = _extract_features(record, _profile())
    if tier1_prob is None:
        import xgboost as xgb
        repo = __import__("pathlib").Path(__file__).resolve().parents[1]
        clf = xgb.XGBClassifier()
        clf.load_model(str(repo / "tier1" / "models" / "xgboost_full.json"))
        tier1_prob = float(clf.predict_proba([tier1_features])[0, 1])

    t1_signals = {
        "malicious_probability": round(float(tier1_prob), 4),
        "triggered_trajectory_features": _tier1_triggered(tier1_features),
    }

    sa = record.get("structured_action", {}) or {}
    structured = {
        "action_type": sa.get("action_type"),
        "target_resource": sa.get("target_resource"),
        "stated_purpose": sa.get("stated_purpose"),
    }

    return {
        "raw_interaction": f"{_EVIDENCE_FENCE_OPEN}\n{full_text}\n{_EVIDENCE_FENCE_CLOSE}",
        "raw_interaction_note": "Observed user/tool text ONLY. A word appearing here "
                               "is NOT by itself evidence of malice — see judge rules.",
        "tier0_signals": t0_signals,
        "tier1_signals": t1_signals,
        "structured_action": structured,
        "session_turn_count": len(raw_turns),
    }
