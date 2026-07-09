"""Tier 0 fusion — combine rule-engine verdict + vector-retrieval verdict into a
single Tier0Verdict with escalation flag.

Fusion logic (the key design point):
  - rule_risk maps: critical/high → malicious; medium → suspicious; low → benign
  - vector_risk maps: margin > FUZZY_HIGH → benign; margin < FUZZY_LOW → malicious; else fuzzy
  - Agreement (same direction, not fuzzy) → trust, escalated=False
  - Disagreement or fuzzy zone → escalated=True, with specific reason
  - escalated=True means Tier 1 should be invoked
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

from .rule_engine import RuleVerdict, evaluate_rules, PatternMatcher
from .text_preprocess import normalize_text
from .vector_index import VectorVerdict, query as vector_query, build_index

# -- configurable thresholds (env-overridable) --------------------------------

def _env_float(name: str, default: float) -> float:
    return float(os.environ.get(name, str(default)))

FUZZY_LOW  = _env_float("TIER0_FUZZY_LOW",  -0.05)
FUZZY_HIGH = _env_float("TIER0_FUZZY_HIGH",  0.05)

# -- data model ---------------------------------------------------------------

@dataclass
class Tier0Verdict:
    """Final Tier 0 verdict after fusing rule engine + vector retrieval.

    Attributes
    ----------
    rule_risk : str
        Risk level from rule engine: low / medium / high / critical.
    rule_d1, rule_d2, rule_d3 : int
        D1-D3 scores from the rule engine.
    rule_matched_patterns : list[dict]
        Simplified pattern matches (id, category, max_weight).
    rule_short_circuit : str | None
        Short-circuit rule fired, e.g. "SC-1", "SC-2", "SC-3", or None.
    vector_margin : float
        margin = d_malicious - d_benign. Positive → benign direction.
    vector_d_benign : float
    vector_d_malicious : float
    escalated : bool
        True when paths disagree or margin falls in fuzzy zone → invoke Tier 1.
    escalation_reasons : list[str]
        Human-readable reasons for escalation.
    final_verdict : str
        One of: benign / suspicious / malicious.
    path_a_ms : float
        Rule-engine wall-clock time in ms.
    path_b_ms : float
        Vector-retrieval wall-clock time in ms.
    total_ms : float
        Total wall-clock time (may exceed path_a + path_b if sequential).
    """
    rule_risk: str
    rule_d1: int
    rule_d2: int
    rule_d3: int
    rule_matched_patterns: list[dict] = field(default_factory=list)
    rule_short_circuit: str | None = None
    vector_margin: float = 0.0
    vector_d_benign: float = 0.0
    vector_d_malicious: float = 0.0
    escalated: bool = False
    escalation_reasons: list[str] = field(default_factory=list)
    final_verdict: str = "benign"
    path_a_ms: float = 0.0
    path_b_ms: float = 0.0
    total_ms: float = 0.0


# -- direction helpers --------------------------------------------------------

def _rule_direction(risk: str) -> str:
    """Map rule-engine risk to a directional label for fusion."""
    if risk in ("critical", "high"):
        return "malicious"
    if risk == "medium":
        return "suspicious"
    return "benign"


def _vector_direction(margin: float) -> str:
    """Map vector margin to a directional label for fusion."""
    if margin > FUZZY_HIGH:
        return "benign"
    if margin < FUZZY_LOW:
        return "malicious"
    return "fuzzy"


# -- fusion -------------------------------------------------------------------

def fuse(rule_verdict: RuleVerdict, vector_verdict: VectorVerdict) -> Tier0Verdict:
    """Combine the two path verdicts into a final Tier0Verdict.

    Fusion rules (as specified in the design doc):

    Agreement cases:
      - Both benign → final=benign, escalated=False
      - Both malicious → final=malicious, escalated=False
      - Rule suspicious + vector malicious → final=suspicious, escalated=False
      - Rule suspicious + vector benign → CONFLICT → escalated=True
    Disagreement cases:
      - Rule malicious + vector benign → escalated=True, final=suspicious
      - Rule benign + vector malicious → escalated=True, final=suspicious
    Fuzzy zone:
      - Any input in fuzzy margin zone → escalated=True
    """
    rule_dir = _rule_direction(rule_verdict.risk_level)
    vec_dir = _vector_direction(vector_verdict.margin)

    escalated = False
    reasons: list[str] = []
    final = "benign"

    # -- agreement --
    if rule_dir == "benign" and vec_dir == "benign":
        final = "benign"
    elif rule_dir == "malicious" and vec_dir == "malicious":
        final = "malicious"
    elif rule_dir == "malicious" and vec_dir == "fuzzy":
        final = "suspicious"
        escalated = True
        reasons.append("margin in fuzzy zone with rule critical/high")
    elif rule_dir == "benign" and vec_dir == "fuzzy":
        final = "benign"
        escalated = True
        reasons.append("margin in fuzzy zone despite rule low")
    elif rule_dir == "suspicious" and vec_dir == "malicious":
        final = "suspicious"
    elif rule_dir == "suspicious" and vec_dir == "benign":
        final = "suspicious"
        escalated = True
        reasons.append("rule suspicious vs vector benign — conflict")
    elif rule_dir == "suspicious" and vec_dir == "fuzzy":
        final = "suspicious"
        escalated = True
        reasons.append("margin in fuzzy zone with rule medium")

    # -- disagreement --
    elif rule_dir == "malicious" and vec_dir == "benign":
        final = "suspicious"
        escalated = True
        reasons.append("rule critical/high vs vector benign — conflict")
    elif rule_dir == "benign" and vec_dir == "malicious":
        final = "suspicious"
        escalated = True
        reasons.append("vector margin indicates malicious vs rule low — conflict")

    else:
        # fallback (shouldn't happen with valid inputs)
        final = "suspicious"
        escalated = True
        reasons.append(f"unhandled fusion case: rule={rule_dir} vector={vec_dir}")

    return Tier0Verdict(
        rule_risk=rule_verdict.risk_level,
        rule_d1=rule_verdict.d1,
        rule_d2=rule_verdict.d2,
        rule_d3=rule_verdict.d3,
        rule_matched_patterns=[
            {"id": p.id, "category": p.category, "max_weight": p.max_weight}
            for p in rule_verdict.matched_patterns
        ],
        rule_short_circuit=rule_verdict.short_circuit,
        vector_margin=vector_verdict.margin,
        vector_d_benign=vector_verdict.d_benign,
        vector_d_malicious=vector_verdict.d_malicious,
        escalated=escalated,
        escalation_reasons=reasons,
        final_verdict=final,
    )


# -- top-level judge ----------------------------------------------------------

def judge(
    text: str,
    *,
    tool_name: str = "",
    payload: dict | None = None,
    matcher: PatternMatcher | None = None,
    models_dir: str = "tier0/models",
    model_name: str = "paraphrase-multilingual-MiniLM-L12-v2",
    text_only: bool = True,
) -> Tier0Verdict:
    """Run the full Tier 0 dual-path judge on *text*.

    Returns a Tier0Verdict with per-path timing, escalation flag, and final
    verdict.  This is the primary entry point for both CLI and programmatic
    use.

    ``text_only`` (default True) judges raw prompt text with no tool-call
    context: an unknown tool scores D1=0 rather than the conservative 2, so
    content patterns + path sensitivity — not a phantom tool-danger floor —
    drive the rule path. Pass False when ``tool_name``/``payload`` describe a
    real agent tool call (then the faithful ClawSentry conservative fallback
    applies).
    """
    payload = payload or {}
    normalized = normalize_text(text)

    # Path A: rule engine
    t0 = time.perf_counter()
    rule_verdict = evaluate_rules(tool_name, payload, normalized, matcher=matcher, text_only=text_only)
    path_a_ms = (time.perf_counter() - t0) * 1000

    # Path B: vector retrieval (skip if short-circuited to CRITICAL — still
    # measure what it would have cost so we can report fairly)
    t1 = time.perf_counter()
    vec_verdict = vector_query(normalized, save_dir=models_dir, model_name=model_name)
    path_b_ms = (time.perf_counter() - t1) * 1000

    total_ms = (time.perf_counter() - t0) * 1000

    verdict = fuse(rule_verdict, vec_verdict)
    verdict.path_a_ms = path_a_ms
    verdict.path_b_ms = path_b_ms
    verdict.total_ms = total_ms
    return verdict
