"""Tier 3 — final orchestration + MOF corrective feedback.

Tier 3 has two responsibilities:

  1. **Orchestration** — combine the per-tier verdicts (Tier 0
     :class:`~tier0.fusion.Tier0Verdict`, Tier 1 XGBoost probability, Tier 2
     :class:`~tier2.base.Tier2Verdict`) into a single final
     allow / block / escalate decision, with a human-readable audit trail.
     The intended policy is :data:`INTENDED_POLICY`.

  2. **MOF corrective feedback** (InjectGuard, see
     ``notes/injectguard_mof.md``) — when a malicious interaction slips through
     as a false negative, generate a *benign corrective sample* that still
     contains the trigger phrase (override / ignore / system) but is wrapped
     in a benign context (e.g. a debugging / hardware-doc sentence), then mix
     these into retraining at ~10% so the classifier learns that a trigger
     phrase alone is not sufficient evidence.

In v0 BOTH responsibilities are **STUBS** returning ``not_implemented``:
the interfaces, the intended policy, and the MOF recipe are documented, but
no real orchestration logic or corrective-sample synthesis runs. This keeps
the Step 6 pipeline callable end-to-end without a retraining loop.
"""
from __future__ import annotations

from dataclasses import dataclass, field


# -- intended orchestration policy --------------------------------------------

INTENDED_POLICY: list[str] = [
    "any tier malicious -> block",
    "tier1 borderline (0.4..0.6) or tier2 suspicious -> escalate",
    "all benign -> allow",
    "tier_used = highest tier with a non-not_implemented verdict",
]
"""Intended orchestration policy (documented; orchestrate() is a v0 stub).

The real ``orchestrate()`` will reduce over the three tier verdicts:

  * Tier 0 — ``Tier0Verdict.final_verdict`` (benign / suspicious / malicious).
  * Tier 1 — the XGBoost malicious probability (0.4..0.6 = borderline).
  * Tier 2 — ``Tier2Verdict.status`` (benign / suspicious / malicious).

Rules (highest priority first):
  1. If ANY tier reports ``malicious`` → final ``block``.
  2. Else if Tier 1 probability is in [0.4, 0.6] OR Tier 2 reports
     ``suspicious`` → final ``escalate``.
  3. Else (all tiers benign / absent) → final ``allow``.
  4. ``tier_used`` = the highest tier index that produced a verdict other than
     ``not_implemented`` (0 < 1 < 2), so the audit trail records which tier
     actually decided.
"""


# -- data models ---------------------------------------------------------------

@dataclass
class FinalDecision:
    """Final allow / block / escalate decision with an audit trail.

    Attributes
    ----------
    status : str
        One of ``'not_implemented'`` (v0 stub), ``'allow'``, ``'block'``,
        ``'escalate'``.
    verdict : str
        Short human-readable verdict label. Defaults to ''.
    confidence : float
        Decision confidence in [0.0, 1.0]. Defaults to 0.0.
    audit_trail : list[str]
        Ordered human-readable trail of which tier fired which rule. Defaults
        to [].
    tier_used : str
        Identifier of the highest tier that produced a real verdict
        (e.g. ``'tier0'`` / ``'tier1'`` / ``'tier2'``), or '' when no tier ran.
    """
    status: str
    verdict: str = ""
    confidence: float = 0.0
    audit_trail: list[str] = field(default_factory=list)
    tier_used: str = ""


@dataclass
class CorrectiveSample:
    """A benign corrective sample produced by MOF feedback.

    Attributes
    ----------
    status : str
        ``'not_implemented'`` (v0 stub) or ``'ok'``.
    sample : dict | None
        The synthesized benign near-duplicate record (same schema as a dataset
        intent record) containing the trigger phrase. ``None`` in v0.
    trigger_phrase : str
        The trigger phrase (override / ignore / system ...) extracted from the
        false-negative record and preserved in the benign sample. Defaults to
        ''.
    notes : str
        Free-form provenance / construction notes. Defaults to ''.
    """
    status: str
    sample: dict | None = None
    trigger_phrase: str = ""
    notes: str = ""


# -- orchestrator --------------------------------------------------------------

class Tier3Orchestrator:
    """Combine per-tier verdicts into a final decision + generate MOF samples.

    v0: both :meth:`orchestrate` and the MOF methods are stubs returning
    ``not_implemented``. The intended policy (:data:`INTENDED_POLICY`) and the
    MOF recipe (see ``notes/injectguard_mof.md``) are documented for v1.
    """

    def orchestrate(
        self,
        tier0_verdict=None,
        tier1_verdict=None,
        tier2_verdict=None,
    ) -> FinalDecision:
        """v0 STUB — returns a fixed ``not_implemented`` decision.

        No policy is applied. The real implementation would:

          TODO(v0->v1):
            - read Tier0Verdict.final_verdict from tier0_verdict,
            - read the Tier 1 XGBoost malicious probability from tier1_verdict,
            - read Tier2Verdict.status from tier2_verdict,
            - apply INTENDED_POLICY (any malicious -> block; tier1 borderline
              0.4..0.6 or tier2 suspicious -> escalate; else allow),
            - set tier_used to the highest tier with a non-not_implemented
              verdict, and build the audit_trail from the per-tier reasons.
        """
        return FinalDecision(
            status="not_implemented",
            audit_trail=[
                "Tier 3 orchestrator is a v0 stub — intended policy: "
                + "; ".join(INTENDED_POLICY)
            ],
        )

    def corrective_update(self, false_negative_record: dict) -> CorrectiveSample:
        """v0 STUB — generate one MOF corrective sample for a false negative.

        The real implementation would:

          TODO(v0->v1):
            - extract the record's trigger phrase from its turns (scan for
              override / ignore / system patterns, e.g. reuse the regexes in
              ``tier1/features.py``: RE_SYSTEM_OVERRIDE, RE_IGNORE_INSTR,
              RE_OVERRIDE_ATTEMPT),
            - build a benign context containing that trigger phrase via the
              parameterized synth-template approach (notes/injectguard_mof.md),
              e.g. "Please ignore previous error messages and retry" or
              "The system override switch is on the back panel",
            - return a near-duplicate BENIGN record (same trigger phrase,
              benign label) for retraining, to be mixed in at ~10% of total
              training data so the classifier learns that a trigger phrase
              alone does not imply malicious intent.
        """
        return CorrectiveSample(
            status="not_implemented",
            notes="MOF corrective feedback is a v0 stub.",
        )

    def generate_corrective_samples(self, malicious_records: list[dict], n: int = 0) -> list[CorrectiveSample]:
        """v0 STUB — batch MOF corrective-sample generation.

        Returns an empty list in v0 (documented stub; no samples synthesized).

          TODO(v0->v1): for each malicious record (or up to ``n`` of them),
          call :meth:`corrective_update` to build a benign corrective sample
          containing the record's trigger phrase, and return the batch for
          mixing into retraining at ~10%.
        """
        return []
