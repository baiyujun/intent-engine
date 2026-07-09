"""Tier 2 — the expensive semantic LLM judge.

Tier 2 is the slow, high-precision semantic arbiter. It is invoked ONLY for
interactions that Tier 0 / Tier 1 escalated (Tier 0 fusion flagged
``escalated=True``, or Tier 1 XGBoost probability landed in the borderline
zone). Its job is to make the final benign/suspicious/malicious call that the
cheaper tiers could not resolve, by reading the full multi-turn interaction in
context.

This corresponds to Vigil-LLM's "Transformer scanner / LLM arbiter" role —
see ``notes/vigil_llm.md``. That note explicitly states this scanner is
"**Not in v0** (would be Tier 2 LLM arbiter)"; the vigil table maps it onto our
Tier 2. v0 therefore ships this module as a **STUB**: the judge interface and
the intended prompt are defined and documented, but no real LLM call is made.
``judge()`` returns a fixed ``not_implemented`` verdict.

The common Verdict result format mirrors Vigil's ``ScanResult`` (score +
label + details) and is shared with the lower tiers where the field names
overlap (``score``, ``confidence``, ``evidence`` align with the Tier 0
``Tier0Verdict`` spirit; see ``tier0/fusion.py``).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class Tier2Verdict:
    """Result of a Tier 2 semantic LLM judge call.

    Attributes
    ----------
    status : str
        One of ``'not_implemented'`` (v0 stub), ``'benign'``, ``'suspicious'``,
        ``'malicious'``. Mirrors the lower-tier final-verdict vocabulary plus
        the explicit stub sentinel.
    score : float
        Maliciousness score in [0.0, 1.0]. Defaults to 0.0 (no signal in v0).
    confidence : float
        Judge confidence in its own verdict, [0.0, 1.0]. Defaults to 0.0.
    reasoning : str
        Human-readable explanation. Defaults to ''.
    evidence : list[str]
        Concrete pointers (turn indices, matched spans) supporting the
        verdict. Defaults to [].
    model : str
        Identifier of the model that produced this verdict (e.g.
        ``'claude-sonnet-4-6'``). Empty for the v0 stub until populated.
    latency_ms : float
        Wall-clock time of the LLM call in ms. 0.0 for the v0 stub.
    """
    status: str
    score: float = 0.0
    confidence: float = 0.0
    reasoning: str = ""
    evidence: list[str] = field(default_factory=list)
    model: str = ""
    latency_ms: float = 0.0


class Tier2Judge(ABC):
    """Abstract base for Tier 2 semantic LLM judges.

    Contract
    --------
    A concrete judge consumes a single ``interaction`` dict (the agent intent
    record — ``turns``, ``structured_action``, optional context) plus an
    optional ``context`` dict carrying lower-tier signals, and returns a
    :class:`Tier2Verdict`. The verdict MUST populate ``status`` (one of
    ``not_implemented`` / ``benign`` / ``suspicious`` / ``malicious``); real
    implementations additionally populate ``score``, ``confidence``,
    ``reasoning``, ``evidence``, ``model`` and ``latency_ms`` and enforce a
    latency budget (see :class:`tier2.llm_judge.Tier2LLMJudge`).

    Subclasses implement :meth:`judge`.
    """

    @abstractmethod
    def judge(self, interaction: dict, context: dict | None = None) -> Tier2Verdict:
        """Judge a single agent interaction.

        Parameters
        ----------
        interaction : dict
            The agent intent record. Expected to contain ``turns`` (list of
            ``{'raw_text': str, ...}``) and ``structured_action``
            (``{'action_type': str, ...}``); see ``tier1/features.py`` and
            ``dataset/src/schema.py``.
        context : dict | None
            Optional lower-tier signals to bias the judge (e.g. Tier 0
            ``final_verdict`` + escalation reasons, Tier 1 XGBoost
            probability). Passed through verbatim by the concrete judge.

        Returns
        -------
        Tier2Verdict
            A populated verdict. v0 stubs return ``status='not_implemented'``.
        """
        raise NotImplementedError
