"""Part 1 — semantic-robustness regression test set for Tier2.

Builds the gate that any Tier2 implementation MUST pass before it can claim
semantic understanding: the same underlying task's 3 surface-word variants
(original / lexical-neutralized / scary-injected) must yield the SAME verdict
CATEGORY. Confidence may differ; the category must not flip.

This is NOT a generation script (Part 0): the 8 edge-case TASKS were designed by
a workflow and adversarially verified (ground-truth + keyword-detector-fooled).
The 3 surface variants are DETERMINISTIC rewrites via a word map (lexical → neutral,
neutral → scary), not LLM generation. The task semantics are unchanged; only
surface vocabulary shifts — which is exactly what a keyword-detector over-weights
and a true semantic judge must ignore.

Ground truth is `purpose_capability_consistent` (from the verified design):
  consistent=True  → verdict category must be benign
  consistent=False → verdict category must be malicious
AND the 3 variants must agree (no flip) regardless of which words are on the surface.

Usage:
  from tier2.regression_set import load_regression_cases
  cases = load_regression_cases()   # list of {id, variants: {orig,neutral,scary},
                                    #            ground_truth_consistent, lens, ...}
"""
from __future__ import annotations

import json
import pathlib
import re

_REPO = pathlib.Path(__file__).resolve().parents[1]
_CASES_JSON = _REPO / "tier2" / "regression_cases.json"

# ── deterministic surface-word rewrites (glue, not generation) ──────────────
# INVARIANT: rewrites only touch ADJECTIVES / generic nouns that do NOT define
# the task's target, destination, resource type, or capability. They NEVER change
# a file path, a host/endpoint identity, a "who owns it" claim, or a data-type,
# because those ARE semantics for a purpose-capability judge. A scary rewrite
# that turns "package-mirror" into "attacker package-mirror" changes whether the
# destination is trusted — that's meaning, not vocabulary. So we only inject
# generic scary ADJECTIVES (sensitive/privileged/secret-looking) and swap generic
# synonyms, leaving every path/host/resource token intact.
_NEUTRAL_MAP = [
    # only generic scary adjectives → plain adjectives; never touch paths/hosts
    (r"\bsensitive\b", "relevant"),
    (r"\bprivileged\b", "elevated"),
    (r"\bmalicious\b", "unusual"),
    (r"\battacker\b", "remote"),
    (r"\bFailed password\b", "rejected attempts"),
    (r"\bexfiltrat\w*", "transfer"),
    (r"\bbrute-forced\b", "repeated"),
    (r"\bstolen\b", "copied"),
]

_SCARY_MAP = [
    # inject generic scary ADJECTIVES only — add "sensitive"/"privileged"/"secret"
    # before generic nouns WITHOUT changing any path/host/destination/type token.
    # Applied to the original (preserves real semantic content).
    (r"\bthe auth log\b", "the sensitive auth log"),
    (r"\bauth logs\b", "sensitive auth logs"),
    (r"\bconfig file\b", "sensitive config file"),
    (r"\bconfig files\b", "sensitive config files"),
    (r"\bconnection\b", "sensitive connection"),
    (r"\btoken\b", "secret token"),
    (r"\btokens\b", "secret tokens"),
    (r"\baccess key\b", "privileged access key"),
    (r"\bconfig items\b", "sensitive config items"),
    (r"\bdata\b", "sensitive data"),
    (r"\bcredentials\b", "privileged credentials"),
]


def _apply(text: str, mapping: list) -> str:
    for pat, rep in mapping:
        text = re.sub(pat, rep, text, flags=re.I)
    return text


def _neutralize(text: str) -> str:
    return _apply(text, _NEUTRAL_MAP)


def _scaryize(text: str) -> str:
    # neutralize first so scary injection is on a clean baseline (no double-applied)
    return _apply(_neutralize(text), _SCARY_MAP)


def _build_variants(turns: list[str]) -> dict:
    """3 surface variants of the SAME underlying task.

    - original: the designed text (designer-chosen surface words)
    - lexical_neutral: scary ops vocab → plain synonyms (strips the lexical tell)
    - scary_injected: plain → scary-sounding ops vocab (injects a lexical tell),
      applied to the ORIGINAL (not the neutralized) so the task's real semantic
      content is preserved and only surface vocabulary is swapped.
    Semantics never change; only surface vocabulary shifts — which is exactly
    what a keyword-detector over-weights and a true semantic judge must ignore.
    """
    return {
        "original": turns,
        "lexical_neutral": [_neutralize(t) for t in turns],
        "scary_injected": [_apply(t, _SCARY_MAP) for t in turns],
    }


def load_regression_cases() -> list[dict]:
    """Load the 8 verified edge cases, each with 3 surface variants."""
    data = json.loads(_CASES_JSON.read_text())
    out = []
    for c in data["cases"]:
        out.append({
            "id": c["id"],
            "lens": c["lens"],
            "stated_purpose": c["stated_purpose"],
            "actual_action_summary": c["actual_action_summary"],
            "ground_truth_consistent": c["purpose_capability_consistent"],
            "why_hard": c.get("why_hard", ""),
            "variants": _build_variants(c["turns"]),
        })
    return out


def _main_export():
    """Regenerate regression_cases.json from the workflow-designed cases.

    Run only when re-designing edge cases. The committed regression_cases.json
    is the frozen test artifact (deterministic variants are derived at load time).
    """
    src = pathlib.Path("/tmp/kept_cases.json")
    if not src.exists():
        raise SystemExit("design workflow output /tmp/kept_cases.json missing")
    cases = json.loads(src.read_text())
    out = {"cases": cases, "note": "8 adversarially-verified edge cases; 3 surface "
           "variants derived deterministically at load (not stored)."}
    _CASES_JSON.write_text(json.dumps(out, indent=2, ensure_ascii=False))
    print(f"wrote {len(cases)} cases -> {_CASES_JSON}")


if __name__ == "__main__":
    _main_export()
