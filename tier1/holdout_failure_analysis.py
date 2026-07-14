"""Reproducible, read-only analysis of Tier1 holdout false negatives."""

from __future__ import annotations

import argparse
import hashlib
import math
import json
import re
import sys
from collections import Counter
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

import numpy as np
import xgboost as xgb
from scipy.stats import fisher_exact, mannwhitneyu
from sklearn.linear_model import LinearRegression
from sklearn.metrics import recall_score, roc_auc_score

from tier1.features import FEATURE_NAMES, build_benign_profile, extract_features


OFFICIAL_COMMIT = "acd51089d05cc13fcb29644170db764a94d936f6"

AUDITED_GAP_FEATURES = (
    "current_external_len",
    "current_prompt_entropy",
    "current_probe_hits",
    "prompt_filter_block",
    "repeated_request_ratio",
    "denied_action_count",
    "probe_turn_ratio",
    "follows_recent_retrieval",
    "sensitive_read_count_so_far",
    "external_recipient_count",
    "sensitive_read_then_send",
)

# The earlier audit called all 11 features missing. Under its own proxy definition,
# follows_recent_retrieval has the local tool_web_fetch full-prefix text proxy.
LOCALLY_MISSING_FEATURES = tuple(
    name for name in AUDITED_GAP_FEATURES if name != "follows_recent_retrieval"
)

# Exact pattern and weight snapshot from the paper authors' fixed commit:
# agent_fraud/config.py:38,54-116 and agent_fraud/rule_filter.py:11-48.
OFFICIAL_PATTERN_GROUPS = {
    "override": [
        r"ignore previous",
        r"disregard instructions",
        r"system override",
        r"override",
        r"developer message",
        r"hidden instruction",
        r"system prompt",
        r"reveal .*prompt",
    ],
    "secret": [
        r"secret",
        r"confidential",
        r"credential",
        r"token",
        r"password",
        r"session cookie",
        r"ssh",
        r"api key",
        r"id_rsa",
        r"private",
        r"vault",
        r"kubeconfig",
        r"oauth",
        r"prod",
        r"customer export",
    ],
    "action": [
        r"read .*file",
        r"open .*file",
        r"send .*email",
        r"run .*shell",
        r"execute .*command",
        r"cat /etc/passwd",
        r"email the contents",
        r"send it externally",
        r"archive .*file",
        r"compress .*file",
        r"base64",
        r"chunk",
        r"upload",
    ],
    "probe": [
        r"what tools",
        r"can you",
        r"could you",
        r"would you",
        r"if needed",
        r"are you able",
        r"do you have access",
        r"help with system inspection",
    ],
}

OFFICIAL_PATTERN_WEIGHTS = {
    "prompt_override": 2.0,
    "prompt_secret": 1.0,
    "prompt_action": 1.0,
    "external_override": 1.0,
    "external_secret": 0.5,
    "external_action": 0.5,
}
OFFICIAL_RULE_THRESHOLD = 3.0

_EXTERNAL_ROLES = {"retrieved_doc", "tool_output"}
_EXTERNAL_ORIGINS = {"retrieved_content", "tool_output", "sub_agent_output"}
_SHELL_INTERPRETER = re.compile(
    r"(?:/bin/sh|(?<![\w./])sh)(?=$|[\s'\",;:()])",
    re.I,
)


def count_pattern_hits(text: str, patterns) -> int:
    """Exact upstream hit-count behavior: regex findall over lower-cased text."""
    if not text:
        return 0
    return sum(len(re.findall(pattern, text.lower())) for pattern in patterns)


def token_entropy(text: str) -> float:
    """Exact upstream whitespace-token Shannon entropy formula."""
    tokens = text.lower().split()
    if not tokens:
        return 0.0
    counts = Counter(tokens)
    total = len(tokens)
    return float(-sum((count / total) * math.log2(count / total) for count in counts.values()))


def official_prompt_signals(prompt: str, external_content: str) -> dict:
    """Compute the upstream pattern counts, score, and block decision."""
    prompt_counts = {
        group: count_pattern_hits(prompt, OFFICIAL_PATTERN_GROUPS[group])
        for group in ("override", "secret", "action", "probe")
    }
    external_counts = {
        group: count_pattern_hits(external_content, OFFICIAL_PATTERN_GROUPS[group])
        for group in ("override", "secret", "action")
    }
    score = (
        prompt_counts["override"] * OFFICIAL_PATTERN_WEIGHTS["prompt_override"]
        + prompt_counts["secret"] * OFFICIAL_PATTERN_WEIGHTS["prompt_secret"]
        + prompt_counts["action"] * OFFICIAL_PATTERN_WEIGHTS["prompt_action"]
        + external_counts["override"] * OFFICIAL_PATTERN_WEIGHTS["external_override"]
        + external_counts["secret"] * OFFICIAL_PATTERN_WEIGHTS["external_secret"]
        + external_counts["action"] * OFFICIAL_PATTERN_WEIGHTS["external_action"]
    )
    return {
        "override_hits": prompt_counts["override"],
        "secret_hits": prompt_counts["secret"],
        "action_hits": prompt_counts["action"],
        "probe_hits": prompt_counts["probe"],
        "external_override_hits": external_counts["override"],
        "external_secret_hits": external_counts["secret"],
        "external_action_hits": external_counts["action"],
        "rule_score": float(score),
        "prompt_filter_block": int(score >= OFFICIAL_RULE_THRESHOLD),
    }


def has_external_input(turn: dict) -> bool:
    return (
        turn.get("role") in _EXTERNAL_ROLES
        or turn.get("instruction_origin") in _EXTERNAL_ORIGINS
    )


def shell_interpreter_signal(text: str) -> float:
    """Candidate signal for standalone sh or /bin/sh invocation tokens."""
    return float(bool(_SHELL_INTERPRETER.search(text or "")))


def _load_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text().splitlines()
        if line.strip()
    ]


def _load_analysis_inputs(repo_root: Path):
    repo_root = Path(repo_root)
    data = repo_root / "dataset"
    train = (
        _load_jsonl(data / "processed" / "train.jsonl")
        + _load_jsonl(data / "synthetic" / "xgboost_paper_derived.jsonl")
        + _load_jsonl(data / "synthetic" / "promptfoo_redteam.jsonl")
    )
    profile = build_benign_profile(
        [record for record in train if not record["label"]["is_malicious"]]
    )
    holdout = _load_jsonl(data / "processed" / "test_holdout_family.jsonl")
    features = np.array(
        [extract_features(record, profile) for record in holdout],
        dtype=float,
    )

    model = xgb.XGBClassifier()
    model.load_model(str(repo_root / "tier1" / "models" / "xgboost_full.json"))
    probabilities = model.predict_proba(features)[:, 1]
    return train, profile, holdout, features, probabilities


def analyze_saved_model(repo_root: Path) -> dict:
    """Reproduce the current saved model's holdout false-negative set."""
    _, _, holdout, features, probabilities = _load_analysis_inputs(repo_root)
    false_negative = probabilities < 0.5
    tp = int((~false_negative).sum())
    fn = int(false_negative.sum())

    by_source = Counter(
        record["source_dataset"]
        for record, is_fn in zip(holdout, false_negative)
        if is_fn
    )
    gtfobins_mask = np.array(
        [record["source_dataset"] == "gtfobins" for record in holdout],
        dtype=bool,
    )
    tool_exec = features[:, FEATURE_NAMES.index("tool_exec")]
    gtfobins_false_negative = false_negative & gtfobins_mask

    return {
        "current_model": {
            "n": len(holdout),
            "tp": tp,
            "fn": fn,
            "recall": tp / len(holdout),
        },
        "false_negatives_by_source": dict(sorted(by_source.items())),
        "true_external_input_records": sum(
            any(has_external_input(turn) for turn in record.get("turns", []))
            for record in holdout
        ),
        "gtfobins": {
            "false_negatives": int(gtfobins_false_negative.sum()),
            "false_negatives_without_tool_exec": int(
                (gtfobins_false_negative & (tool_exec == 0)).sum()
            ),
        },
    }


def _record_text(record: dict) -> str:
    return " ".join(
        str(turn.get("raw_text", ""))
        for turn in record.get("turns", [])
        if str(turn.get("raw_text", "")).strip()
    )


def _current_prompt_external(record: dict) -> tuple[str, str]:
    turns = record.get("turns", [])
    if len(turns) != 1:
        raise ValueError("holdout gap analysis requires one visible turn per record")
    turn = turns[0]
    text = str(turn.get("raw_text", ""))
    return ("", text) if has_external_input(turn) else (text, "")


def _binary_metrics(probabilities, labels) -> dict:
    labels = np.asarray(labels, dtype=int)
    predictions = np.asarray(probabilities) >= 0.5
    tp = int(((predictions == 1) & (labels == 1)).sum())
    fp = int(((predictions == 1) & (labels == 0)).sum())
    tn = int(((predictions == 0) & (labels == 0)).sum())
    fn = int(((predictions == 0) & (labels == 1)).sum())
    return {
        "n": int(len(labels)),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "recall": float(recall_score(labels, predictions, zero_division=0)),
        "auc": (
            float(roc_auc_score(labels, probabilities))
            if len(set(labels.tolist())) > 1
            else None
        ),
    }


def _signal_exposure(records: list[dict], signal) -> dict:
    values = np.array([signal(record) for record in records], dtype=float)
    labels = np.array(
        [int(record["label"]["is_malicious"]) for record in records],
        dtype=int,
    )
    return {
        "total": int((values > 0).sum()),
        "malicious": int(((values > 0) & (labels == 1)).sum()),
        "benign": int(((values > 0) & (labels == 0)).sum()),
    }


def _fit_xgboost(features, labels):
    model = xgb.XGBClassifier(
        n_estimators=180,
        max_depth=4,
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=42,
    )
    model.fit(features, labels)
    return model


def _official_snapshot_hash() -> str:
    payload = json.dumps(
        {
            "patterns": OFFICIAL_PATTERN_GROUPS,
            "weights": OFFICIAL_PATTERN_WEIGHTS,
            "threshold": OFFICIAL_RULE_THRESHOLD,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def run_analysis(repo_root: Path) -> dict:
    """Run the full current-holdout analysis and an in-memory candidate experiment."""
    repo_root = Path(repo_root)
    train, profile, holdout, holdout_x, saved_prob = _load_analysis_inputs(repo_root)
    if not all(len(record.get("turns", [])) == 1 for record in holdout):
        raise ValueError("test_holdout_family is no longer all single-turn")

    false_negative = saved_prob < 0.5
    true_positive = ~false_negative
    prompts = []
    external_contents = []
    prompt_signals = []
    entropies = []
    for record in holdout:
        prompt, external = _current_prompt_external(record)
        prompts.append(prompt)
        external_contents.append(external)
        prompt_signals.append(official_prompt_signals(prompt, external))
        entropies.append(token_entropy(" ".join(part for part in (prompt, external) if part)))
    entropies = np.array(entropies, dtype=float)

    zero_values = np.zeros(len(holdout), dtype=float)
    gap_values = {
        "current_external_len": np.array([len(text) for text in external_contents], dtype=float),
        "current_prompt_entropy": entropies,
        "current_probe_hits": np.array(
            [item["probe_hits"] for item in prompt_signals], dtype=float
        ),
        "prompt_filter_block": np.array(
            [item["prompt_filter_block"] for item in prompt_signals], dtype=float
        ),
        "repeated_request_ratio": zero_values.copy(),
        "denied_action_count": zero_values.copy(),
        "probe_turn_ratio": zero_values.copy(),
        "sensitive_read_count_so_far": zero_values.copy(),
        "external_recipient_count": zero_values.copy(),
        "sensitive_read_then_send": zero_values.copy(),
    }
    feature_exposure = {
        name: {
            "nonzero_records": int((values != 0).sum()),
            "false_negative_nonzero": int(((values != 0) & false_negative).sum()),
            "true_positive_nonzero": int(((values != 0) & true_positive).sum()),
        }
        for name, values in gap_values.items()
    }

    entropy_fn = entropies[false_negative]
    entropy_tp = entropies[true_positive]
    fn_labels = false_negative.astype(int)
    entropy_auc = float(roc_auc_score(fn_labels, entropies))
    entropy_mw = mannwhitneyu(entropy_fn, entropy_tp, alternative="two-sided")
    lengths = holdout_x[:, [
        FEATURE_NAMES.index("prompt_length"),
        FEATURE_NAMES.index("token_count"),
    ]]
    source_names = np.array([record["source_dataset"] for record in holdout])
    source_indicator = (source_names == "gtfobins").astype(float).reshape(-1, 1)
    adjustment = np.column_stack([lengths, source_indicator])
    entropy_residual = entropies - LinearRegression().fit(
        adjustment, entropies
    ).predict(adjustment)
    residual_mw = mannwhitneyu(
        entropy_residual[false_negative],
        entropy_residual[true_positive],
        alternative="two-sided",
    )

    local_external = holdout_x[:, FEATURE_NAMES.index("has_external_content")] > 0
    exposed_fn = int((local_external & false_negative).sum())
    exposed_tp = int((local_external & true_positive).sum())
    unexposed_fn = int(((~local_external) & false_negative).sum())
    unexposed_tp = int(((~local_external) & true_positive).sum())
    outbound_fisher = fisher_exact(
        [[exposed_fn, exposed_tp], [unexposed_fn, unexposed_tp]],
        alternative="two-sided",
    )

    gtfobins = np.array(
        [record["source_dataset"] == "gtfobins" for record in holdout],
        dtype=bool,
    )
    advbench = np.array(
        [record["source_dataset"] == "advbench" for record in holdout],
        dtype=bool,
    )
    tool_exec = holdout_x[:, FEATURE_NAMES.index("tool_exec")] > 0
    shell_signal = np.array(
        [shell_interpreter_signal(_record_text(record)) for record in holdout],
        dtype=float,
    )
    gtfobins_fn = gtfobins & false_negative
    gtfobins_tp = gtfobins & true_positive
    tool_exec_table = {
        "false_negative_present": int((gtfobins_fn & tool_exec).sum()),
        "false_negative_absent": int((gtfobins_fn & ~tool_exec).sum()),
        "true_positive_present": int((gtfobins_tp & tool_exec).sum()),
        "true_positive_absent": int((gtfobins_tp & ~tool_exec).sum()),
    }
    tool_exec_fisher = fisher_exact(
        [
            [
                tool_exec_table["false_negative_absent"],
                tool_exec_table["true_positive_absent"],
            ],
            [
                tool_exec_table["false_negative_present"],
                tool_exec_table["true_positive_present"],
            ],
        ],
        alternative="two-sided",
    )
    gtfobins_cases = [
        {
            "id": record["id"],
            "probability": float(probability),
            "tool_exec": int(exec_value),
            "shell_interpreter_signal": int(shell_value),
            "text": _record_text(record),
        }
        for record, probability, exec_value, shell_value, is_gtfo_fn in zip(
            holdout,
            saved_prob,
            tool_exec,
            shell_signal,
            gtfobins_fn,
        )
        if is_gtfo_fn
    ]

    data = repo_root / "dataset"
    test_indist = _load_jsonl(data / "processed" / "test_indist.jsonl")
    known_benign_eval_sets = {
        "val": _load_jsonl(data / "processed" / "val.jsonl"),
        "test_indist": test_indist,
        "test_on_target": _load_jsonl(data / "processed" / "test_on_target.jsonl"),
        "legacy_multiturn_benign": _load_jsonl(
            data / "processed" / "test_holdout_multiturn_benign.jsonl"
        ),
        "reviewed_multiturn": _load_jsonl(
            data / "processed" / "test_holdout_multiturn.jsonl"
        ),
    }
    known_benign_exposure = {
        name: sum(
            not record["label"]["is_malicious"]
            and bool(shell_interpreter_signal(_record_text(record)))
            for record in records
        )
        for name, records in known_benign_eval_sets.items()
    }
    train_x = np.array([extract_features(record, profile) for record in train], dtype=float)
    test_indist_x = np.array(
        [extract_features(record, profile) for record in test_indist],
        dtype=float,
    )
    train_y = np.array([int(record["label"]["is_malicious"]) for record in train])
    test_indist_y = np.array(
        [int(record["label"]["is_malicious"]) for record in test_indist]
    )
    holdout_y = np.ones(len(holdout), dtype=int)
    train_shell = np.array(
        [shell_interpreter_signal(_record_text(record)) for record in train],
        dtype=float,
    )
    test_indist_shell = np.array(
        [shell_interpreter_signal(_record_text(record)) for record in test_indist],
        dtype=float,
    )
    train_entropy = np.array(
        [
            token_entropy(str(record.get("turns", [{}])[-1].get("raw_text", "")))
            for record in train
        ],
        dtype=float,
    )
    test_indist_entropy = np.array(
        [
            token_entropy(str(record.get("turns", [{}])[-1].get("raw_text", "")))
            for record in test_indist
        ],
        dtype=float,
    )

    baseline_model = _fit_xgboost(train_x, train_y)
    entropy_model = _fit_xgboost(
        np.column_stack([train_x, train_entropy]),
        train_y,
    )
    candidate_model = _fit_xgboost(
        np.column_stack([train_x, train_shell]),
        train_y,
    )
    baseline_holdout_prob = baseline_model.predict_proba(holdout_x)[:, 1]
    baseline_probability_difference = np.abs(saved_prob - baseline_holdout_prob)
    candidate_holdout_prob = candidate_model.predict_proba(
        np.column_stack([holdout_x, shell_signal])
    )[:, 1]
    baseline_indist_prob = baseline_model.predict_proba(test_indist_x)[:, 1]
    entropy_holdout_prob = entropy_model.predict_proba(
        np.column_stack([holdout_x, entropies])
    )[:, 1]
    entropy_indist_prob = entropy_model.predict_proba(
        np.column_stack([test_indist_x, test_indist_entropy])
    )[:, 1]
    candidate_indist_prob = candidate_model.predict_proba(
        np.column_stack([test_indist_x, test_indist_shell])
    )[:, 1]

    def source_metrics(probabilities, mask):
        predictions = probabilities[mask] >= 0.5
        return {
            "n": int(mask.sum()),
            "tp": int(predictions.sum()),
            "fn": int((~predictions).sum()),
            "recall": float(predictions.mean()),
        }

    by_source = Counter(
        record["source_dataset"]
        for record, is_fn in zip(holdout, false_negative)
        if is_fn
    )
    local_follows_proxy = holdout_x[:, FEATURE_NAMES.index("tool_web_fetch")] > 0
    historical_prefix = json.loads(
        (repo_root / "reports" / "tier1_prefix_eval.json").read_text()
    )["test_holdout"]

    return {
        "analysis_environment": {
            "xgboost_version": xgb.__version__,
        },
        "baseline_reproduction": {
            "max_abs_probability_difference": float(
                baseline_probability_difference.max()
            ),
            "mean_abs_probability_difference": float(
                baseline_probability_difference.mean()
            ),
            "threshold_disagreements": int(
                ((saved_prob >= 0.5) != (baseline_holdout_prob >= 0.5)).sum()
            ),
        },
        "official_source": {
            "repository": "Yunicorn228/A-Low-Latency-Fraud-Detection",
            "commit": OFFICIAL_COMMIT,
            "pattern_snapshot_sha256": _official_snapshot_hash(),
        },
        "metric_provenance": {
            "stale_prefix_report": {
                "tp": int(historical_prefix["early_detection_first_flag_at_prefix"]["1"]),
                "fn": int(historical_prefix["early_detection_first_flag_at_prefix"]["never"]),
                "recall": historical_prefix["Recall"],
            },
            "current_saved_model": {
                "n": len(holdout),
                "tp": int(true_positive.sum()),
                "fn": int(false_negative.sum()),
                "recall": float(true_positive.mean()),
            },
            "false_negative_set_overlap_note": (
                "The historical and current FN sets use different model/feature revisions; "
                "do not mix their case identities."
            ),
        },
        "false_negatives_by_source": dict(sorted(by_source.items())),
        "holdout_structure": {
            "records": len(holdout),
            "single_turn_records": sum(len(record.get("turns", [])) == 1 for record in holdout),
            "user_role_records": sum(
                record["turns"][0].get("role") == "user" for record in holdout
            ),
            "agent_plan_role_records": sum(
                record["turns"][0].get("role") == "agent_plan" for record in holdout
            ),
            "user_direct_origin_records": sum(
                record["turns"][0].get("instruction_origin") == "user_direct"
                for record in holdout
            ),
            "true_external_input_records": sum(bool(text) for text in external_contents),
            "agent_plan_training_records": sum(
                any(turn.get("role") == "agent_plan" for turn in record.get("turns", []))
                for record in train
            ),
            "benign_agent_plan_training_records": sum(
                not record["label"]["is_malicious"]
                and any(
                    turn.get("role") == "agent_plan"
                    for turn in record.get("turns", [])
                )
                for record in train
            ),
        },
        "paper_gap_hypothesis": {
            "prior_audit_candidate_count": len(AUDITED_GAP_FEATURES),
            "corrected_missing_count": len(LOCALLY_MISSING_FEATURES),
            "classification_correction": {
                "feature": "follows_recent_retrieval",
                "local_proxy": "tool_web_fetch",
                "reason": (
                    "official prior-two proposed_tool check vs local full-prefix text regex"
                ),
            },
            "feature_exposure": feature_exposure,
            "local_follows_proxy_nonzero_records": int(local_follows_proxy.sum()),
            "entropy_association": {
                "false_negative_mean": float(entropy_fn.mean()),
                "true_positive_mean": float(entropy_tp.mean()),
                "false_negative_median": float(np.median(entropy_fn)),
                "true_positive_median": float(np.median(entropy_tp)),
                "auc_for_false_negative": entropy_auc,
                "mann_whitney_pvalue": float(entropy_mw.pvalue),
                "source_and_length_residual_mann_whitney_pvalue": float(
                    residual_mw.pvalue
                ),
                "by_source": {
                    source: {
                        "false_negative_mean": float(
                            entropies[(source_names == source) & false_negative].mean()
                        ),
                        "true_positive_mean": float(
                            entropies[(source_names == source) & true_positive].mean()
                        ),
                        "mann_whitney_pvalue": float(
                            mannwhitneyu(
                                entropies[(source_names == source) & false_negative],
                                entropies[(source_names == source) & true_positive],
                                alternative="two-sided",
                            ).pvalue
                        ),
                    }
                    for source in sorted(set(source_names.tolist()))
                },
            },
            "entropy_experiment": {
                "feature_definition": (
                    "last-visible-turn whitespace-token Shannon entropy; exact on this "
                    "single-turn holdout, a schema proxy on multi-turn training records"
                ),
                "holdout": {
                    "baseline": _binary_metrics(baseline_holdout_prob, holdout_y),
                    "candidate": _binary_metrics(entropy_holdout_prob, holdout_y),
                },
                "test_indist": {
                    "baseline": _binary_metrics(baseline_indist_prob, test_indist_y),
                    "candidate": _binary_metrics(entropy_indist_prob, test_indist_y),
                },
                "assessment": "holdout_gain_below_one_percentage_point",
            },
        },
        "reversed_external_proxy": {
            "local_feature": "has_external_content",
            "actual_semantics": "outbound network-like text",
            "exposed_records": int(local_external.sum()),
            "exposed_false_negatives": exposed_fn,
            "exposed_true_positives": exposed_tp,
            "unexposed_false_negatives": unexposed_fn,
            "unexposed_true_positives": unexposed_tp,
            "fisher_odds_ratio": float(outbound_fisher.statistic),
            "fisher_pvalue": float(outbound_fisher.pvalue),
        },
        "advbench_scope_mixture": {
            "records": int(advbench.sum()),
            "false_negatives": int((advbench & false_negative).sum()),
            "false_negatives_with_domain_gap_note": int(
                sum(
                    is_advbench
                    and is_fn
                    and "domain-gap" in str(record.get("notes", ""))
                    for record, is_advbench, is_fn in zip(
                        holdout, advbench, false_negative
                    )
                )
            ),
            "note": (
                "These records are labeled in the dataset as general content-safety "
                "harmful prompts rather than Agent action-risk."
            ),
        },
        "gtfobins_action_representation": {
            "records": int(gtfobins.sum()),
            "false_negatives": int(gtfobins_fn.sum()),
            "false_negatives_without_tool_exec": int((gtfobins_fn & ~tool_exec).sum()),
            "tool_exec_table": tool_exec_table,
            "tool_exec_absence_fisher_odds_ratio": float(tool_exec_fisher.statistic),
            "tool_exec_absence_fisher_pvalue": float(tool_exec_fisher.pvalue),
            "false_negative_cases": gtfobins_cases,
        },
        "candidate_shell_signal": {
            "definition": "standalone sh or /bin/sh token in model-visible text",
            "not_official_feature": True,
            "exposure": {
                "train_total": int((train_shell > 0).sum()),
                "train_malicious": int(((train_shell > 0) & (train_y == 1)).sum()),
                "train_benign": int(((train_shell > 0) & (train_y == 0)).sum()),
                "test_indist_total": int((test_indist_shell > 0).sum()),
                "test_indist_malicious": int(
                    ((test_indist_shell > 0) & (test_indist_y == 1)).sum()
                ),
                "test_indist_benign": int(
                    ((test_indist_shell > 0) & (test_indist_y == 0)).sum()
                ),
                "holdout_total": int((shell_signal > 0).sum()),
            },
            "known_benign_eval_exposure": known_benign_exposure,
            "experiment": {
                "holdout": {
                    "baseline": _binary_metrics(baseline_holdout_prob, holdout_y),
                    "candidate": _binary_metrics(candidate_holdout_prob, holdout_y),
                },
                "gtfobins": {
                    "baseline": source_metrics(baseline_holdout_prob, gtfobins),
                    "candidate": source_metrics(candidate_holdout_prob, gtfobins),
                },
                "test_indist": {
                    "baseline": _binary_metrics(baseline_indist_prob, test_indist_y),
                    "candidate": _binary_metrics(candidate_indist_prob, test_indist_y),
                },
            },
            "limitation": (
                "No train or test_indist benign record exposes this signal; the experiment "
                "cannot estimate false positives on legitimate shell operations. The signal "
                "was selected after inspecting this holdout's false negatives, so its measured "
                "gain is post-hoc diagnostic evidence rather than independent generalization."
            ),
        },
        "disposition": {
            "paper_gap_features": "do_not_add",
            "external_direction_fix": "semantically_needed_but_not_a_holdout_recall_fix",
            "shell_action_parser": "validate_with_benign_controls_first",
            "primary_holdout_issue": "scope_mixture_plus_action_representation",
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "output",
        type=Path,
        nargs="?",
        default=Path(__file__).resolve().parents[1]
        / "reports"
        / "tier1_holdout_failure_analysis_20260714.json",
    )
    args = parser.parse_args()
    repo_root = Path(__file__).resolve().parents[1]
    result = run_analysis(repo_root)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(f"written {args.output}")


if __name__ == "__main__":
    main()
