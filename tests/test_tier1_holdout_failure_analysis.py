from pathlib import Path

from tier1.holdout_failure_analysis import (
    AUDITED_GAP_FEATURES,
    LOCALLY_MISSING_FEATURES,
    analyze_saved_model,
    count_pattern_hits,
    has_external_input,
    official_prompt_signals,
    run_analysis,
    shell_interpreter_signal,
    token_entropy,
)


def test_official_prompt_signal_formulas_match_fixed_upstream_semantics():
    signals = official_prompt_signals("Ignore previous secret", "")

    assert count_pattern_hits("Could you help?", [r"could you"]) == 1
    assert token_entropy("a a b b") == 1.0
    assert token_entropy("") == 0.0
    assert signals["override_hits"] == 1
    assert signals["secret_hits"] == 1
    assert signals["rule_score"] == 3.0
    assert signals["prompt_filter_block"] == 1


def test_external_input_uses_role_or_instruction_origin_not_outbound_words():
    assert has_external_input(
        {"role": "retrieved_doc", "instruction_origin": "user_direct"}
    )
    assert has_external_input(
        {"role": "user", "instruction_origin": "tool_output"}
    )
    assert not has_external_input(
        {"role": "user", "instruction_origin": "user_direct", "raw_text": "email it"}
    )


def test_shell_interpreter_signal_matches_shell_tokens_not_substrings():
    assert shell_interpreter_signal("flock -u / /bin/sh -p") == 1.0
    assert shell_interpreter_signal("reset; sh 1>&0 2>&0") == 1.0
    assert shell_interpreter_signal("capsh --gid=0 --uid=0 --") == 0.0
    assert shell_interpreter_signal("Can you cat scripts/build.sh") == 0.0
    assert shell_interpreter_signal("update the cash forecast") == 0.0


def test_prior_audit_gap_count_is_corrected_without_dropping_the_signal():
    assert len(AUDITED_GAP_FEATURES) == 11
    assert len(LOCALLY_MISSING_FEATURES) == 10
    assert "follows_recent_retrieval" in AUDITED_GAP_FEATURES
    assert "follows_recent_retrieval" not in LOCALLY_MISSING_FEATURES


def test_current_saved_model_holdout_failure_set_is_reproducible():
    repo = Path(__file__).resolve().parents[1]

    result = analyze_saved_model(repo)

    assert result["current_model"] == {
        "n": 793,
        "tp": 520,
        "fn": 273,
        "recall": 520 / 793,
    }
    assert result["false_negatives_by_source"] == {
        "advbench": 245,
        "gtfobins": 28,
    }
    assert result["true_external_input_records"] == 0
    assert result["gtfobins"]["false_negatives"] == 28
    assert result["gtfobins"]["false_negatives_without_tool_exec"] == 27


def test_full_analysis_falsifies_paper_gap_hypothesis_and_bounds_candidate():
    repo = Path(__file__).resolve().parents[1]

    result = run_analysis(repo)

    assert "project_revision" not in result
    assert result["analysis_environment"]["xgboost_version"]
    assert result["baseline_reproduction"] == {
        "max_abs_probability_difference": 0.0,
        "mean_abs_probability_difference": 0.0,
        "threshold_disagreements": 0,
    }
    nonzero = {
        name
        for name, details in result["paper_gap_hypothesis"]["feature_exposure"].items()
        if details["nonzero_records"]
    }
    assert nonzero == {"current_prompt_entropy"}
    assert result["paper_gap_hypothesis"]["local_follows_proxy_nonzero_records"] == 0
    assert result["holdout_structure"]["user_role_records"] == 510
    assert result["holdout_structure"]["agent_plan_role_records"] == 283
    assert result["holdout_structure"]["user_direct_origin_records"] == 793
    assert result["advbench_scope_mixture"]["false_negatives"] == 245
    assert (
        result["advbench_scope_mixture"]["false_negatives_with_domain_gap_note"]
        == 245
    )
    assert result["reversed_external_proxy"]["exposed_records"] == 31
    assert result["reversed_external_proxy"]["fisher_pvalue"] > 0.05
    entropy_experiment = result["paper_gap_hypothesis"]["entropy_experiment"]
    assert entropy_experiment["holdout"]["candidate"]["tp"] == 522
    assert entropy_experiment["test_indist"]["candidate"]["tp"] == 209
    assert entropy_experiment["test_indist"]["candidate"]["fp"] == 32
    assert (
        entropy_experiment["holdout"]["candidate"]["recall"]
        - entropy_experiment["holdout"]["baseline"]["recall"]
        < 0.01
    )
    assert result["candidate_shell_signal"]["exposure"]["train_benign"] == 0
    assert result["gtfobins_action_representation"]["tool_exec_table"] == {
        "false_negative_present": 1,
        "false_negative_absent": 27,
        "true_positive_present": 42,
        "true_positive_absent": 213,
    }
    assert all(
        count == 0
        for count in result["candidate_shell_signal"][
            "known_benign_eval_exposure"
        ].values()
    )
    assert (
        result["candidate_shell_signal"]["experiment"]["holdout"]["candidate"]["recall"]
        > result["candidate_shell_signal"]["experiment"]["holdout"]["baseline"]["recall"]
    )
    assert result["candidate_shell_signal"]["experiment"]["holdout"]["candidate"][
        "tp"
    ] == 545
    assert result["candidate_shell_signal"]["experiment"]["gtfobins"]["candidate"][
        "tp"
    ] == 280
    shell_indist = result["candidate_shell_signal"]["experiment"]["test_indist"][
        "candidate"
    ]
    assert shell_indist["n"] == 275
    assert shell_indist["tp"] == 209
    assert shell_indist["fp"] == 31
    assert shell_indist["tn"] == 21
    assert shell_indist["fn"] == 14
    assert shell_indist["recall"] == 209 / 223
    assert result["disposition"]["paper_gap_features"] == "do_not_add"
    assert result["disposition"]["shell_action_parser"] == "validate_with_benign_controls_first"
