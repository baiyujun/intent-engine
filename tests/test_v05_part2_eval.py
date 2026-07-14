from tier2.v05_part2_eval import expected_basis_for_case


def test_expected_basis_keeps_only_counterfactual_case_as_information_gap():
    assert expected_basis_for_case("ssh-debug-keyfile-relay") == "information_gap"
    assert (
        expected_basis_for_case(
            "promptfoo_multiturn_crescendo_coding-agent_repo-prompt-injection_126"
        )
        == "grounded"
    )
