# Data Card — Agent Intent-Recognition Dataset v0

## Per-source counts (unified.jsonl)

| source | n | license | license_status | fetched_at | verified |
|---|---|---|---|---|---|
| advbench | 520 | MIT | ok | 2026-07-07T08:23:57Z | 2026-07-07 llm-attacks repo MIT |
| agentdojo | 2 | MIT | ok | 2026-07-07T08:20:05Z | 2026-07-07 raw repo LICENSE |
| clawsentry_rules | 6 | MIT | ok | - | 2026-07-07 AI45Lab/ClawSentry local clone |
| lolbas | 521 | GPL-3.0 | ok | 2026-07-07T08:24:01Z | 2026-07-07 GitHub API; copyleft noted |
| mitre_attack_samples | 858 | custom | needs_confirmation | - | 2026-07-07 ATT&CK Terms of Use; taxonomy use ok, sample derivation needs confirmation |
| near_dup_pairs | 16 | own | ok | - | self-generated |

## license_status breakdown
{'ok': 1065, 'needs_confirmation': 858}

## Distributions
risk_category: {'goal_hijack': 520, 'benign': 9, 'prompt_injection': 7, 'tool_misuse': 521, 'other_unsafe': 858, 'reconnaissance': 8}
attack_family: {'advbench_gcg': 520, 'benign': 9, 'indirect_injection_slack_message': 1, 'command_injection': 3, 'prompt_injection': 3, 'code_exec': 400, 'defense_evasion': 50, 'network_request': 62, 'reconnaissance': 4, 'credential_access': 5, 'mitre_technique_rewrite': 858, 'recon_precursor': 8}
instruction_origin: {'user_direct': 1923, 'tool_output': 1}

## Benign vs malicious
malicious=1906 benign=17 precursor(not-mal)=8
near-dup-pair+precursor share = 0.4%

## Splits
{
  "train": 414,
  "val": 49,
  "test_indist": 56,
  "test_holdout_family": 510
}

## Figures
- reports/figures/risk_category.png
- reports/figures/attack_family.png
- reports/figures/instruction_origin.png