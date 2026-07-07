# Data Card — Agent Intent-Recognition Dataset v0

## Per-source counts (unified.jsonl)

| source | n | license | license_status | fetched_at | verified |
|---|---|---|---|---|---|
| advbench | 520 | MIT | ok | 2026-07-07T10:40:35Z | 2026-07-07 llm-attacks repo MIT |
| agentdojo | 183 | MIT | ok | 2026-07-07T10:39:00Z | 2026-07-07 raw repo LICENSE |
| clawsentry_rules | 25 | MIT | ok | - | 2026-07-07 AI45Lab/ClawSentry local clone |
| gtfobins | 920 | GPL-3.0 | ok | 2026-07-07T10:40:36Z | 2026-07-07 GitHub API; copyleft noted |
| hf_deepset | 662 | Apache-2.0 | ok | - | 2026-07-07 HF tags license:apache-2.0 |
| hf_jayavibhav | 4338 | none | needs_confirmation | - | 2026-07-07 no license tag on HF |
| injecagent | 2108 | MIT | ok | 2026-07-07T10:39:02Z | 2026-07-07 raw file LICENCE on main (British spelling) |
| jailbreakbench | 1097 | MIT | ok | - | 2026-07-07 repo pyproject.toml + JBB-Behaviors HF + artifacts README |
| llamafirewall_rules | 113 | custom | needs_confirmation | 2026-07-07T10:42:55Z | 2026-07-07 under PurpleLlama custom license |
| lolbas | 521 | GPL-3.0 | ok | 2026-07-07T10:40:38Z | 2026-07-07 GitHub API; copyleft noted |
| mitre_attack_samples | 858 | custom | needs_confirmation | - | 2026-07-07 ATT&CK Terms of Use; taxonomy use ok, sample derivation needs confirmation |
| near_dup_pairs | 16 | own | ok | - | self-generated |
| rjudge | 571 | none | needs_confirmation | 2026-07-07T10:39:05Z | 2026-07-07 no LICENSE file found |

## license_status breakdown
{'ok': 6052, 'needs_confirmation': 5880}

## Distributions
risk_category: {'goal_hijack': 1617, 'prompt_injection': 3868, 'benign': 3814, 'tool_misuse': 1466, 'other_unsafe': 858, 'reconnaissance': 8, 'unauthorized_action': 301}
attack_family: {'advbench_gcg': 520, 'indirect_injection_banking': 17, 'benign': 3544, 'indirect_injection_slack': 5, 'indirect_injection_travel': 11, 'indirect_injection_workspace': 21, 'goal_hijack': 5, 'tool_misuse': 161, 'privilege_abuse': 5, 'code_execution': 6, 'supply_chain': 2, 'file_read': 216, 'shell_spawn': 351, 'exfil': 78, 'file_write': 97, 'reverse_shell': 24, 'direct_injection': 1593, 'indirect_injection': 2108, 'jailbreak_dsn': 195, 'jailbreak_gcg': 200, 'jailbreak_jbc': 100, 'jailbreak_pair': 237, 'jailbreak_prompt_with_random_search': 365, 'lf_rule_derived': 113, 'code_exec': 400, 'defense_evasion': 50, 'network_request': 62, 'reconnaissance': 4, 'credential_access': 5, 'mitre_technique_rewrite': 858, 'recon_precursor': 8, 'unintended': 157, 'injection': 414}
instruction_origin: {'user_direct': 14405, 'tool_output': 2162}

## Benign vs malicious
malicious=8110 benign=3822 precursor(not-mal)=8
near_dup_pairs share = 0.1% (precursor count=8)

## Splits
{
  "train": 2149,
  "val": 267,
  "test_indist": 275,
  "test_holdout_family": 793
}

## Figures
- reports/figures/risk_category.png
- reports/figures/attack_family.png
- reports/figures/instruction_origin.png