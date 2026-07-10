"""Part 2: rebuild a TARGET-ALIGNED single-turn test set.

v0.2 audit found the single-turn test sets were off-target:
  - jailbreakbench: "bomb/anorexia/hate-speech" content-safety jailbreaks, NOT
    agent action-risk. The CAVEAT in normalize_jailbreakbench.py already said
    "domain-gap: general content-safety jailbreak, not Agent action-risk; ablation
    candidate" — but no one ever filtered it.
  - hf_deepset benign: "What is wonderful?" general QA, not coding-agent tasks.
  - gtfobins/lolbas: raw shell command strings (e.g. 'rundll32.exe ...'), a data-
    TYPE mismatch (shell commands != natural-language intent).

This module FILTERS existing processed records (no new generation — it is a
classifier/partitioner, glue only, honoring the Part-0 reuse rule):
  1. Malicious: keep only JBB categories in TARGET_MAL + AdvBench goals matching
     TARGET keywords (code-exec/privilege/exfiltration); drop bomb/hate/anorexia/etc.
  2. Benign: use AgentDojo benign tool-calling tasks (already-approved compliant
     source) instead of hf_deepset general QA.
  3. GTFOBins/LOLBAS raw command strings: EXCLUDED from the natural-language
     intent test (data-type mismatch); they're left in train as-is.
  4. Build a TRUE single-turn holdout disjoint from train by id (the old
     test_indist was in-distribution — 61% JBB text identical to train).

Outputs:
  dataset/processed/test_on_target_mal.jsonl      (malicious, target-filtered)
  dataset/processed/test_on_target_benign.jsonl  (AgentDojo benign, NOT in train)
  dataset/processed/test_on_target.jsonl         (combined holdout)
"""
import json
import pathlib
import re
import sys

_REPO = pathlib.Path(__file__).resolve().parents[2]  # intent-engine root
sys.path.insert(0, str(_REPO / "dataset" / "src"))

DATA = _REPO / "dataset" / "processed"

# JailbreakBench categories that ARE our target (agent action-risk):
# Malware/Hacking (code exec), Fraud/Deception (social engineering to action),
# Privacy (data exfil), Economic harm (fraud to action).
TARGET_JBB_CATS = {
    "Malware/Hacking", "Fraud/Deception", "Privacy", "Economic harm",
}
# AdvBench has no category; classify by goal keywords.
TARGET_ADV_KW = re.compile(
    r"(?i)(malware|vulnerab|hack|exploit|phish|ransomware|backdoor|keylog|botnet|"
    r"reverse.shell|privilege.escalat|sudo|root.access|credentials?|passwords?|"
    r"tokens?|secret.keys?|steal.*(data|information)|exfiltrat|unauthorized|"
    r"bypass.*(auth|security|firewall)|sql.injection|command.injection|"
    r"remote.code.exec|persisten|lateral.mov|credential.dump)"
)
# AdvBench goals that are explicitly OFF-target (drop):
OFFTARGET_KW = re.compile(
    r"(?i)(bomb|explosive|firearm|weapon|meth|drug|anorexi|bulimi|self.harm|suicide|"
    r"racist|nazi|holocaust|sex(ual|ism)?|rape|child|violent|gore|harass|"
    r"misinformation|fake.news|election|political|cult|bestialit|animal.cruelty)"
)


def load_jsonl(p):
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]


def write_jsonl(p, recs):
    p.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in recs) + "\n")


def jbb_category(r):
    m = re.search(r"category=([^;]+)", r.get("notes", ""))
    return m.group(1).strip() if m else None


def goal_text(r):
    sa = r.get("structured_action", {}) or {}
    return (sa.get("stated_purpose") or "") + " " + r["turns"][0].get("raw_text", "")


def is_target_malicious(r):
    src = r.get("source_dataset", "")
    if src == "jailbreakbench":
        cat = jbb_category(r)
        if cat in TARGET_JBB_CATS:
            return True
        return False  # every other JBB category is off-target
    if src == "advbench":
        g = goal_text(r)
        # must match target keywords AND NOT match off-target
        if OFFTARGET_KW.search(g):
            return False
        return bool(TARGET_ADV_KW.search(g))
    return False


def main():
    # gather all processed single-turn records (train+val+test) to filter from
    pool = []
    for f in ["train.jsonl", "val.jsonl", "test_indist.jsonl", "test_holdout_family.jsonl"]:
        pool += load_jsonl(DATA / f)

    train = load_jsonl(DATA / "train.jsonl")
    train_ids = {r.get("id") for r in train}
    # also exclude training benign agentdojo ids for a true benign holdout
    train_benign_agentdojo_ids = {
        r.get("id") for r in train
        if r.get("source_dataset") == "agentdojo" and not r["label"]["is_malicious"]
    }

    # 1. malicious on-target (JBB target cats + AdvBench target goals)
    mal_pool = [r for r in pool if r.get("label", {}).get("is_malicious") and is_target_malicious(r)]
    # exclude any that leaked into train (by id) for a true holdout
    mal_holdout = [r for r in mal_pool if r.get("id") not in train_ids]
    # dedup by canonical text to avoid near-duplicate variants
    seen_text = set()
    mal_dedup = []
    for r in mal_holdout:
        t = r["turns"][0].get("raw_text", "").strip().lower()
        if t in seen_text:
            continue
        seen_text.add(t)
        mal_dedup.append(r)

    # 2. benign on-target: AgentDojo benign tasks NOT in train
    ben_pool = [
        r for r in pool
        if r.get("source_dataset") == "agentdojo"
        and not r.get("label", {}).get("is_malicious")
        and r.get("id") not in train_benign_agentdojo_ids
    ]
    # include val/test agentdojo benign that are genuinely disjoint from train
    # (val/test were already split off, but test_indist was in-distribution by
    #  source; for benign we take the agentdojo benign that are NOT in train_ids)
    ben_holdout = [r for r in ben_pool if r.get("id") not in train_ids]
    ben_dedup = []
    seen_ben = set()
    for r in ben_holdout:
        t = r["turns"][0].get("raw_text", "").strip().lower()
        if t in seen_ben:
            continue
        seen_ben.add(t)
        ben_dedup.append(r)

    # write
    write_jsonl(DATA / "test_on_target_mal.jsonl", mal_dedup)
    write_jsonl(DATA / "test_on_target_benign.jsonl", ben_dedup)
    write_jsonl(DATA / "test_on_target.jsonl", mal_dedup + ben_dedup)

    # report
    from collections import Counter
    mal_src = Counter(r.get("source_dataset") for r in mal_dedup)
    mal_cat = Counter(jbb_category(r) for r in mal_dedup if r.get("source_dataset") == "jailbreakbench")
    print(f"ON-TARGET malicious holdout: {len(mal_dedup)}", file=sys.stderr)
    print(f"  by source: {dict(mal_src)}", file=sys.stderr)
    print(f"  JBB categories: {dict(mal_cat)}", file=sys.stderr)
    print(f"ON-TARGET benign holdout (AgentDojo, not in train): {len(ben_dedup)}", file=sys.stderr)
    print(f"  combined: {len(mal_dedup)+len(ben_dedup)}", file=sys.stderr)
    # sanity: confirm disjoint from train
    leak = sum(1 for r in mal_dedup + ben_dedup if r.get("id") in train_ids)
    print(f"  train-id leakage check: {leak} (must be 0 for a true holdout)", file=sys.stderr)
    # what was dropped (off-target) — report so the filter is auditable
    dropped_jbb = [r for r in pool if r.get("source_dataset") == "jailbreakbench"
                   and r.get("label", {}).get("is_malicious") and not is_target_malicious(r)]
    print(f"  JBB DROPPED (off-target cats): {len(dropped_jbb)}", file=sys.stderr)
    print(f"    dropped cats: {dict(Counter(jbb_category(r) for r in dropped_jbb))}", file=sys.stderr)
    dropped_adv = [r for r in pool if r.get("source_dataset") == "advbench" and not is_target_malicious(r)]
    print(f"  AdvBench DROPPED (off-target goals): {len(dropped_adv)}", file=sys.stderr)


if __name__ == "__main__":
    main()
