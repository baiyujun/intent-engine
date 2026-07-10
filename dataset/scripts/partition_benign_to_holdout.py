"""Part 3(b): single-turn benign partition — move ~17 AgentDojo benign
from train to the on-target holdout (a partition, NOT generation; Part-0 compliant).

Leakage check (done, see reports/part3b_single_turn_partition.md):
- build_benign_profile (novelty_recipient/novelty_filepath reference) is fitted on
  ALL 3599 benign training records incl. the 77 AgentDojo benign.
- The 77 AgentDojo benign contributed 2 of the profile's recipients (sarah.connor@...,
  david.smith@...). The 17 to move do NOT contain those 2 recipient records, and the
  2 recipient records STAY in train, so the re-fitted profile keeps them.
- => we still re-fit the profile from the reduced train (382 benign) for correctness:
  the holdout must be scored by a profile that did not see its records.

This script MUTATES train.jsonl (benign 399 -> 382) and rebuilds the on-target
holdout to ~31 benign (14 not-in-train + 17 moved) + 161 malicious.
"""
import json
import pathlib

DATA = pathlib.Path(__file__).resolve().parents[2] / "dataset"  # intent-engine/dataset
P = DATA / "processed"
S = DATA / "synthetic"


def load(p):
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]


def write(p, recs):
    p.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in recs) + "\n")


def main():
    train = load(P / "train.jsonl")
    ad_ben = [r for r in train if r.get("source_dataset") == "agentdojo"
              and not r["label"]["is_malicious"]]
    ad_sorted = sorted(ad_ben, key=lambda r: r.get("id", ""))
    to_move = ad_sorted[-17:]   # 17 -> holdout
    move_ids = {r.get("id") for r in to_move}

    # new train: drop the 17 moved
    new_train = [r for r in train if r.get("id") not in move_ids]
    old_ben = sum(1 for r in train if not r["label"]["is_malicious"])
    new_ben = sum(1 for r in new_train if not r["label"]["is_malicious"])
    write(P / "train.jsonl", new_train)
    print(f"train: {len(train)} -> {len(new_train)} (benign {old_ben} -> {new_ben})")

    # rebuild on-target holdout benign = 14 not-in-train(original) + 17 moved
    # (re-run the on-target filter logic, but now include the moved AgentDojo benign)
    val = load(P / "val.jsonl")
    testi = load(P / "test_indist.jsonl")
    # AgentDojo benign across val/test that are NOT in new train
    new_train_ids = {r.get("id") for r in new_train}
    ad_ben_all = []
    for src in [val, testi, load(P / "test_holdout_family.jsonl")]:
        for r in src:
            if (r.get("source_dataset") == "agentdojo"
                    and not r["label"]["is_malicious"]
                    and r.get("id") not in new_train_ids):
                ad_ben_all.append(r)
    # add the 17 moved (now not in train)
    ben_holdout = ad_ben_all + to_move
    # dedup by canonical text
    seen, dedup = set(), []
    for r in ben_holdout:
        t = r["turns"][0].get("raw_text", "").strip().lower()
        if t in seen:
            continue
        seen.add(t); dedup.append(r)

    write(P / "test_on_target_benign.jsonl", dedup)
    # combined on-target (mal from Part 2 + new benign)
    mal = load(P / "test_on_target_mal.jsonl")
    write(P / "test_on_target.jsonl", mal + dedup)
    leak = sum(1 for r in mal + dedup if r.get("id") in new_train_ids)
    print(f"on-target holdout: {len(mal)} mal + {len(dedup)} ben = {len(mal)+len(dedup)} (train-id leak={leak})")
    # save the moved id list for traceability
    (P.parent / "reports" / "part3b_moved_ids.json").write_text(
        json.dumps({"moved_to_holdout": sorted(move_ids),
                    "n_moved": len(move_ids)}, indent=2))
    print(f"moved ids saved -> dataset/reports/part3b_moved_ids.json")


if __name__ == "__main__":
    main()
