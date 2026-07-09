"""Build data_card.md + coverage_gaps.md + distribution figures."""
import json, pathlib, collections
import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
from src.normalize_utils import iter_jsonl, processed_dir, reports_dir
from src.licenses import load_license_config

def _all_records():
    p = processed_dir()/"unified.jsonl"
    return list(iter_jsonl(p)) if p.exists() else []

def _bar(counter, title, path):
    if not counter: return
    path = pathlib.Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    plt.figure(figsize=(8,4)); plt.bar(list(counter.keys()), list(counter.values()))
    plt.title(title); plt.xticks(rotation=30, ha="right"); plt.tight_layout()
    plt.savefig(path, dpi=110); plt.close()

def main():
    recs = _all_records()
    cfg = load_license_config()
    by_src = collections.Counter(r["source_dataset"] for r in recs)
    by_cat = collections.Counter(r["label"]["risk_category"] for r in recs)
    by_fam = collections.Counter(r["label"]["attack_family"] for r in recs)
    by_origin = collections.Counter(t["instruction_origin"] for r in recs for t in r["turns"])
    by_ls = collections.Counter(r["license_status"] for r in recs)
    n_mal = sum(1 for r in recs if r["label"]["is_malicious"])
    n_prec = sum(1 for r in recs if r["label"].get("attack_stage_precursor"))
    n_near_dup = sum(1 for r in recs if r.get("source_dataset") == "near_dup_pairs")
    fig = reports_dir()/"figures"
    _bar(by_cat, "risk_category", fig/"risk_category.png")
    _bar(by_fam, "attack_family", fig/"attack_family.png")
    _bar(by_origin, "instruction_origin", fig/"instruction_origin.png")
    # per-split sizes
    pd = processed_dir()
    splits = {n: sum(1 for _ in iter_jsonl(pd/f"{n}.jsonl"))
              for n in ("train","val","test_indist","test_holdout_family") if (pd/f"{n}.jsonl").exists()}
    manifest = {}
    rep = reports_dir()
    mp = rep/"fetch_manifest.json"
    if mp.exists(): manifest = json.loads(mp.read_text())
    lines = ["# Data Card — Agent Intent-Recognition Dataset v0\n",
             "## Per-source counts (unified.jsonl)\n",
             "| source | n | license | license_status | fetched_at | verified |",
             "|---|---|---|---|---|---|"]
    for src, n in sorted(by_src.items()):
        e = cfg.get(src, {})
        m = manifest.get(src, {})
        lines.append(f"| {src} | {n} | {e.get('license_spdx','?')} | {e.get('license_status','?')} | {m.get('fetched_at','-')} | {e.get('verified','-')} |")
    lines += ["\n## license_status breakdown", f"{dict(by_ls)}",
              "\n## Distributions", f"risk_category: {dict(by_cat)}", f"attack_family: {dict(by_fam)}",
              f"instruction_origin: {dict(by_origin)}",
              "\n## Benign vs malicious", f"malicious={n_mal} benign={len(recs)-n_mal} precursor(not-mal)={n_prec}",
              f"near_dup_pairs share = {round(n_near_dup/max(len(recs),1)*100,1)}% (precursor count={n_prec})",
              "\n## Splits", json.dumps(splits, indent=2),
              "\n## Figures", "- reports/figures/risk_category.png", "- reports/figures/attack_family.png",
              "- reports/figures/instruction_origin.png"]
    (rep/"data_card.md").write_text("\n".join(lines))
    gaps = ["# Coverage Gaps — v0\n",
            "- **Languages**: English-heavy; Chinese/other-language samples limited (multilingual dedup model used, but source coverage is EN).",
            "- **Modalities**: text-only unless BIPIA multimodal present; no audio/vision pipeline.",
            "- **Tool types**: bounded by AgentDojo fixed suites; gaps for many real-world tools/APIs.",
            "- **Red-team LLM**: no live LLM key this run; redteam_candidates.jsonl are DRY-RUN templated perturbations only (pending key).",
            "- **License-held-out sources**: BIPIA, R-Judge, PurpleLlama CyberSecEval, jayavibhav, imoxto, LlamaFirewall rules, MITRE sample-derivation are in unified.jsonl but NOT in any split (needs_confirmation).",
            "- **JailbreakBench/AdvBench domain gap**: general content-safety jailbreaks, not Agent action-risk; per-source ablation recommended; samples carry the domain-gap note.",
            "- **GTFOBins/LOLBAS**: command patterns only — no complete payloads (by design).",
            "- **Near-dup pairs**: v0 has 16 constructed pairs (~0.2% of unified); the spec §5 ≥10% target is unmet — deferred to v0.1 expansion (more benign-lookalike + precursor templates).",
            "- **Skipped sources**: see reports/fetch_errors.log for any fetch that failed (network/rate-limit/ToU)."]
    (rep/"coverage_gaps.md").write_text("\n".join(gaps))
if __name__ == "__main__": main()
