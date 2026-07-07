# Coverage Gaps — v0

- **Languages**: English-heavy; Chinese/other-language samples limited (multilingual dedup model used, but source coverage is EN).
- **Modalities**: text-only unless BIPIA multimodal present; no audio/vision pipeline.
- **Tool types**: bounded by AgentDojo fixed suites; gaps for many real-world tools/APIs.
- **Red-team LLM**: no live LLM key this run; redteam_candidates.jsonl are DRY-RUN templated perturbations only (pending key).
- **License-held-out sources**: BIPIA, R-Judge, PurpleLlama CyberSecEval, jayavibhav, imoxto, LlamaFirewall rules, MITRE sample-derivation are in unified.jsonl but NOT in any split (needs_confirmation).
- **JailbreakBench/AdvBench domain gap**: general content-safety jailbreaks, not Agent action-risk; per-source ablation recommended; samples carry the domain-gap note.
- **GTFOBins/LOLBAS**: command patterns only — no complete payloads (by design).
- **Skipped sources**: see reports/fetch_errors.log for any fetch that failed (network/rate-limit/ToU).