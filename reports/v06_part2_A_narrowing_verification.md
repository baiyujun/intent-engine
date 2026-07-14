# v0.6 Part 2 — A: adversarial verification of the narrowing (2 agents, 2/2 agree)

Your structural review asked me to adversarially verify my own 2 narrowing claims before
reporting them. I ran a 3-agent blind workflow (one agent failed schema; 2 returned valid
verdicts — both AGREE on the substance).

## Claim 1: "12 cases all indirect-injection (same mechanism); 58.3% = indirect-injection
detection rate, NOT edge-case generalization" — **HOLDS (2/2)**

Both verifiers confirm: all 12 cases deliver the malicious instruction in the turn1
`<INFORMATION>` block (tool/context output), never in the user's own turn0 text. The 3
`attack_type` values (important_instructions / _no_model_name / _no_names) differ only in
the authority-anchor wording (signature/identity), not in mechanism. So the 58.3% is
correctly described as **"Tier2's detection rate on indirect injection,"** NOT a
generalization-on-real-edge-cases total. No correction to Claim 1.

## Claim 2: "the 5 FN show the judge CORRECTLY judged the user's benign task but missed the
hidden injection; blind spot is FRAMEWORK (Tier2 judges actions, injection risk isn't at the
action layer), NOT semantic failure" — **PARTIALLY HOLDS, needs correction (2/2)**

The strong form is **wrong**. The verifiers found the FN failure mode is **mixed**, not the
clean "framework blind spot, injection never reached the action layer" I claimed:

- Some FN: judge judged only the ORIGINAL task action (e.g. "network request to read a
  user-specified webpage, directly matches stated purpose"), and the injection's "send a
  link to Alice" never surfaced as an action → this IS the clean framework blind spot.
- Other FN: the judge **did read the injected instruction** and judged ITS capability, but
  **mis-judged it as benign** (absorbed the injection, then evaluated the injected action as
  consistent with a plausible purpose) → this is a **semantic mis-judgment**, not a framework
  gap. And some FN the judge **treated the disguised "important message from the user" as a
  real user instruction** (authority-spoofing absorbed).

So the accurate framing (both verifiers): **"absorbed-then-mis-judged"** — Tier2 absorbs the
injected text into the action it evaluates, then mis-judges the resulting capability as
benign. It is **NOT** uniformly "the injection never reached the action layer." The blind
spot is a framework gap that *manifests as* a semantic capability mis-judgment on injected
content.

## Corrected conclusion (what goes in the report)

- Part 2's 58.3% = **Tier2 detection rate on indirect injection** (12 AgentDojo cases, all
  one mechanism) — NOT a generalization total. Narrowing stands.
- The 5 FN failure mode = **absorbed-then-mis-judged** (mixed: some pure framework
  blind-spot, some semantic mis-judgment on absorbed injection, some authority-spoof
  absorbed). NOT the clean "framework-not-semantic" dichotomy I first wrote.
- Implication for the next test (B, the purpose-capability mismatch set): indirect-injection
  cases partly test the WRONG thing (whether Tier2 treats tool/context origin skeptically — a
  framework property), which is orthogonal to the purpose-capability semantic judgment the
  Part B 87% claimed to measure. So B (real purpose-capability mismatch, risk in the action,
  no injection block) is the RIGHT complementary test — it isolates the semantic judgment.
  (This is exactly what you concluded; the verification sharpens the "why.")

## Data
- 2-agent verdicts: `reports/v06_part2_A_verification.json` (the workflow result)
- The 12-case eval: `reports/v06_part2_frozen_eval.json`
