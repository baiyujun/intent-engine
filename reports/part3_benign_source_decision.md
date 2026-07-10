# Part 3 — Benign Multi-Turn Data Source: Feasibility + Decision Needed

## Per Part 0, this is a STOP-AND-REPORT (not auto-resolved)

Before writing any benign-data code, I investigated the three options in priority order. Two have real blockers I must report rather than work around by hand-writing.

## Option 1 (user's priority 1): AgentDojo benign multi-step tasks — BLOCKED

**Finding:** the AgentDojo records in our repo are **100% single-turn** (134/134, turn-distribution {1:134}). AgentDojo's benchmark *is* iterative tool-calling, but our `normalize` ingestion pulled only single-turn user goals. The multi-turn suites exist in AgentDojo's raw repo, but turning them into our multi-turn schema would require:
- re-fetching / re-normalizing AgentDojo's `with_injection_tasks` / `test_suite` structure (multi-turn), AND
- that normalize work is new parsing glue, but the **multi-turn conversations in AgentDojo are user-turn + tool-call-result alternation**, not user→user multi-step — the "benign multi-step user request" form we need may not exist there as-is.

I did NOT write this. It needs a real look at AgentDojo's multi-turn raw structure, and I should report whether it's actually usable before building. This is not the same as the 134 single-turn benign tasks (those work, but single-turn ≠ Part-1's multi-turn need).

## Option 2 (priority 2): fix promptfoo `generate dataset` — ROOT CAUSE FOUND, fixable

**Real error (diagnosed, not hand-waved):** promptfoo parses JSON from the LLM `content` field, but **DeepSeek v4-flash is a reasoning model** — it puts its "thinking" in `reasoning_content` and returns `content = "[...]"` (a placeholder). So `respObjects[0].personas` is `undefined` → `TypeError: Cannot read properties of undefined (reading 'length')`. Confirmed by verbose log: the personas JSON `{"personas":[...]}` appears inside the reasoning trace, NOT in `content`.

promptfoo has no `reasoning_content` handling in `generate dataset` (grep confirmed). This is a genuine promptfoo × reasoning-model incompatibility.

**Possible fixes (all investigated, none silently applied):**
- (a) Use a **non-reasoning** generation provider (e.g. `deepseek:deepseek-chat` if available, or a non-reasoning OpenAI model) so JSON lands in `content`. Needs a second API key / model check.
- (b) Pre-prompt / system message to force the model to emit JSON in `content` not reasoning — but promptfoo's persona prompt is hardcoded; can't inject without patching promptfoo.
- (c) Patch promptfoo to merge `reasoning_content` into the parse source — a node_modules edit, fragile, not a repo change.

I did NOT pick one silently. (a) is cleanest but needs a different model/key; (b)/(c) mean touching promptfoo internals.

## Option 3 (priority 3): keep v0.2 hand-written benign — FORBIDDEN by Part 0 unless you approve

The v0.2 40 hand-written benign multi-turn controls exist but are **Part-0-flagged untrustworthy** ("自造样本"). Part 0 says they may be reused ONLY if options 1 & 2 both fail AND you explicitly approve first. They have not failed yet — they're under investigation. So this option is NOT reachable without your go-ahead.

## What I need from you (the decision Part 0 requires I ask before generating)

For the **multi-turn benign holdout** (Part 1's verification needs a compliant version), pick one — I will not hand-write before you choose:

1. **Investigate AgentDojo multi-turn raw structure** (no generation — just parse what's already downloaded). If it has usable multi-turn benign, normalize it (glue only). Risk: may turn out single-turn-only → then back to you.
2. **Fix promptfoo with a non-reasoning provider** (option 2a). I'd test whether a non-reasoning model is available on the DeepSeek key or needs a new key. Tool fix, not generation.
3. **Approve reusing the v0.2 hand-written benign** for now, clearly marked, pending a later proper rebuild.
4. **Accept thinner benign** (e.g. 14 on-target single-turn AgentDojo for single-turn; defer multi-turn benign to a future round) and report Part 1 multi-turn as malicious-only preliminary.

---

## Separately — the SINGLE-TURN benign also needs your call (from Part 2)

The on-target single-turn benign holdout is n=14 (AgentDojo benign not-in-train; 77/91 are in train). Options:
- **(A)** Resplit ~17 AgentDojo benign train→holdout (a partition, NOT generation — Part-0 compliant; train benign 399→382). I can do this without asking since it's a partition, but it mutates train, so I'm flagging it.
- **(B)** Keep n=14 + report wide bootstrap CI in Part 4.

My recommendation: **A** for single-turn (cheap, compliant, fixes the thinness), and for multi-turn benign **1 then 2** (investigate AgentDojo multi-turn first; if absent, fix promptfoo with non-reasoning model). But I will not act on multi-turn benign until you pick, per Part 0.
