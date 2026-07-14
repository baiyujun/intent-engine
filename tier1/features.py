"""Tier 1 feature extraction — project-specific XGBoost features in 5 groups.

This 40-dimensional heuristic adaptation is inspired by the five signal groups
in arXiv:2605.01143. It does not reproduce the authors' 42 experimental columns;
see reports/tier1_paper_feature_mapping_audit.md.

Groups / indices:
  prompt  0-10   (11)  per-turn surface signals
  session 11-18  (8)   turn-indexed behavioural aggregates
  tool    19-24  (6)   full-prefix text action proxies + mismatch flag
  context 25-30  (6)   outbound/suspicious full-prefix text proxies
  fraud   31-39  (9)   fraud-inspired trajectory / novelty / exfil-gap features

Honest feature-count note:
  The authors' fixed implementation has 11 trajectory columns. This local fraud
  group has 9: seven conceptual proxies plus two project-only novelty-score
  aliases. It omits the official sensitive-read count, external-recipient count,
  and read-then-send fields; a distinct-tool proxy lives in the local session
  group. The total is therefore 40, not the official 42.

Notes / honest caveats baked into the code:
  - denied_tool_call_count and failed_tool_call_count are always 0 because the
    v0 schema has no tool-result/permission fields; they are kept as reserved
    columns so the 8-feature session group matches the paper.
  - novelty_* features need a benign_profile (built from training benign
    records). Pass None to use empty sets -> every recipient/filepath is
    "novel" by default, so the *_flag features default to 0 when there is no
    matching turn.
  - novelty_*_score are exact aliases of their corresponding flags. They are
    retained for saved-model compatibility, not claimed as independent paper
    features.
  - Several fraud-inspired features (cumulative_risk, monotonicity,
    action_burst, context_exfil_gap) are degenerate (=0 / -1) for the
    single-turn records that dominate the real datasets; they only carry
    signal on the multi-turn synthetic families.
"""
import re
import sys
import pathlib

# ── self-contained import shim (conftest covers pytest; this covers standalone) ──
_REPO = pathlib.Path(__file__).resolve().parents[1]
_DS = _REPO / "dataset" / "src"
if str(_DS) not in sys.path:
    sys.path.insert(0, str(_DS))

from schema import validate_record, canonical_text  # noqa: E402  (re-exported helpers)

# ── regex patterns ───────────────────────────────────────────────────────────
SUSPICIOUS_KW = re.compile(
    r"(?i)(ignore|override|secret|password|admin|root|sudo|bash|shell|exec|rm\s+-rf|curl|wget|nc|/etc/shadow)"
)
RE_SYSTEM_OVERRIDE = re.compile(r"(?i)(ignore previous|override|system prompt)")
RE_IGNORE_INSTR = re.compile(r"(?i)ignore.{0,10}(instruction|previous|above)")
RE_NEW_INSTR = re.compile(r"(?i)(new instruction|instead|your task is now)")
RE_OVERRIDE_ATTEMPT = re.compile(r"(?i)(pretend|act as|you are now|roleplay)")
RE_PRIV_ESCALATION = re.compile(r"(?i)(sudo|root|admin|elevated|superuser)")
RE_SUMMARIZE = re.compile(r"(?i)(summarize|overview|digest|condense)")
RE_WEB_FETCH = re.compile(r"(?i)(fetch|pull|retrieve|browse).{0,20}https?://")
RE_SENSITIVE = re.compile(
    r"(?i)(shadow|passwd|id_rsa|credentials|\.env|private\.key|token\.json|bash_history|aws|gnupg|ssh/)"
)

# classify_action keyword groups (checked in this order — network_request before
# file_read so "send" wins over a possible "display" co-mention).
# NOTE: these are substring matches (no \b) — "README" matches \bread\ inside
# it. This is a pre-existing imprecision; changing it would shift ALL features
# that depend on classify_action. Kept as-is for stability.
_ACT_NETWORK = re.compile(r"(?i)(send|email|upload|post|forward|pipe)")
_ACT_FILE = re.compile(r"(?i)(read|cat|open|display|dump|show)")
_ACT_EXEC = re.compile(r"(?i)(run|execute|sudo|shell|bash)")

# Word-boundary variants for the within-turn mismatch check only — avoids the
# "README" false-positive (read|cat|… matches inside "README") that would
# inflate task_tool_mismatch_flag for benign exec commands mentioning README.
_ACT_NETWORK_WB = re.compile(r"(?i)\b(send|email|upload|post|forward|pipe)\b")
_ACT_FILE_WB = re.compile(r"(?i)\b(read|cat|open|display|dump|show)\b")
_ACT_EXEC_WB = re.compile(r"(?i)\b(run|execute|sudo|shell|bash)\b")

# recipient / filepath extraction for novelty features.
# NOTE: the naive `(?:to|at|https?://|@)(\S+)` filepath/recipient regexes were
# BUGGY — `_RE_FILEPATH` captured only the first token after the read verb
# (e.g. "the" from "Read the private key file at ~/.ssh/id_rsa"), so sensitive
# paths were never recognised as novel. `_RE_RECIPIENT` matched "at"/"to" as
# substrings (e.g. "att**at**cker" -> "tacker@...", or "to**at**" -> "a"). Both
# are replaced below with patterns that capture the actual path / recipient.
_RE_RECIPIENT = re.compile(
    r"(?i)(?:send|email|upload|post|forward|pipe).*?"
    r"((?:https?://\S+|[\w.+-]+@[\w.-]+))"
)
# a path-like token: absolute (/x), home (~), relative-dot (./x, ../x), or
# plain relative-with-slash (config/database.yml, src/main.py, secrets/x.json)
_RE_FILEPATH = re.compile(
    r"(?i)(?:read|cat|open|display|dump|show)\b.*?"
    r"((?:~/|/|\.\.?/|[\w.\-]+/)[\w./\-]+)"
)

# suspicious-keyword weights for prompt_suspicion_score group-1 feature 4
_KW_WEIGHTS = [
    (re.compile(r"(?i)override"), 4),
    (re.compile(r"(?i)ignore"), 3),
    (re.compile(r"(?i)/etc/shadow"), 3),
    (re.compile(r"(?i)(secret|password)"), 2),
    (re.compile(r"(?i)(admin|root)"), 2),
    (re.compile(r"(?i)(sudo|bash|shell|exec)"), 2),
    (re.compile(r"(?i)(rm\s+-rf|curl|wget|nc)"), 1),
]


def classify_action(text: str) -> str:
    """Map a single turn's raw text to a coarse action class.

    Order matters: network_request is checked BEFORE file_read so that
    "send ... " is not swallowed by a stray "show" / "display".
    """
    if _ACT_NETWORK.search(text):
        return "network_request"
    if _ACT_FILE.search(text):
        return "file_read"
    if _ACT_EXEC.search(text):
        return "exec"
    return "unknown"


def tool_risk(action: str) -> int:
    """Discrete per-action risk score used by the fraud-inspired group."""
    return {"unknown": 0, "file_read": 1, "network_request": 2, "exec": 3}.get(action, 0)


def _sensitive_in_text(text: str) -> bool:
    return bool(RE_SENSITIVE.search(text))


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    inter = len(a & b)
    return inter / len(a | b)


def build_benign_profile(records: list[dict]) -> dict:
    """Scan benign records and collect known recipients + filepaths.

    'recipients': substrings captured from network_request turns via
      r'(?i)(?:to|at|https?://|@)(\\S+)'.
    'filepaths':  substrings captured from file_read turns via
      r'(?i)(?:read|cat|open|display|dump|show)\\s+(\\S+)'.

    Returns {'recipients': set, 'filepaths': set}.
    """
    recipients: set[str] = set()
    filepaths: set[str] = set()
    for r in records:
        if not r.get("label", {}).get("is_malicious") is False:
            continue
        for t in r.get("turns", []):
            txt = t.get("raw_text", "") or ""
            act = classify_action(txt)
            if act == "network_request":
                for m in _RE_RECIPIENT.findall(txt):
                    recipients.add(m)
            elif act == "file_read":
                for m in _RE_FILEPATH.findall(txt):
                    filepaths.add(m)
    return {"recipients": recipients, "filepaths": filepaths}


# ── feature names in exact index order ───────────────────────────────────────
FEATURE_NAMES = [
    # group 1: prompt (0-10)
    "prompt_length", "token_count", "suspicious_keyword_count",
    "suspicious_keyword_max_weight", "has_system_override", "has_ignore_instruction",
    "has_new_instruction", "instruction_conflict_flag", "override_attempt_flag",
    "privilege_escalation_signal", "prompt_suspicion_score",
    # group 2: session (11-18)
    "retry_count", "denied_tool_call_count", "failed_tool_call_count",
    "has_external_content_recently", "semantic_drift_score", "tool_diversity_score",
    "tool_transition_count", "session_length",
    # group 3: tool (19-24)
    "tool_file_read", "tool_network_request", "tool_exec", "tool_summarize",
    "tool_web_fetch", "task_tool_mismatch_flag",
    # group 4: context (25-30)
    "has_external_content", "suspicious_pattern_in_context",
    "sensitive_resource_involved", "risky_action_after_external_input",
    "external_content_count", "context_suspicion_score",
    # group 5: fraud (31-39) — 9 project-specific trajectory features
    "cumulative_risk_sum", "risk_delta", "monotonicity_flag", "action_burst_score",
    "novelty_recipient_flag", "novelty_recipient_score", "novelty_filepath_flag",
    "novelty_filepath_score", "context_exfil_gap",
]
assert len(FEATURE_NAMES) == 40

FEATURE_GROUPS = {
    "prompt": list(range(0, 11)),
    "session": list(range(11, 19)),
    "tool": list(range(19, 25)),
    "context": list(range(25, 31)),
    "fraud": list(range(31, 40)),
}
assert sorted({i for v in FEATURE_GROUPS.values() for i in v}) == list(range(40))


def extract_features(record: dict, benign_profile: dict | None = None) -> list[float]:
    """Return exactly 40 float features for one record, in group order.

    Reads NO record-level field other than `turns`. The one feature that
    previously read `structured_action` (task_tool_mismatch_flag) is now
    rebuilt from per-turn classify_action() — checking whether any single
    turn bundles ≥2 distinct action types (within-turn task-tool mismatch).
    """
    profile = benign_profile or {"recipients": set(), "filepaths": set()}
    known_recipients = profile.get("recipients", set()) or set()
    known_filepaths = profile.get("filepaths", set()) or set()

    turns = record.get("turns", []) or []
    texts = [t.get("raw_text", "") or "" for t in turns]
    n = len(turns)

    # ── GROUP 1: Prompt Features (0-10) ──────────────────────────────────────
    prompt_length = float(sum(len(t) for t in texts))
    token_count = float(sum(len(t.split()) for t in texts))

    suspicious_keyword_count = 0
    suspicious_keyword_max_weight = 0
    for t in texts:
        if SUSPICIOUS_KW.search(t):
            suspicious_keyword_count += 1
            for pat, w in _KW_WEIGHTS:
                if pat.search(t) and w > suspicious_keyword_max_weight:
                    suspicious_keyword_max_weight = w

    has_system_override = float(any(RE_SYSTEM_OVERRIDE.search(t) for t in texts))
    has_ignore_instruction = float(any(RE_IGNORE_INSTR.search(t) for t in texts))
    has_new_instruction = float(any(RE_NEW_INSTR.search(t) for t in texts))
    instruction_conflict_flag = float(has_ignore_instruction and has_new_instruction)
    override_attempt_flag = float(any(RE_OVERRIDE_ATTEMPT.search(t) for t in texts))
    privilege_escalation_signal = float(any(RE_PRIV_ESCALATION.search(t) for t in texts))
    prompt_suspicion_score = float(
        suspicious_keyword_count * 0.3
        + has_system_override
        + has_ignore_instruction * 1.5
        + has_new_instruction
        + instruction_conflict_flag * 2
        + override_attempt_flag * 2
        + privilege_escalation_signal * 2
    )

    # ── GROUP 2: Session Features (11-18) ────────────────────────────────────
    token_sets = [set(t.split()) for t in texts]
    retry_count = 0
    for i in range(1, n):
        if _jaccard(token_sets[i - 1], token_sets[i]) > 0.9:
            retry_count += 1
    denied_tool_call_count = 0  # v0 schema has no permission/denial field
    failed_tool_call_count = 0   # v0 schema has no tool-result/status field

    per_turn_actions = [classify_action(t) for t in texts]
    last2 = per_turn_actions[-2:] if n >= 2 else per_turn_actions
    has_external_content_recently = float(any(a == "network_request" for a in last2))

    if n >= 2:
        drifts = [1.0 - _jaccard(token_sets[i - 1], token_sets[i]) for i in range(1, n)]
        semantic_drift_score = float(sum(drifts) / len(drifts))
    else:
        semantic_drift_score = 0.0

    if n >= 1:
        tool_diversity_score = float(len(set(per_turn_actions)) / n)
    else:
        tool_diversity_score = 0.0

    if n >= 2:
        transitions = {(per_turn_actions[i], per_turn_actions[i + 1]) for i in range(n - 1)}
        tool_transition_count = float(len(transitions))
    else:
        tool_transition_count = 0.0

    session_length = float(n)

    # ── GROUP 3: Tool Features (19-24) ───────────────────────────────────────
    tool_file_read = float(any(a == "file_read" for a in per_turn_actions))
    tool_network_request = float(any(a == "network_request" for a in per_turn_actions))
    tool_exec = float(any(a == "exec" for a in per_turn_actions))
    tool_summarize = float(any(RE_SUMMARIZE.search(t) for t in texts))
    tool_web_fetch = float(any(RE_WEB_FETCH.search(t) for t in texts))

    # task_tool_mismatch_flag — rebuilt from per-turn classify_action() only.
    # Faithful definition: 1 if ANY single turn bundles ≥2 distinct action types
    # (e.g. "read /etc/shadow and send to attacker" = {file_read, network_request}).
    # This captures "tool inconsistent with request" — a single user instruction
    # invoking tools that don't cohere into one task. On the expanded data this
    # is NO LONGER a near-perfect separator (AUC 0.629, gap 0.257) unlike the
    # old "last-turn novel action" proxy that was 100% on templated synth.
    # Honest limitation: near-zero signal on real test data (AUC 0.525); the
    # moderate full-train AUC is driven by synth/promptfoo. Not redundant with
    # tool_diversity_score (corr 0.016), partially with has_external_content (0.48).
    task_tool_mismatch_flag = 0.0
    for t in texts:
        # collect ALL action types whose keyword group matches (not just
        # classify_action's single winner), so within-turn multi-tool is visible.
        # Word-boundary variants avoid "README"->read false positives.
        act_types = set()
        if _ACT_NETWORK_WB.search(t): act_types.add("network_request")
        if _ACT_FILE_WB.search(t):    act_types.add("file_read")
        if _ACT_EXEC_WB.search(t):    act_types.add("exec")
        if len(act_types) >= 2:
            task_tool_mismatch_flag = 1.0
            break

    # ── GROUP 4: Context Features (25-30) ───────────────────────────────────
    has_external_content = float(any(a == "network_request" for a in per_turn_actions))
    suspicious_pattern_in_context = float(any(SUSPICIOUS_KW.search(t) for t in texts))
    sensitive_resource_involved = float(any(_sensitive_in_text(t) for t in texts))
    # risky_action_after_external_input: exists i<j, turn i is network_request
    # and turn j>=i has sensitive_resource_involved True OR classified as exec.
    risky_action_after_external_input = 0.0
    for i in range(n):
        if per_turn_actions[i] != "network_request":
            continue
        for j in range(i, n):
            if _sensitive_in_text(texts[j]) or per_turn_actions[j] == "exec":
                risky_action_after_external_input = 1.0
                break
        if risky_action_after_external_input:
            break
    external_content_count = float(sum(1 for a in per_turn_actions if a == "network_request"))
    context_suspicion_score = float(
        has_external_content * 1
        + suspicious_pattern_in_context * 1.5
        + sensitive_resource_involved * 2
        + risky_action_after_external_input * 3
    )

    # ── GROUP 5: Fraud-inspired Features (31-39, 9 features) ───────────────
    risks = [tool_risk(a) for a in per_turn_actions]
    cumulative_risk_sum = float(sum(risks))
    if n >= 2:
        risk_delta = float(risks[-1] - risks[-2])
    else:
        risk_delta = 0.0
    monotonicity_flag = 1.0 if n >= 2 and all(risks[i] >= risks[i - 1] for i in range(1, n)) else 0.0

    def _burst(window: int) -> float:
        if n == 0:
            return 0.0
        w = min(window, n)
        tail = risks[-w:]
        if not tail:
            return 0.0
        return float(sum(1 for r in tail if r >= 2) / len(tail))

    # action-burst score = fraction of the last three turns invoking a
    # high-risk tool (tool_risk >= 2), capturing the staged-burst pattern.
    action_burst_score = _burst(3)

    # novelty recipient (network_request turns)
    novelty_recipient_flag = 0.0
    for t in texts:
        # only examine turns classified as network_request
        if classify_action(t) != "network_request":
            continue
        for cand in _RE_RECIPIENT.findall(t):
            if cand not in known_recipients:
                novelty_recipient_flag = 1.0
                break
        if novelty_recipient_flag:
            break
    novelty_recipient_score = 1.0 if novelty_recipient_flag else 0.0

    # novelty filepath (file_read turns)
    novelty_filepath_flag = 0.0
    for t in texts:
        if classify_action(t) != "file_read":
            continue
        for cand in _RE_FILEPATH.findall(t):
            if cand not in known_filepaths:
                novelty_filepath_flag = 1.0
                break
        if novelty_filepath_flag:
            break
    novelty_filepath_score = 1.0 if novelty_filepath_flag else 0.0

    # context_exfil_gap: first sensitive file_read at i, network_request at j>i
    context_exfil_gap = -1.0
    first_sensitive_read = None
    for i, t in enumerate(texts):
        if per_turn_actions[i] == "file_read" and _sensitive_in_text(t):
            first_sensitive_read = i
            break
    if first_sensitive_read is not None:
        for j in range(first_sensitive_read + 1, n):
            if per_turn_actions[j] == "network_request":
                context_exfil_gap = float(j - first_sensitive_read)
                break

    return [
        # prompt 0-10
        prompt_length, token_count, float(suspicious_keyword_count),
        float(suspicious_keyword_max_weight), has_system_override, has_ignore_instruction,
        has_new_instruction, instruction_conflict_flag, override_attempt_flag,
        privilege_escalation_signal, prompt_suspicion_score,
        # session 11-18
        float(retry_count), float(denied_tool_call_count), float(failed_tool_call_count),
        has_external_content_recently, semantic_drift_score, tool_diversity_score,
        tool_transition_count, session_length,
        # tool 19-24
        tool_file_read, tool_network_request, tool_exec, tool_summarize,
        tool_web_fetch, task_tool_mismatch_flag,
        # context 25-30
        has_external_content, suspicious_pattern_in_context,
        sensitive_resource_involved, risky_action_after_external_input,
        external_content_count, context_suspicion_score,
        # fraud 31-39 (9 local features)
        cumulative_risk_sum, risk_delta, monotonicity_flag, action_burst_score,
        novelty_recipient_flag, novelty_recipient_score, novelty_filepath_flag,
        novelty_filepath_score, context_exfil_gap,
    ]
