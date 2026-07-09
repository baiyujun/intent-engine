"""Tier 0 rule engine — standalone adaptation of ClawSentry's D1-D3 scoring.

Faithful re-implementation of ClawSentry gateway/risk_snapshot.py D1-D3
dimensions, _has_dangerous_command_pattern, the short-circuit rules SC-1/2/3,
and the composite-score→risk-level mapping. NO imports from ClawSentry.

Also integrates a standalone PatternMatcher that loads attack_patterns.yaml
and matches detection regexes, mirroring ClawSentry pattern_matcher.py.

Public API (per Tier 0 spec):
  Tool risk sets:
    READONLY_TOOLS (score 0), LIMITED_WRITE_TOOLS (score 1),
    SYSTEM_INTERACTION_TOOLS (score 2), HIGH_DANGER_TOOLS (score 3),
    DANGEROUS_TOOLS (expanded → score 3), SYSTEM_PATHS (bash system paths → 3)

  Scoring functions:
    score_d1(tool_name, command="") -> int (0-3)
    score_d2(tool_name, payload)   -> int (0-3)
    score_d3(tool_name, command)    -> int (0-3)

  Pattern matching:
    AttackPattern dataclass
    load_attack_patterns(path=None) -> list[AttackPattern]
    PatternMatcher.match(tool_name, payload, content) -> list[AttackPattern]

  Verdict:
    RuleVerdict(risk_level, d1, d2, d3, matched_patterns, short_circuit)
    evaluate_rules(tool_name, payload, content, matcher=None) -> RuleVerdict

  Short-circuits: SC-1 (d1==3 and d2>=2 → CRITICAL),
                  SC-2 (d3==3 → CRITICAL),
                  SC-3 (d1==0 and d2==0 and d3==0 → LOW)
  Non-short-circuit: composite score = w_max_d123 * max(d1,d2,d3),
    mapped via thresholds (critical>=2.2, high>=1.5, medium>=0.8 else LOW).
"""

from __future__ import annotations

import copy
import fnmatch
import logging
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import yaml

from tier0.text_preprocess import normalize_text

logger = logging.getLogger(__name__)

_DEFAULT_PATTERNS_PATH = Path(__file__).parent / "attack_patterns.yaml"
_MAX_DETECTION_INPUT_LEN = 102_400  # 100 KB — hard cap to prevent ReDoS


# ---------------------------------------------------------------------------
# Risk level
# ---------------------------------------------------------------------------

class RiskLevel(str, Enum):
    """Risk level.

    Values are lowercase strings (``"low"``, ``"medium"``, ``"high"``,
    ``"critical"``) so that ``RuleVerdict.risk_level`` — typed as ``str`` —
    compares equal to the literal lowercase levels in the Tier 0 contract
    while remaining usable as an enum (``RiskLevel.CRITICAL``).
    """
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __ge__(self, other: "RiskLevel") -> bool:
        order = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2, RiskLevel.CRITICAL: 3}
        return order[self] >= order[other]

    def __gt__(self, other: "RiskLevel") -> bool:
        order = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2, RiskLevel.CRITICAL: 3}
        return order[self] > order[other]

    def __le__(self, other: "RiskLevel") -> bool:
        order = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2, RiskLevel.CRITICAL: 3}
        return order[self] <= order[other]

    def __lt__(self, other: "RiskLevel") -> bool:
        order = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2, RiskLevel.CRITICAL: 3}
        return order[self] < order[other]


# ---------------------------------------------------------------------------
# Composite score thresholds (mirrors ClawSentry DetectionConfig defaults,
# restricted to D1-D3 since Tier 0 has no D4/D5/D6)
# ---------------------------------------------------------------------------

_COMPOSITE_WEIGHT_MAX_D123 = 0.4
_THRESHOLD_CRITICAL = 2.2
_THRESHOLD_HIGH = 1.5
_THRESHOLD_MEDIUM = 0.8


# ---------------------------------------------------------------------------
# D1: Tool type danger (0-3) — tool risk sets
# ---------------------------------------------------------------------------

# Public tool risk sets (per Tier 0 spec). Aliased from internal names below
# for backward compatibility with earlier rule_engine consumers.

READONLY_TOOLS = frozenset({
    "read_file", "list_dir", "search", "grep", "glob",
    "list_files", "read", "find", "cat", "head", "tail",
})

LIMITED_WRITE_TOOLS = frozenset({
    "write_file", "edit_file", "create_file", "edit", "write",
})

SYSTEM_INTERACTION_TOOLS = frozenset({
    "http_request", "install_package", "fetch", "web_fetch",
})

HIGH_DANGER_TOOLS = frozenset({
    "exec", "sudo", "chmod", "chown", "mount", "kill", "pkill",
})

# Canonical set of dangerous tools — expanded set (R-10) → score 3
DANGEROUS_TOOLS = frozenset({
    # Shells
    "bash", "sh", "zsh", "ksh", "dash", "shell", "powershell", "cmd",
    # Execution
    "exec", "eval", "system", "popen", "spawn",
    # Privilege escalation
    "sudo", "su", "pkexec", "doas", "runas",
    # File permission / ownership
    "chmod", "chown", "chgrp", "mount", "umount",
    # Process control
    "kill", "pkill", "killall", "taskkill",
    # macOS system tools
    "launchctl", "pmset", "diskutil", "dscl", "security", "codesign",
    # Windows system tools
    "wmic", "reg", "regedit", "schtasks", "at", "netsh", "sc", "icacls",
    "takeown", "cipher", "diskpart", "msiexec", "rundll32",
    # Network / remote access
    "nc", "ncat", "netcat", "socat", "telnet", "ssh", "ftp",
    # Persistence
    "cron", "crontab", "systemctl",
})

# Backward-compat internal aliases (older consumers used _D1_-prefixed names)
_D1_READONLY_TOOLS = READONLY_TOOLS
_D1_LIMITED_WRITE_TOOLS = LIMITED_WRITE_TOOLS
_D1_SYSTEM_INTERACTION_TOOLS = SYSTEM_INTERACTION_TOOLS
_D1_HIGH_DANGER_TOOLS = HIGH_DANGER_TOOLS

# System paths that elevate bash from D1=2 to D1=3 (public, compiled)
SYSTEM_PATHS = re.compile(
    r"(/etc/|/usr/|/var/|/sys/|/proc/|/boot/|/dev/(?!null\b))"
)
_SYSTEM_PATHS = SYSTEM_PATHS  # backward-compat alias


# ---------------------------------------------------------------------------
# D2: Target path sensitivity (0-3)
# ---------------------------------------------------------------------------

_D2_SYSTEM_CRITICAL = re.compile(
    r"^(/etc/|/usr/|/var/|/sys/|/proc/|/boot/)"
)

_D2_CONFIG_PATTERNS = re.compile(
    r"(\.config\.|\.env|\.rc$|Makefile$|Dockerfile$|docker-compose)",
    re.IGNORECASE,
)

_CREDENTIAL_PATH_RE = re.compile(
    r"\.(env|pem|key|p12|pfx|jks|keystore)(?:$|[^a-z0-9])|"
    r"id_rsa|id_ed25519|credentials|\.secret|\.token|\.password|"
    r"\.aws/|\.ssh/",
    re.IGNORECASE,
)


def is_credential_path(value: str) -> bool:
    """Return True if the path looks like a credential/secret file.

    Mirrors ClawSentry risk_signals.is_credential_path.
    """
    return bool(_CREDENTIAL_PATH_RE.search(str(value or "")))


# Backward-compat private alias
_is_credential_path = is_credential_path


def _extract_paths_from_command(command: str) -> list[str]:
    """Best-effort path extraction from shell commands."""
    paths: list[str] = []
    for token in command.split():
        if token.startswith("/") or token.startswith("~"):
            paths.append(token)
        elif "/" in token and not token.startswith("-"):
            paths.append(token)
    return paths


def _extract_paths_from_payload(payload: dict) -> list[str]:
    """Extract file paths from a payload dict (path keys + command string).

    Mirrors ClawSentry risk_snapshot._extract_paths: pulls values from the
    keys (path, file_path, file, target, destination, source) and any paths
    embedded in the command string.
    """
    paths: list[str] = []
    if not isinstance(payload, dict):
        return paths
    for key in ("path", "file_path", "file", "target", "destination", "source"):
        val = payload.get(key)
        if isinstance(val, str) and val:
            paths.append(val)
    command = str(payload.get("command", "") or "")
    if command:
        paths.extend(_extract_paths_from_command(command))
    return paths


def _extract_paths(file_path: str, command: str) -> list[str]:
    """Extract file paths from the event's file_path + command (legacy helper)."""
    paths: list[str] = []
    if isinstance(file_path, str) and file_path:
        paths.append(file_path)
    if command:
        paths.extend(_extract_paths_from_command(command))
    return paths


# ---------------------------------------------------------------------------
# D3: Command pattern danger (0-3, only bash/exec tools)
# ---------------------------------------------------------------------------

_D3_SAFE_COMMANDS = frozenset({
    "ls", "cat", "echo", "pwd", "whoami", "date", "env", "printenv",
    "hostname", "uname", "id", "wc", "sort", "uniq", "diff",
    "head", "tail", "less", "more", "file", "which", "type",
})

_D3_REGULAR_WRITE = frozenset({
    "cp", "mv", "mkdir", "touch", "git add", "git commit",
    "ln", "rename",
})

_D3_POTENTIAL_DESTRUCTIVE = frozenset({
    "rm", "git push", "git reset", "npm install", "pip install",
    "yarn add", "apt install", "yum install",
})

# Regex patterns that score d3=2 (concerning but not immediately catastrophic)
_D3_POTENTIAL_DESTRUCTIVE_PATTERNS = [
    re.compile(r"launchctl\s+(?:unload|disable)\s+.*(?:/Library|/System)", re.I),
    re.compile(r"icacls\s+.*(?:/grant|/deny)", re.I),
]

_D3_HIGH_DANGER_PATTERNS = [
    re.compile(r"rm\s+.*-[^\s]*r[^\s]*f|rm\s+.*-[^\s]*f[^\s]*r|rm\s+-rf"),
    re.compile(r"\bdd\b.*\bof\s*=\s*/dev/"),
    re.compile(r"\bmkfs\b"),
    re.compile(r":\(\)\s*\{"),  # Fork bomb
    re.compile(r"curl\s.*\|\s*(sh|bash)"),
    re.compile(r"wget\s.*\|\s*(sh|bash)"),
    re.compile(r">[^\S\r\n]*/dev/(?!null\b)"),
    re.compile(r"git\s+push\s+.*--force"),
    re.compile(r"chmod\s+777"),
    re.compile(r"\bsudo\b"),
    # Windows destructive operations
    re.compile(r"rmdir\s+/s\s+/q", re.I),
    re.compile(r"Remove-Item\s+.*-Recurse\s+.*-Force", re.I),
    re.compile(r"del\s+/[sq]\s+/[sq]", re.I),
    # Privilege escalation
    re.compile(r"Set-ExecutionPolicy\s+(?:Unrestricted|Bypass)", re.I),
    re.compile(r"net\s+(?:user|localgroup)\s+.*\s+/add", re.I),
    # macOS disk destruction
    re.compile(r"diskutil\s+(?:secureErase|eraseVolume|eraseDisk)", re.I),
    # Firewall tampering (flush/delete/reset only, not normal rule additions)
    re.compile(r"iptables\s+(?:-F|-X)\b", re.I),
    re.compile(r"ufw\s+(?:disable|reset)", re.I),
    re.compile(r"netsh\s+(?:advfirewall|firewall)\s+set\s+.*state\s+off", re.I),
    # Log clearing
    re.compile(r"wevtutil\s+cl\s+(?:System|Security|Application)", re.I),
    # Reverse shell indicators
    re.compile(r"(?:nc|ncat|netcat)\s+.*-e\s+(?:/bin/|cmd)", re.I),
    re.compile(r"\|\s*IEX\s*\(", re.I),
    # Disk destruction / secure erase
    re.compile(r"shred\s+-[a-z]*u", re.I),
    re.compile(r"cipher\s+/w:", re.I),
]

# Remote pipe / process-sub exec patterns (from risk_signals.py)
_REMOTE_PIPE_EXEC_RE = re.compile(
    r"(?:curl|wget)\b.*\|\s*(?:sh|bash|zsh|dash|ksh)\b",
    re.IGNORECASE,
)
_PROCESS_SUB_REMOTE_RE = re.compile(
    r"(?:bash|sh|zsh)\s+<\(\s*(?:curl|wget)\b",
    re.IGNORECASE,
)


def has_remote_pipe_exec_command(command: str) -> bool:
    """Mirror of ClawSentry risk_signals.has_remote_pipe_exec_command."""
    return bool(_REMOTE_PIPE_EXEC_RE.search(str(command or "")))


def has_process_sub_remote_command(command: str) -> bool:
    """Mirror of ClawSentry risk_signals.has_process_sub_remote_command."""
    return bool(_PROCESS_SUB_REMOTE_RE.search(str(command or "")))


def _has_dangerous_command_pattern(command: str) -> bool:
    """Check if a command matches any high-danger pattern.

    Mirrors ClawSentry risk_snapshot._has_dangerous_command_pattern: remote
    pipe exec + process-sub remote + the _D3_HIGH_DANGER_PATTERNS regex list.
    """
    if has_remote_pipe_exec_command(command):
        return True
    if has_process_sub_remote_command(command):
        return True
    for pat in _D3_HIGH_DANGER_PATTERNS:
        if pat.search(command):
            return True
    return False


# ---------------------------------------------------------------------------
# Public D1-D3 scoring functions
# ---------------------------------------------------------------------------

def score_d1(tool_name: str, command: str = "") -> int:
    """Score tool type dangerousness (0-3).

    Faithful copy of ClawSentry risk_snapshot._score_d1:
      readonly → 0, limited_write → 1, high_danger → 3,
      bash/shell/terminal/command → check command for dangerous patterns or
      system paths → 3 else 2, system_interaction → 2, dangerous → 3,
      unknown → 2.
    """
    tool = (tool_name or "").lower()

    if not tool:
        return 2  # Conservative fallback per 12.5

    if tool in READONLY_TOOLS:
        return 0

    if tool in LIMITED_WRITE_TOOLS:
        return 1

    if tool in HIGH_DANGER_TOOLS:
        return 3

    if tool in ("bash", "shell", "terminal", "command"):
        cmd = str(command or "")
        if _has_dangerous_command_pattern(cmd):
            return 3
        if SYSTEM_PATHS.search(cmd):
            return 3
        return 2

    if tool in SYSTEM_INTERACTION_TOOLS:
        return 2

    # R-10: Check expanded dangerous tools set (after bash/shell special case
    # to preserve command-level analysis for those tools)
    if tool in DANGEROUS_TOOLS:
        return 3

    # Unknown tool: conservative fallback
    return 2


def score_d2(tool_name: str, payload: dict) -> int:
    """Score target path sensitivity (0-3).

    Extracts paths from the payload keys (path/file_path/file/target/
    destination/source) plus any paths embedded in the command string, then
    applies ClawSentry risk_snapshot._score_d2 logic:
      _D2_SYSTEM_CRITICAL → 3, _D2_CONFIG_PATTERNS → 1,
      credential path or .gnupg → 2, no path → 1.
    ``tool_name`` is accepted for API symmetry but does not affect D2 scoring
    (matching ClawSentry, where D2 is path-driven, not tool-driven).
    """
    paths = _extract_paths_from_payload(payload if isinstance(payload, dict) else {})
    if not paths:
        return 1  # Conservative fallback per 12.5

    max_score = 0
    for p in paths:
        if _D2_SYSTEM_CRITICAL.search(p):
            max_score = max(max_score, 3)
        elif _D2_CONFIG_PATTERNS.search(p):
            max_score = max(max_score, 1)
        elif is_credential_path(p) or ".gnupg/" in p.lower():
            max_score = max(max_score, 2)
    return max_score


def score_d3(tool_name: str, command: str) -> int:
    """Score command pattern danger (0-3). Only applies to bash/exec tools.

    Faithful copy of ClawSentry risk_snapshot._score_d3:
      tool not in (bash, shell, terminal, command, exec) → 0;
      empty command → 2; high-danger pattern → 3; safe command → 0;
      potential-destructive (set or regex) → 2; regular write → 1;
      unknown → 2.
    """
    tool = (tool_name or "").lower()
    if tool not in ("bash", "shell", "terminal", "command", "exec"):
        return 0  # Non-bash tools: fixed 0

    command = str(command or "")
    if not command.strip():
        return 2  # Conservative fallback per 12.5

    # Check high danger first
    if _has_dangerous_command_pattern(command):
        return 3

    # Extract first meaningful command word
    first_cmd = command.strip().split()[0] if command.strip() else ""
    # Strip path prefix
    first_cmd = first_cmd.rsplit("/", 1)[-1]

    if first_cmd in _D3_SAFE_COMMANDS:
        return 0

    # Check potential destructive (word-boundary match for single-word patterns)
    for pattern in _D3_POTENTIAL_DESTRUCTIVE:
        if " " in pattern:
            # Multi-word pattern: substring match is appropriate
            if pattern in command:
                return 2
        else:
            # Single-word pattern: use word boundary to avoid false positives
            if re.search(r"\b" + re.escape(pattern) + r"\b", command):
                return 2

    # Check potential destructive regex patterns (d3=2)
    for pat in _D3_POTENTIAL_DESTRUCTIVE_PATTERNS:
        if pat.search(command):
            return 2

    # Check regular write (word-boundary match for single-word patterns)
    for pattern in _D3_REGULAR_WRITE:
        if " " in pattern:
            if pattern in command:
                return 1
        else:
            if re.search(r"\b" + re.escape(pattern) + r"\b", command):
                return 1

    # Unknown command: conservative fallback
    return 2


# ---------------------------------------------------------------------------
# Short-circuit rules + composite scoring
# ---------------------------------------------------------------------------

# Short-circuit rules (evaluated before composite scoring)
_SHORT_CIRCUIT_RULES = [
    # SC-1: High-danger tool + sensitive path → critical
    ("SC-1", lambda d: d.d1 == 3 and d.d2 >= 2, RiskLevel.CRITICAL),
    # SC-2: High-danger command pattern → critical
    ("SC-2", lambda d: d.d3 == 3, RiskLevel.CRITICAL),
    # SC-3: Pure read-only on normal path → low
    ("SC-3", lambda d: d.d1 == 0 and d.d2 == 0 and d.d3 == 0, RiskLevel.LOW),
]


def _composite_score(d1: int, d2: int, d3: int) -> float:
    """E-4 composite score restricted to D1-D3 (D4/D5/D6 = 0 at Tier 0)."""
    return _COMPOSITE_WEIGHT_MAX_D123 * max(d1, d2, d3)


def _score_to_risk_level(score: float) -> RiskLevel:
    """Map composite score to risk level (mirrors _score_to_risk_level_v2)."""
    if score >= _THRESHOLD_CRITICAL:
        return RiskLevel.CRITICAL
    if score >= _THRESHOLD_HIGH:
        return RiskLevel.HIGH
    if score >= _THRESHOLD_MEDIUM:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


# ---------------------------------------------------------------------------
# Pattern matching (standalone adaptation of ClawSentry pattern_matcher.py)
# ---------------------------------------------------------------------------

def _has_nested_repetition(pattern: str) -> bool:
    """Conservative check for nested quantifiers indicating ReDoS risk."""
    depth = 0
    has_inner_complexity: list[bool] = [False]
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern):
            i += 2
            continue
        if ch == "[":
            i += 1
            if i < len(pattern) and pattern[i] == "^":
                i += 1
            if i < len(pattern) and pattern[i] == "]":
                i += 1
            while i < len(pattern) and pattern[i] != "]":
                if pattern[i] == "\\" and i + 1 < len(pattern):
                    i += 1
                i += 1
            i += 1
            continue
        if ch == "(":
            depth += 1
            has_inner_complexity.append(False)
        elif ch == ")":
            inner = has_inner_complexity.pop() if len(has_inner_complexity) > 1 else False
            depth = max(depth - 1, 0)
            rest = pattern[i + 1:]
            if re.match(r"[*+?]|\{\d+,?\d*\}", rest) and inner:
                return True
        elif ch == "|":
            if depth > 0 and has_inner_complexity:
                has_inner_complexity[-1] = True
        elif ch in "*+":
            if has_inner_complexity:
                has_inner_complexity[-1] = True
        elif ch == "{" and re.match(r"\{\d+,?\d*\}", pattern[i:]):
            if has_inner_complexity:
                has_inner_complexity[-1] = True
        i += 1
    return False


def _compile_safe_regex(pattern: str, flags: int = re.IGNORECASE | re.DOTALL) -> Optional[re.Pattern]:
    """Compile a regex only if it passes safety checks. Returns None if unsafe."""
    if not pattern:
        return None
    if _has_nested_repetition(pattern):
        logger.warning("Skipped potential ReDoS pattern: %r", pattern)
        return None
    try:
        return re.compile(pattern, flags)
    except re.error as e:
        logger.warning("Skipped invalid regex pattern %r: %s", pattern, e)
        return None


@dataclass
class AttackPattern:
    """Parsed attack pattern from YAML (mirrors ClawSentry pattern_matcher.AttackPattern)."""
    id: str
    category: str
    description: str
    risk_level: RiskLevel
    triggers: dict[str, Any]
    detection: dict[str, Any]
    false_positive_filters: list[dict[str, Any]] = field(default_factory=list)
    risk_escalation: Optional[dict[str, str]] = None
    references: Optional[dict[str, list[str]]] = None
    mitre_attack: Optional[dict[str, list[str]]] = None
    # Populated at match time with the highest weight of any fired detection regex
    max_weight: int = 0


def _precompile_trigger_patterns(triggers: dict[str, Any]) -> None:
    """Pre-compile regex patterns in trigger conditions."""
    for key in ("command_patterns", "path_patterns"):
        raw_patterns = triggers.get(key)
        if raw_patterns:
            compiled_key = f"_compiled_{key}"
            compiled_list = []
            for p in raw_patterns:
                compiled = _compile_safe_regex(p, re.IGNORECASE | re.DOTALL)
                if compiled is not None:
                    compiled_list.append(compiled)
            triggers[compiled_key] = compiled_list
    for cond in triggers.get("conditions", []):
        if "OR" in cond:
            for sub in cond["OR"]:
                _precompile_trigger_patterns(sub)
        else:
            _precompile_trigger_patterns(cond)


def _parse_pattern(raw: dict) -> AttackPattern:
    """Parse a single pattern dict from YAML, pre-compiling regexes."""
    detection: dict[str, Any] = raw.get("detection", {})

    compiled: list[dict[str, Any]] = []
    for rp in detection.get("regex_patterns", []):
        if isinstance(rp, str):
            cre = _compile_safe_regex(rp)
            if cre is not None:
                compiled.append({"compiled": cre, "weight": 5})
        elif isinstance(rp, dict):
            pat_str = rp.get("pattern", "")
            if pat_str:
                cre = _compile_safe_regex(pat_str)
                if cre is not None:
                    compiled.append({
                        "compiled": cre,
                        "weight": rp.get("weight", 5),
                    })
    detection["_compiled"] = compiled

    triggers: dict[str, Any] = raw.get("triggers", {})
    _precompile_trigger_patterns(triggers)

    return AttackPattern(
        id=raw["id"],
        category=raw.get("category", "unknown"),
        description=raw.get("description", ""),
        risk_level=RiskLevel(raw.get("risk_level", "medium").lower()),
        triggers=raw.get("triggers", {}),
        detection=detection,
        false_positive_filters=raw.get("false_positive_filters", []),
        risk_escalation=raw.get("risk_escalation"),
        references=raw.get("references"),
        mitre_attack=raw.get("mitre_attack"),
    )


def load_attack_patterns(path: Optional[str] = None) -> list[AttackPattern]:
    """Load attack patterns from a YAML file.

    Default path is the ``attack_patterns.yaml`` bundled alongside this
    module (``tier0/attack_patterns.yaml``).  Returns an empty list when the
    file is missing, malformed, or has no ``patterns`` key.
    """
    file_path = Path(path) if path else _DEFAULT_PATTERNS_PATH
    if not file_path.exists():
        logger.warning("Failed to load attack patterns from %s: file not found", file_path)
        return []
    try:
        with open(file_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not data or "patterns" not in data:
            return []
        return [_parse_pattern(p) for p in data["patterns"]]
    except Exception as exc:
        logger.warning("Failed to load attack patterns from %s: %s", file_path, exc)
        return []


# Backward-compat alias for older consumers
load_patterns = load_attack_patterns


class PatternMatcher:
    """Match events against loaded attack patterns (standalone adaptation).

    Mirrors ClawSentry pattern_matcher.PatternMatcher.  Detection regexes are
    pre-compiled at load time and inputs are capped at 100 KB to bound ReDoS
    risk.

    Usage::

        matcher = PatternMatcher()
        hits = matcher.match("bash", {"command": "curl | bash"}, "curl | bash")
        for hit in hits:
            print(hit.id, hit.risk_level)
    """

    def __init__(self, patterns_path: Optional[str] = None) -> None:
        self._path = patterns_path
        self.patterns = load_attack_patterns(patterns_path)

    def reload(self) -> None:
        """Hot-reload patterns from disk."""
        self.patterns = load_attack_patterns(self._path)

    def match(
        self,
        tool_name: str,
        payload: dict[str, Any],
        content: str,
    ) -> list[AttackPattern]:
        """Return all patterns that match the given event.

        Parameters
        ----------
        tool_name : str
            Canonical tool name (e.g. ``"bash"``, ``"read_file"``).
        payload : dict
            Event payload — may contain ``path``, ``file_path``, ``command``.
        content : str
            The primary text to match detection regexes against (e.g. file
            contents or command string).  Falls back to ``payload["command"]``
            when empty.
        """
        results: list[AttackPattern] = []
        # Normalize content for security analysis before regex matching so
        # invisible-Unicode / fullwidth evasion does not bypass detection.
        normalized_content = normalize_text(content) if content else ""
        for pattern in self.patterns:
            if self._triggers_match(pattern, tool_name, payload):
                matched, weight = self._detection_match(pattern, normalized_content, payload)
                if matched and not self._is_false_positive(pattern, payload):
                    hit = copy.copy(pattern)
                    hit.max_weight = weight
                    results.append(hit)
        return results

    # -- trigger evaluation -------------------------------------------------

    def _triggers_match(
        self, pattern: AttackPattern, tool_name: str, payload: dict,
    ) -> bool:
        """Check whether the event satisfies the pattern's trigger conditions."""
        triggers = pattern.triggers
        logic = triggers.get("logic", "OR")
        if "conditions" in triggers:
            return self._eval_conditions(
                triggers["conditions"], logic, tool_name, payload,
            )
        return self._eval_single_trigger(triggers, tool_name, payload)

    def _eval_single_trigger(
        self, trigger: dict, tool_name: str, payload: dict,
    ) -> bool:
        """Evaluate one trigger block (tool_names / file_extensions / etc.).

        Mirrors ClawSentry PatternMatcher._eval_single_trigger: an empty
        trigger dict matches nothing (avoids catch-all false positives).
        """
        if not trigger:
            return False

        if "tool_names" in trigger:
            if tool_name.lower() not in [t.lower() for t in trigger["tool_names"]]:
                return False

        path = str(payload.get("path", payload.get("file_path", "")))

        if "file_extensions" in trigger:
            if not any(path.endswith(ext) for ext in trigger["file_extensions"]):
                return False

        if "file_patterns" in trigger:
            basename = os.path.basename(path)
            if not any(fnmatch.fnmatch(basename, pat) for pat in trigger["file_patterns"]):
                return False

        if "_compiled_command_patterns" in trigger:
            command = str(payload.get("command", ""))
            if not any(cp.search(command) for cp in trigger["_compiled_command_patterns"]):
                return False

        if "_compiled_path_patterns" in trigger:
            if not any(cp.search(path) for cp in trigger["_compiled_path_patterns"]):
                return False

        return True

    def _eval_conditions(
        self,
        conditions: list,
        logic: str,
        tool_name: str,
        payload: dict,
    ) -> bool:
        """Evaluate a list of conditions with AND/OR logic."""
        results: list[bool] = []
        for cond in conditions:
            if "OR" in cond:
                or_results = [
                    self._eval_single_trigger(sub, tool_name, payload)
                    for sub in cond["OR"]
                ]
                results.append(any(or_results))
            else:
                results.append(
                    self._eval_single_trigger(cond, tool_name, payload),
                )
        if logic == "AND":
            return all(results)
        return any(results)

    # -- detection (regex) --------------------------------------------------

    def _detection_match(
        self, pattern: AttackPattern, content: str, payload: dict,
    ) -> tuple[bool, int]:
        """Check whether the detection regex patterns fire on the text.

        Returns ``(matched, max_weight)`` where *max_weight* is the highest
        weight of any regex that fired (0 when unweighted or no match).
        """
        detection = pattern.detection
        if not detection:
            return True, 0

        text = content or str(payload.get("command", ""))
        if not text:
            return False, 0

        # H9: Input length gating — truncate oversized inputs to cap ReDoS risk
        if len(text) > _MAX_DETECTION_INPUT_LEN:
            text = text[:_MAX_DETECTION_INPUT_LEN]

        max_weight = 0
        matched = False

        for cp in detection.get("_compiled", []):
            if cp["compiled"].search(text):
                matched = True
                max_weight = max(max_weight, cp["weight"])

        if matched:
            return True, max_weight

        return False, 0

    # -- false-positive filtering -------------------------------------------

    def _is_false_positive(
        self, pattern: AttackPattern, payload: dict,
    ) -> bool:
        """Return True if the match should be suppressed by a false-positive filter."""
        path = str(payload.get("path", payload.get("file_path", "")))
        for fp_filter in pattern.false_positive_filters:
            filter_type = fp_filter.get("type", "")
            if filter_type == "whitelist_path":
                for wp in fp_filter.get("paths", []):
                    if fnmatch.fnmatch(path, wp):
                        return True
        return False


# ---------------------------------------------------------------------------
# Rule verdict + evaluation
# ---------------------------------------------------------------------------

@dataclass
class RuleVerdict:
    """Verdict from the rule engine.

    ``risk_level`` is a ``RiskLevel`` (a ``str`` subclass enum whose values are
    lowercase) so it compares equal to both ``RiskLevel.CRITICAL`` and the
    literal lowercase ``"critical"``.
    """
    risk_level: RiskLevel
    d1: int
    d2: int
    d3: int
    matched_patterns: list[AttackPattern] = field(default_factory=list)
    short_circuit: Optional[str] = None
    confidence: float = 1.0


@dataclass
class _Dims:
    """Lightweight container for short-circuit predicates."""
    d1: int
    d2: int
    d3: int


def evaluate_rules(
    tool_name: str,
    payload: dict,
    content: str,
    matcher: Optional[PatternMatcher] = None,
) -> RuleVerdict:
    """Evaluate D1-D3 + short-circuits + pattern match → RuleVerdict.

    Per the Tier 0 spec:
      1. Run ``PatternMatcher.match`` (uses ``matcher`` if provided, else a
         default ``PatternMatcher()`` loaded from the bundled YAML).
      2. Compute D1/D2/D3 from ``tool_name`` / ``payload`` / ``content``.
      3. Apply short-circuit rules in order:
         - SC-1: d1==3 and d2>=2 → critical
         - SC-2: d3==3 → critical
         - SC-3: d1==0 and d2==0 and d3==0 → low
      4. Otherwise: risk_level from the composite-score thresholds.
    """
    tool = (tool_name or "").lower()
    payload = payload if isinstance(payload, dict) else {}
    cmd = str(payload.get("command", "") or "")
    content_text = content or ""

    # 1. Pattern match
    if matcher is None:
        matcher = PatternMatcher()
    matched = matcher.match(tool, payload, content_text or cmd)

    # 2. D1-D3 scoring
    d1 = score_d1(tool, cmd)
    d2 = score_d2(tool, payload)
    d3 = score_d3(tool, cmd)

    # 3. Short-circuit rules (evaluated before composite scoring)
    short_circuit: Optional[str] = None
    risk_level: RiskLevel
    dims = _Dims(d1=d1, d2=d2, d3=d3)
    for name, predicate, level in _SHORT_CIRCUIT_RULES:
        if predicate(dims):
            short_circuit = name
            risk_level = level
            break
    else:
        # 4. No short-circuit: composite score → risk level
        score = _composite_score(d1, d2, d3)
        risk_level = _score_to_risk_level(score)

    return RuleVerdict(
        risk_level=risk_level,
        d1=d1,
        d2=d2,
        d3=d3,
        matched_patterns=matched,
        short_circuit=short_circuit,
        confidence=1.0,
    )


# ---------------------------------------------------------------------------
# Backward-compat: RuleEngine facade (older consumers / tests)
# ---------------------------------------------------------------------------

class RuleEngine:
    """Tier 0 rule engine facade — D1-D3 scoring + short-circuit + pattern match.

    Thin wrapper over :func:`evaluate_rules` kept for backward compatibility
    with earlier consumers that used ``RuleEngine().evaluate(tool, cmd, path, content)``.
    """

    def __init__(self, attack_patterns_path: Optional[str] = None) -> None:
        self._matcher = PatternMatcher(attack_patterns_path)

    def evaluate(
        self,
        tool_name: str,
        command: str,
        file_path: str,
        content: str,
    ) -> RuleVerdict:
        """Compute D1-D3, apply short-circuits, run pattern matcher, return verdict."""
        tool = (tool_name or "").lower()
        cmd = str(command or "")
        fpath = str(file_path or "")

        payload = {"command": cmd, "path": fpath, "file_path": fpath}
        return evaluate_rules(tool, payload, content or cmd, matcher=self._matcher)
