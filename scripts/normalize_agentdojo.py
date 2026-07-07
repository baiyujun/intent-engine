"""Normalize AgentDojo default_suites -> unified records (AST only, no exec).

Real AgentDojo suites live under `default_suites/v1*/<suite>/` and define:

  - ``user_tasks.py``:  ``class UserTaskNN(BaseUserTask)`` with a class-level
    ``PROMPT = "..."`` (or an f-string) attribute = the benign user instruction.
  - ``injection_tasks.py``: ``class InjectionTaskNN(BaseInjectionTask)`` with a
    class-level ``GOAL = "..."`` (or an f-string) attribute = the injected
    payload (the attacker's goal instruction).

Both ``PROMPT`` and ``GOAL`` are frequently f-strings that reference other
class-level attributes (e.g. ``URL = "..."``, ``_RECIPIENT = "..."``); a few use
``f"..." + f"..."`` concatenation (``ast.BinOp``). We resolve them with a tiny
AST evaluator over the class namespace — no ``exec``/``eval`` of suite code.

The fixture fallback (``tests/fixtures/agentdojo``) mirrors this layout so the
offline test exercises the real class-based shape.
"""
import ast
import hashlib
import pathlib

from src.schema import make_record, validate_record
from src.normalize_utils import write_slice, make_turn
from src.licenses import license_status, license_spdx

# Real default_suites dir (no double `agentdojo/agentdojo` — confirmed via ls).
RAW_DIR = pathlib.Path("raw/agentdojo/src/agentdojo/default_suites")
SRC_KEY = "agentdojo"

# Class-level attribute names that carry the text payload.
_USER_ATTR = "PROMPT"
_INJ_ATTR = "GOAL"


def _resolve_str(node, ns):
    """Resolve an AST node to a string against the class namespace `ns`.

    Handles plain string constants, f-strings (JoinedStr), and `+`-concatenated
    strings (BinOp/Add). Returns None if the node cannot be resolved to a
    string without executing arbitrary code.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        out = []
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                out.append(part.value)
            elif isinstance(part, ast.FormattedValue):
                inner = _resolve_value(part.value, ns)
                if inner is None:
                    return None
                # Apply !s conversion if specified (conversion == 115 -> str).
                out.append(str(inner))
            else:
                return None
        return "".join(out)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _resolve_str(node.left, ns)
        right = _resolve_str(node.right, ns)
        if left is not None and right is not None:
            return left + right
        return None
    return None


def _resolve_value(node, ns):
    """Resolve a FormattedValue's inner expression to a python value."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name) and node.id in ns:
        return ns[node.id]
    if isinstance(node, ast.JoinedStr):
        return _resolve_str(node, ns)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _resolve_value(node.left, ns)
        right = _resolve_value(node.right, ns)
        if left is not None and right is not None and isinstance(left, str) and isinstance(right, str):
            return left + right
    # Anything else (Attribute, Call, Subscript, ...) would need execution — skip.
    return None


def _class_namespace(cls_node):
    """Build a {name: str} namespace from simple ``Name = <str-literal|fstr>``
    assignments in the class body. f-strings are resolved against earlier
    entries so chained f-strings resolve. Non-str / unresolvable assignments
    are skipped."""
    ns = {}

    def assign(name, value):
        resolved = _resolve_str(value, ns)
        if resolved is not None:
            ns[name] = resolved

    for stmt in cls_node.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            assign(stmt.targets[0].id, stmt.value)
        # Allow annotated assignments without value (no-op) and tuple targets
        # (skip — none of the payload attrs use those).
    return ns


def _extract_payload(cls_node, attr):
    """Return the resolved string for the class-level `attr` (PROMPT/GOAL), or
    None if absent / unresolvable."""
    ns = _class_namespace(cls_node)
    for stmt in cls_node.body:
        if (isinstance(stmt, ast.Assign)
                and len(stmt.targets) == 1
                and isinstance(stmt.targets[0], ast.Name)
                and stmt.targets[0].id == attr):
            return _resolve_str(stmt.value, ns)
    return None


def _suite_name(file_path, base_dir):
    """Suite name = the directory immediately under v1*/ that contains the
    suite files (e.g. ``workspace``). Falls back to the parent dir name."""
    try:
        rel = file_path.relative_to(base_dir)
        # rel.parts: (vX_Y, <suite>, user_tasks.py|injection_tasks.py)
        if len(rel.parts) >= 3:
            return rel.parts[1]
    except ValueError:
        pass
    return file_path.parent.name


def _stable_id(suite, cls_name, payload):
    key = f"{suite}#{cls_name}#{payload}"
    return hashlib.sha1(key.encode()).hexdigest()[:16]


def main():
    recs = []
    base_dir = RAW_DIR
    if not base_dir.exists():
        base_dir = pathlib.Path("tests/fixtures/agentdojo")

    # user_tasks.py -> BENIGN records (PROMPT); injection_tasks.py -> INJECTION records (GOAL)
    for f in sorted(list(base_dir.rglob("user_tasks.py")) + list(base_dir.rglob("injection_tasks.py"))):
        try:
            tree = ast.parse(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        is_inj_file = f.name == "injection_tasks.py"
        suite = _suite_name(f, base_dir)
        attr = _INJ_ATTR if is_inj_file else _USER_ATTR

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            payload = _extract_payload(node, attr)
            if not payload:
                continue
            rid = _stable_id(suite, node.name, payload)
            if is_inj_file:
                recs.append(make_record(
                    _raw_id=rid,
                    source_dataset=SRC_KEY,
                    license=license_spdx(SRC_KEY),
                    license_status=license_status(SRC_KEY),
                    modality="multi_turn",
                    turns=[make_turn("tool_output", payload, "tool_output", 0)],
                    structured_action={"action_type": "unknown",
                                       "target_resource": suite,
                                       "stated_purpose": None},
                    label={"risk_category": "prompt_injection",
                           "is_malicious": True,
                           "attack_family": f"indirect_injection_{suite}",
                           "purpose_capability_consistent": False,
                           "confidence": "high",
                           "attack_stage_precursor": False},
                    notes=f"agentdojo injection [{suite}] {node.name}",
                ))
            else:
                recs.append(make_record(
                    _raw_id=rid,
                    source_dataset=SRC_KEY,
                    license=license_spdx(SRC_KEY),
                    license_status=license_status(SRC_KEY),
                    modality="multi_turn",
                    turns=[make_turn("user", payload, "user_direct", 0)],
                    structured_action={"action_type": "unknown",
                                       "target_resource": suite,
                                       "stated_purpose": None},
                    label={"risk_category": "benign",
                           "is_malicious": False,
                           "attack_family": "benign",
                           "purpose_capability_consistent": True,
                           "confidence": "high",
                           "attack_stage_precursor": False},
                    notes=f"agentdojo benign task [{suite}] {node.name}",
                ))

    recs = [r for r in recs if validate_record(r) == []]
    return write_slice(SRC_KEY, recs)


if __name__ == "__main__":
    main()
