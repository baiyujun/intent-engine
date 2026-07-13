# Part A — Tier3 read_only_toolkit.py vs ClawSentry review_toolkit.py (code-reuse audit)

## Direct answer first

- **Reused from ClawSentry: the class NAME (`ReadOnlyToolkit`) and the read-only-investigation
  CONCEPT.** Nothing else.
- **Hand-written from scratch: every line of the implementation** — the dataclasses
  (`TrajectoryResult`/`CodebaseResult`/`InfraResult`), the `ReadOnlyToolkitBackend` ABC, the
  `ReadOnlyToolkit` facade, the `FixtureToolkitBackend`, the `_WRITE_EXEC_VERBS` denylist, and
  the method-name-introspection safety test.
- **Why not directly reuse ClawSentry's code:** interface mismatch + dependency weight +
  different abstraction. ClawSentry's toolkit is a **concrete class doing real I/O** (async
  file reads, `git` subprocess, a real `trajectory_store`, a real `session_registry`, with
  path-sandboxing). intent-engine v0.5 has **none of those backends** (no trajectory store, no
  session registry, no workspace to sandbox), and its Tier3 needs an **infra/asset registry**
  tool that ClawSentry does not have. I chose Dependency Inversion (inject a backend) so the
  investigator is testable with a labeled synthetic fixture today and a real backend
  (which *could* be an adapter over ClawSentry's toolkit) later. ClawSentry's class is concrete,
  not injectable.

This is honest: I did **not** "reuse ClawSentry's code." I borrowed the name and the idea,
then wrote my own. Saying otherwise would be the "设计思路一致" hand-wave the task forbids.

## Side-by-side 1 — class identity & constructor

```python
# ClawSentry  review_toolkit.py:20-51  — CONCRETE, real I/O
class ReadOnlyToolkit:
    MAX_FILE_READ_BYTES = 512_000
    MAX_TOOL_CALLS = 20
    MAX_TRAJECTORY_EVENTS = 500
    # ... MAX_SEARCH_FILES, MAX_SEARCH_SECONDS, DEFAULT_SEARCH_IGNORES
    def __init__(self,
        workspace_root: Path,          # a REAL filesystem root
        trajectory_store: Any,         # a real replay_session() store
        session_registry: Any = None, # a real get_session_risk() registry
    ) -> None:
        self._default_workspace_root = workspace_root.resolve()
        self._workspace_root_ctx: ContextVar[Path] = ContextVar(...)  # async rebinding
        self._transcript_path_ctx: ContextVar[str] = ContextVar(...)
        self._session_id_ctx: ContextVar[str] = ContextVar(...)
        self._trajectory_store = trajectory_store
        self._session_registry = session_registry
        self._calls_remaining = self.MAX_TOOL_CALLS
```

```python
# intent-engine  tier3/read_only_toolkit.py:86-105  — FACADE over an injectable backend
class ReadOnlyToolkit:
    def __init__(self, backend: ReadOnlyToolkitBackend | None = None):
        # default to the synthetic fixture backend (clearly labeled test data)
        self._backend: ReadOnlyToolkitBackend = backend or FixtureToolkitBackend()
    def query_session_trajectory(self, resource: str) -> TrajectoryResult:
        return self._backend.query_session_trajectory(resource)
    def search_codebase(self, resource: str) -> CodebaseResult:
        return self._backend.search_codebase(resource)
    def query_infra_registry(self, resource: str) -> InfraResult:
        return self._backend.query_infra_registry(resource)
```

**Difference:** ClawSentry's constructor binds to a real workspace + trajectory store +
session registry and uses `ContextVar` for async per-session rebinding. Mine takes a single
injectable `backend` (an ABC) and forwards 3 methods. Different abstraction on purpose:
intent-engine has no real store to bind to.

## Side-by-side 2 — tool surface (what each can query)

| ClawSentry `ReadOnlyToolkit` (13 read methods) | mine `ReadOnlyToolkit` (3) |
|---|---|
| `read_trajectory(session_id, limit)` / `read_trajectory_page(...)` | `query_session_trajectory(resource)` |
| `read_file(rel_path)` / `read_file_range(...)` | — (no file read) |
| `read_transcript()` | — |
| `read_session_risk(limit)` | — (ClawSentry's `session_registry` is risk-events, not an infra registry) |
| `search_codebase(pattern, glob, max_results)` — **regex over real files** | `search_codebase(resource)` — **looks up a named resource** |
| `query_git_diff/status/show`, `list_changed_files` — git subprocess | — |
| `read_package_manifest(rel_path)` — parse package.json/pyproject/Cargo | — |
| `read_l3_trace(limit)` — L3 risk records | — |
| `list_directory(rel_path)` | — |
| — (no infra/asset-registry tool) | `query_infra_registry(resource)` — **intent-engine's NEW tool, ClawSentry has no analog** |

**Difference:** ClawSentry's `search_codebase` takes a **regex pattern + glob** and walks the
real workspace; mine takes a **resource name** and looks it up. ClawSentry has no
infra-registry tool — `query_infra_registry` is intent-engine-specific (resolve "is
deployment-config-host internal or external"), which is exactly the gap Tier3 needs that
ClawSentry's surface doesn't cover.

## Side-by-side 3 — sandbox path validation (the key safety logic)

```python
# ClawSentry  review_toolkit.py:123-145  — real path sandboxing on real reads
def _safe_path(self, relative_path: str) -> Path:
    clean = relative_path.lstrip("/")
    workspace_root = self.workspace_root
    target = (workspace_root / clean).resolve()
    try:
        target.relative_to(workspace_root)        # ← must stay inside workspace
    except ValueError as exc:
        raise ValueError(f"Path '{relative_path}' escapes workspace_root") from exc
    return target

def _safe_bound_path(self, bound_path: str) -> Path:
    workspace_root = self.workspace_root
    candidate = Path(bound_path)
    target = (candidate.resolve() if candidate.is_absolute()
              else (workspace_root / candidate).resolve())
    try:
        target.relative_to(workspace_root)
    except ValueError as exc:
        raise ValueError(f"Path '{bound_path}' escapes workspace_root") from exc
    return target
```
ClawSentry tests this: `test_rejects_dotdot`, `test_rejects_absolute_escape`,
`test_nested_dotdot_escape`, `test_leading_slash_stripped` (test_review_toolkit.py:123-150).

```python
# intent-engine  tier3/read_only_toolkit.py  — NO path validation, because NO file I/O
# (the whole file has no open()/Path/resolve/relative_to — the fixture backend is in-memory dicts)
class FixtureToolkitBackend(ReadOnlyToolkitBackend):
    def query_infra_registry(self, resource: str) -> InfraResult:
        if resource in self._infra:           # dict lookup, not a path
            r = self._infra[resource]
            return InfraResult(resource=resource, registered=r.registered, kind=r.kind, ...)
        return InfraResult(resource=resource, registered=False, kind="unknown", ...)
```

**Difference (this is the heart of why I didn't reuse):** ClawSentry's safety property is
**"you may read files, but only inside the workspace sandbox"** — enforced by
`_safe_path` resolve+`relative_to`. intent-engine's prototype toolkit does **no file I/O at
all** (it queries in-memory fixtures), so there is nothing to sandbox. The two safety
models are genuinely different and serve different threat models:

- ClawSentry: real investigator reads real files → must stop path traversal.
- intent-engine: investigator queries labeled fixtures → must (a) have no write/exec
  methods and (b) make no real I/O. Enforced by method-name introspection, not path checks.

A path-sandbox method copied from ClawSentry into my toolkit would be **dead code** — there
is no `read_file` to protect. So it was not "reused"; it was *not applicable*.

## Side-by-side 4 — the safety mechanism each actually enforces

```python
# ClawSentry: safety = path sandboxing + budget (review_toolkit.py:116-131, 256-294)
def _consume_call(self) -> None:
    if self._calls_remaining <= 0:
        raise ToolCallBudgetExhausted(...)   # budget lives IN the toolkit
    self._calls_remaining -= 1
# every read method calls self._consume_call() first, then self._safe_path(...)
```

```python
# intent-engine: safety = "no write/exec method" + no real I/O (read_only_toolkit.py:82-91 + test)
_WRITE_EXEC_VERBS = ("write","exec","run","mutate","delete","save","push","send",
                     "patch","update","create","insert","upload","post","put")
# test_tier3_toolkit.py::test_toolkit_has_no_write_or_exec_methods introspects the class:
for cls in (ReadOnlyToolkit, ReadOnlyToolkitBackend):
    methods = [n for n,_ in inspect.getmembers(cls, predicate=callable) if not n.startswith("_")]
    for verb in _WRITE_EXEC_VERBS:
        assert [m for m in methods if verb in m.lower()] == []
# budget is in the INVESTIGATOR (investigator.py), not the toolkit
```

**Difference:** ClawSentry's `_WRITE_EXEC_VERBS`-style introspection does **not exist** in
ClawSentry (it relies on path sandboxing + the fact that its methods are reads). The
`_WRITE_EXEC_VERBS` denylist and the introspection test are **my additions**, not borrowed.
The budget (`ToolCallBudgetExhausted` / `_consume_call`) is ClawSentry's and lives inside its
toolkit; mine lives in the investigator (separate concern).

## Verdict

- **Borrowed:** the `ReadOnlyToolkit` name + the "read-only toolkit for an L3 review agent"
  concept. Both files are async-vs-sync, concrete-vs-facade, real-I/O-vs-fixture, with
  different tool surfaces (ClawSentry has no infra-registry; mine has no git/file tools).
- **Reused code:** zero lines. `grep`-verified: my file imports no `clawsentry.*`, has no
  `Path`/`open`/`resolve`/`relative_to`/`subprocess`/`async`, shares no identifiers with
  ClawSentry beyond the class name and the generic word "search_codebase" (different signature).
- **Why not reusable directly:** (1) interface — ClawSentry needs a real workspace +
  trajectory_store + session_registry that intent-engine doesn't have; (2) dependency weight
  — it pulls `clawsentry._tomllib`, ContextVar async binding, a git subprocess; (3) missing
  tool — it has no infra-registry, which is the one query Tier3 actually needs for ssh-debug.
- **The honest follow-up:** a real backend for intent-engine's Tier3 *could* be written as an
  adapter that wraps ClawSentry's toolkit (mapping `query_infra_registry` to a real asset
  inventory, `search_codebase` to ClawSentry's regex search, `query_session_trajectory` to
  `read_trajectory`). That adapter is a v0.6 integration task; it is not what v0.5 shipped
  (v0.5 shipped the facade + fixture + investigator + the introspection safety test).

## Files compared
- `/home/hjy/ClawSentry/src/clawsentry/gateway/review_toolkit.py` (456 lines, 18.8KB)
- `/home/hjy/intent-engine/tier3/read_only_toolkit.py` (~175 lines)
- `/home/hjy/ClawSentry/src/clawsentry/tests/test_review_toolkit.py` (533 lines — path-sandbox tests)
- `/home/hjy/intent-engine/tests/test_tier3_toolkit.py` (method-name introspection + degradation tests)
