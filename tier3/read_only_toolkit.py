"""Tier 3 read-only investigation toolkit (v0.5 Part 4).

Tier3 is the layer that RESOLVES the information gaps Tier2 flagged as unresolvable from
the Evidence Capsule alone (e.g. "is 'deployment-config-host' an internal service or an
external sink?"). It does this by querying read-only sources — NEVER by writing, executing,
or mutating anything. The zero-side-effect property is a SAFETY REQUIREMENT, not a style
choice: a guardrail layer that investigates must not itself become an attack surface.

Three tools (all read-only):
  1. query_session_trajectory(resource) — has this target appeared before in this session /
     related sessions, and was it previously judged normal? (history of prior verdicts)
  2. search_codebase(resource) — does the hostname/path appear in the repo's config files,
     docs, or existing references? (is it a known, referenced resource?)
  3. query_infra_registry(resource) — is the target a REGISTERED internal service, or an
     unknown/external address? (asset inventory lookup)

The toolkit is a facade over an injectable backend (Dependency Inversion). The default
backend is :class:`FixtureToolkitBackend` — an in-memory, EXPLICITLY-LABELED synthetic test
fixture. There is no real session-trajectory store / codebase index / infra inventory in
this prototype's test environment, so the default backend carries clearly-marked synthetic
data so the investigator MECHANISM can be exercised. Production would inject a real backend.
This is documented honestly in reports/v05_part4_tier3.md — the fixture is test input, not
a fabricated claim that a real system was queried.

Safety property (enforced + tested in tests/test_tier3_toolkit.py):
  - ReadOnlyToolkit exposes ONLY read methods. No method name matches write/exec/mutate/
    delete/save/push/send/patch. A test introspects the class and asserts this.
  - Backends subclass ReadOnlyToolkitBackend, whose ONLY abstract methods are the 3 reads.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class TrajectoryResult:
    """Result of query_session_trajectory."""
    resource: str
    found: bool = False
    n_occurrences: int = 0
    prior_verdicts: list[str] = field(default_factory=list)   # e.g. ["benign","benign"]
    note: str = ""


@dataclass
class CodebaseResult:
    """Result of search_codebase."""
    resource: str
    found: bool = False
    locations: list[str] = field(default_factory=list)       # e.g. ["deploy/config.yaml"]
    context: str = ""                                         # the matching line/snippet
    note: str = ""


@dataclass
class InfraResult:
    """Result of query_infra_registry."""
    resource: str
    registered: bool = False
    kind: str = "unknown"     # "internal_service" | "external" | "unknown"
    owner: str | None = None
    note: str = ""


class ReadOnlyToolkitBackend(ABC):
    """Abstract read-only backend. Concrete backends implement ONLY these three reads.

    A backend that needs to write or execute anything to answer a query is WRONG by design
    — it must not exist in this layer. The ABC deliberately defines no write/exec methods.
    """

    @abstractmethod
    def query_session_trajectory(self, resource: str) -> TrajectoryResult: ...
    @abstractmethod
    def search_codebase(self, resource: str) -> CodebaseResult: ...
    @abstractmethod
    def query_infra_registry(self, resource: str) -> InfraResult: ...


# Denylist of verbs a read-only toolkit method must NEVER carry. Used by the safety test.
_WRITE_EXEC_VERBS = ("write", "exec", "run", "mutate", "delete", "save", "push", "send",
                     "patch", "update", "create", "insert", "upload", "post", "put")


class ReadOnlyToolkit:
    """Read-only investigation facade. Exposes ONLY the three read methods.

    All methods are side-effect-free queries against the injected backend. The class
    MUST NOT gain write/exec methods — tests/test_tier3_toolkit.py enforces this by
    introspecting the public method names against :data:`_WRITE_EXEC_VERBS`.
    """

    def __init__(self, backend: ReadOnlyToolkitBackend | None = None):
        # default to the synthetic fixture backend (clearly labeled test data)
        self._backend: ReadOnlyToolkitBackend = backend or FixtureToolkitBackend()

    def query_session_trajectory(self, resource: str) -> TrajectoryResult:
        return self._backend.query_session_trajectory(resource)

    def search_codebase(self, resource: str) -> CodebaseResult:
        return self._backend.search_codebase(resource)

    def query_infra_registry(self, resource: str) -> InfraResult:
        return self._backend.query_infra_registry(resource)


class FixtureToolkitBackend(ReadOnlyToolkitBackend):
    """In-memory SYNTHETIC test-fixture backend.

    This is NOT a real session-trajectory store, codebase index, or infra inventory — the
    prototype has none. It holds a small, explicitly-labeled fixture so the investigator
    MECHANISM can be exercised end-to-end. Two fixtures are provided:
      - DEFAULT (empty): no resource is registered / referenced / seen before. This models
        "the destination is unverified by every available read-only source" — the honest
        outcome for an unknown host like 'deployment-config-host'. The investigator should
        then ESCALATE TO HUMAN (it cannot confirm the destination is legitimate).
      - Populated variant (via .with_registry_entry / .with_codebase_ref / .with_trajectory):
        models a resource that IS known — the investigator should then RESOLVE the verdict.
    A real deployment injects a real backend; nothing here claims a real system was queried.
    """

    def __init__(self):
        self._infra: dict[str, InfraResult] = {}
        self._codebase: dict[str, CodebaseResult] = {}
        self._trajectory: dict[str, TrajectoryResult] = {}
        self._fixture_label = "synthetic test fixture (no real system queried)"

    # --- fixture population (test-setup only; NOT exposed via the ReadOnlyToolkit facade) ---
    def with_registry_entry(self, resource: str, *, kind: str, owner: str | None = None) -> "FixtureToolkitBackend":
        self._infra[resource] = InfraResult(resource=resource, registered=True, kind=kind,
                                            owner=owner, note=self._fixture_label)
        return self

    def with_codebase_ref(self, resource: str, *, locations: list[str], context: str = "") -> "FixtureToolkitBackend":
        self._codebase[resource] = CodebaseResult(resource=resource, found=True,
                                                  locations=list(locations), context=context)
        return self

    def with_trajectory(self, resource: str, *, n: int, prior_verdicts: list[str]) -> "FixtureToolkitBackend":
        self._trajectory[resource] = TrajectoryResult(resource=resource, found=True,
                                                       n_occurrences=n,
                                                       prior_verdicts=list(prior_verdicts),
                                                       note=self._fixture_label)
        return self

    def label_external_attacker(self, resource: str) -> "FixtureToolkitBackend":
        """Explicitly mark a resource as a known external/attacker destination (scenario A)."""
        self._infra[resource] = InfraResult(resource=resource, registered=False, kind="external",
                                             owner=None, note=self._fixture_label + " — flagged external")
        return self

    # --- the three read methods (the only thing ReadOnlyToolkit can call) ---
    def query_session_trajectory(self, resource: str) -> TrajectoryResult:
        if resource in self._trajectory:
            r = self._trajectory[resource]
            return TrajectoryResult(resource=resource, found=True, n_occurrences=r.n_occurrences,
                                     prior_verdicts=list(r.prior_verdicts), note=r.note)
        return TrajectoryResult(resource=resource, found=False, n_occurrences=0,
                                 prior_verdicts=[], note="no prior trajectory (fixture: unseen)")

    def search_codebase(self, resource: str) -> CodebaseResult:
        if resource in self._codebase:
            r = self._codebase[resource]
            return CodebaseResult(resource=resource, found=True, locations=list(r.locations),
                                   context=r.context)
        return CodebaseResult(resource=resource, found=False, locations=[],
                              note="not referenced in codebase (fixture: unseen)")

    def query_infra_registry(self, resource: str) -> InfraResult:
        if resource in self._infra:
            r = self._infra[resource]
            return InfraResult(resource=resource, registered=r.registered, kind=r.kind,
                               owner=r.owner, note=r.note)
        return InfraResult(resource=resource, registered=False, kind="unknown",
                           owner=None, note="not in infra registry (fixture: unseen)")
