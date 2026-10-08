# Agent Working Rules

These rules are mandatory for any AI agent working on this project.

The agent must treat `implementation.md` as the source of truth for project architecture, implementation phases, constraints, and acceptance criteria.

---

## 1. Phase Discipline

The project is implemented strictly in phases.

When the user requests:

> Implement Phase N

the agent MUST:

1. Read `implementation.md`.
2. Read the requirements and acceptance criteria for Phase N.
3. Inspect only the repository files relevant to Phase N.
4. Implement Phase N only.
5. Add or update tests required by Phase N.
6. Run relevant validation and tests.
7. Report the result.
8. Stop.

The agent MUST NOT automatically implement Phase N+1.

The agent MAY create interfaces, extension points, schemas, or internal structures required to support future phases, but MUST NOT implement future-phase behavior.

### Forbidden

* Implementing future phases without explicit instruction.
* Adding unrelated features.
* Refactoring unrelated code.
* Reorganizing the entire repository unnecessarily.
* Adding speculative architecture.
* Adding features "because they may be useful later".

---

## 2. Read Before Write

Before modifying code, the agent MUST inspect the existing implementation.

Required order:

1. `implementation.md`
2. Relevant source files
3. Relevant tests
4. Relevant configuration
5. Implement
6. Run targeted tests
7. Run broader validation when appropriate

The agent MUST NOT assume that a component does not exist before checking the repository.

The agent MUST NOT recreate functionality that already exists.

The agent SHOULD read the minimum amount of code necessary to understand the current task.

Avoid reading the entire repository when the requested phase only affects a small subset of files.

---

## 3. Anti-AI-Slop Rules

Code must be production-oriented, minimal, and justified.

### Do NOT create:

* Unused classes
* Unused functions
* Unused interfaces
* Empty abstraction layers
* Generic "manager", "helper", or "utils" classes without a concrete need
* Wrapper classes that provide no meaningful behavior
* Duplicate representations of the same concept
* Speculative plugin systems
* Speculative dependency injection frameworks
* Generic factories without multiple real implementations
* Configuration options that are not consumed
* Dead code
* Placeholder production implementations
* Fake implementations
* Unnecessary comments
* Obvious comments that merely restate the code
* TODOs instead of implementing required functionality

### Prefer:

* Small functions
* Explicit data flow
* Strongly typed models
* Concrete implementations
* Clear interfaces only where multiple implementations actually exist or are required
* Standard library functionality when sufficient
* Existing project dependencies before introducing new dependencies

Every abstraction must have a real consumer.

Every dependency must have a concrete reason to exist.

---

## 4. No Speculative Engineering

Do not implement functionality based on assumptions about future requirements.

If a feature is not required by the current phase, do not implement it.

Examples:

Do NOT add:

* Distributed scanning
* Plugin marketplaces
* Cloud execution
* Message queues
* REST APIs
* Web dashboards
* AI/LLM integrations
* Complex caching systems
* Multi-process orchestration
* Kubernetes support

unless explicitly required by the project specification.

The goal is to build the required system correctly, not to maximize the number of features.

---

## 5. Performance Is a Requirement

Performance is part of correctness.

The agent MUST consider:

* CPU usage
* Memory usage
* Disk I/O
* Network requests
* Subprocess creation
* Thread/task count
* Database operations
* Parsing cost
* Duplicate work
* Repeated network requests
* Repeated tool execution

Do not optimize blindly.

Measure first when optimization is relevant.

### Avoid unnecessary:

* Subprocesses
* Threads
* Async tasks
* Network requests
* File reads
* File writes
* Database queries
* Parsing passes
* Object allocations
* Serialization/deserialization
* Duplicate scans

Do not introduce concurrency merely because concurrency is available.

Concurrency MUST be used only where tasks are genuinely independent and where it provides measurable or expected benefit without violating resource limits.

---

## 6. Controlled Concurrency

The project MUST NOT use unrestricted concurrency.

Concurrency must be bounded by explicit limits.

At minimum, distinguish between resource classes where appropriate:

* Global concurrency
* DNS concurrency
* Network/service discovery concurrency
* HTTP concurrency
* Web enumeration concurrency
* Vulnerability-testing concurrency

A high global concurrency value MUST NOT automatically cause every subsystem to execute at that rate.

The scheduler should prevent resource exhaustion.

Avoid launching expensive tasks when cheaper discovery information shows that they are unnecessary.

Example:

If service discovery indicates that a host does not expose HTTP/HTTPS, HTTP-specific enumeration MUST NOT run against that host.

---

## 7. Avoid Redundant Work

Before executing a task, the agent should determine whether the task is actually necessary.

The system should reuse existing observations when possible.

Avoid:

```text
discover → scan → rescan → rescan again
```

when the existing evidence is sufficient.

Tasks should have clear inputs and outputs.

If two tasks require the same information, prefer sharing the normalized observation rather than executing the underlying external tool twice.

Duplicate tasks should be detected and avoided where practical.

---

## 8. External Tool Discipline

All external security/reconnaissance tools MUST be isolated behind controlled adapters.

Do not scatter raw subprocess calls throughout the application.

External execution MUST go through the project's command execution layer.

Each execution should provide, where applicable:

* Tool name
* Tool version
* Arguments
* Target
* Start time
* End time
* Duration
* Exit code
* stdout
* stderr
* Timeout state
* Cancellation state

The agent MUST NOT silently ignore tool failures.

A failed tool execution must remain distinguishable from:

* No result
* No finding
* Empty output
* Successful execution

---

## 9. Safe Command Execution

Never construct shell commands through unsafe string interpolation.

Prefer argument arrays such as:

```python
[
    "nmap",
    "-sV",
    target,
]
```

over shell strings.

Avoid `shell=True` unless there is a documented and justified requirement.

Targets and discovered values MUST be treated as untrusted input.

Command execution must have:

* Timeout controls
* Exit status handling
* Cancellation support where applicable
* Resource limits where practical
* Clear error propagation

Never allow discovered target data to become uncontrolled shell syntax.

---

## 10. Scope Is a Hard Security Boundary

Scope enforcement is mandatory.

The system MUST distinguish between:

* User-provided scope
* Discovered assets
* Out-of-scope assets

Discovery MUST NOT automatically expand the authorized scan scope.

Examples:

If the user authorizes:

```text
example.com
```

and DNS reveals another domain, IP, or hostname, that does not automatically authorize scanning it.

Redirects, DNS results, links, subdomains, virtual hosts, and discovered IP addresses must be evaluated against the configured scope policy before active interaction.

Out-of-scope targets MUST NOT be actively scanned.

Scope validation should happen centrally rather than being reimplemented inconsistently in individual tools.

---

## 11. Safe Defaults

The default configuration should favor:

* Explicit scope
* Bounded concurrency
* Timeouts
* Minimal necessary requests
* Non-destructive checks
* Evidence collection
* Reproducibility

Destructive or potentially disruptive testing MUST NOT be enabled implicitly.

Active vulnerability testing must require explicit configuration/profile selection where appropriate.

SQL injection testing, aggressive enumeration, and similar intrusive operations must remain controlled by explicit scope and execution policy.

---

## 12. Discovery Before Expensive Testing

Use staged discovery.

Prefer:

```text
Target
  ↓
Basic discovery
  ↓
Service detection
  ↓
Relevant protocol detection
  ↓
Protocol-specific enumeration
  ↓
Vulnerability testing
```

Do not execute every available tool against every target by default.

For example:

```text
No HTTP service
    ↓
Skip HTTP enumeration

No TLS service
    ↓
Skip TLS-specific checks

No relevant service
    ↓
Skip service-specific vulnerability checks
```

This is both a performance requirement and a false-positive reduction strategy.

---

## 13. Observation vs Finding

Do not treat raw tool output as a confirmed vulnerability.

The system must distinguish between:

### Observation

Something detected by a tool or protocol interaction.

### Evidence

Data supporting an observation or finding.

### Finding

A correlated security issue supported by sufficient evidence.

### Risk

The assessed impact/likelihood/severity of the finding.

The pipeline should conceptually remain:

```text
Tool Output
    ↓
Parser
    ↓
Observation
    ↓
Correlation
    ↓
Finding
    ↓
Confidence
    ↓
Risk / CVSS
```

Weak evidence MUST NOT automatically become a confirmed vulnerability.

---

## 14. Evidence-Based Findings

Every finding should be traceable to evidence.

Where applicable, preserve:

* Target
* Asset
* Service
* Endpoint
* Tool
* Tool version
* Execution timestamp
* Command/arguments
* Exit code
* Relevant raw output
* Parsed observation
* Correlation logic
* Confidence
* Risk score
* Supporting evidence

Do not create findings solely because a tool returned a suspicious keyword.

Findings should be reproducible from stored evidence whenever practical.

---

## 15. False-Positive Reduction

The system should prioritize evidence quality over finding count.

Avoid simplistic rules such as:

```text
HTTP 200 = file exists
```

or:

```text
Tool says vulnerable = confirmed vulnerability
```

Where web enumeration is used, establish an appropriate baseline response when necessary.

For example, wildcard routing may return HTTP 200 for nonexistent paths. The scanner should account for baseline behavior before classifying discovered paths as real resources.

Similar normalization and validation should be applied to other tool outputs where false positives are known to occur.

---

## 16. Finding Deduplication

The same underlying issue reported by multiple tools should normally become one logical finding with multiple evidence sources.

Example:

```text
curl       → missing security header
nikto      → missing security header
custom     → missing security header
```

should not automatically produce three separate findings.

Instead:

```text
Finding
 ├── Evidence: curl
 ├── Evidence: nikto
 └── Evidence: custom check
```

Deduplication must preserve evidence provenance.

Do not deduplicate unrelated findings merely because they have similar names.

---

## 17. Confidence Is Separate From Severity

Do not confuse:

```text
Confidence
```

with:

```text
Severity
```

A finding can be:

```text
High severity
Low confidence
```

or:

```text
Low severity
High confidence
```

Confidence should describe how strongly the available evidence supports the finding.

Severity/risk should describe the security impact.

---

## 18. CVSS Discipline

CVSS scores MUST be evidence-driven.

Do not invent CVSS metrics merely to produce a score.

If required metrics cannot be determined reliably:

* Mark the assessment as incomplete/review-required, or
* Use only the metrics that can be justified according to the project's scoring policy.

The system must preserve the distinction between:

```text
Observed evidence
```

and:

```text
Analyst-assessed risk
```

Do not present an automatically generated score as authoritative when the available evidence is insufficient.

---

## 19. Data Model Discipline

Use typed models for important domain concepts.

Avoid passing loosely structured dictionaries throughout the application when a stable domain model exists.

However, do not create a model for every small value.

Create domain models when they provide:

* Validation
* Type safety
* Clear semantics
* Reuse
* Serialization
* Persistence
* Stable interfaces

Avoid unnecessary model proliferation.

---

## 20. Database Discipline

Database access must avoid unnecessary I/O.

Prefer:

* Batched writes where appropriate
* Transactions for logically grouped operations
* Indexed lookup fields
* Prepared/parameterized queries
* Avoiding repeated identical queries
* Clear repository boundaries

Do not write every tiny intermediate event to disk if batching is more appropriate.

Do not load entire large datasets into memory when streaming or incremental processing is sufficient.

Database schema changes must be explicit and migration-safe.

---

## 21. Error Handling

Errors must be explicit and actionable.

Do NOT use:

```python
except Exception:
    pass
```

Do NOT silently convert failures into successful empty results.

Errors should preserve enough context to determine:

* What operation failed
* Which target was involved
* Which tool was involved
* Why it failed
* Whether execution can continue
* Whether the result is incomplete

Expected failures should be handled specifically.

Unexpected failures should not be silently swallowed.

---

## 22. Logging

Logs should support debugging and reproducibility without becoming excessive.

Use appropriate log levels:

* DEBUG
* INFO
* WARNING
* ERROR

Do not log secrets, credentials, tokens, or sensitive authentication material.

Avoid logging the same error repeatedly at multiple layers.

A lower-level failure should generally be recorded once with sufficient context, then propagated appropriately.

---

## 23. Secret and Sensitive Data Handling

Never intentionally expose:

* Passwords
* API keys
* Session tokens
* Authorization headers
* Private keys
* Credentials
* Sensitive cookies

in reports or normal logs.

Evidence storage should distinguish between raw evidence and report-safe evidence.

Sensitive values must be redacted where appropriate.

Do not introduce credential collection or storage functionality unless explicitly required by the specification.

---

## 24. Configuration Discipline

Configuration must have a clear source of truth.

Avoid hardcoding operational settings throughout the codebase.

Configuration should control appropriate parameters such as:

* Timeouts
* Concurrency
* Profiles
* Tool paths
* Output formats
* Scope policy
* Active/passive behavior

Do not expose configuration options that have no implementation.

Do not create a configuration option merely because it might be useful later.

---

## 25. CLI Discipline

CLI options must correspond to real behavior.

Every option should:

1. Have a clear purpose.
2. Be validated.
3. Affect execution or output.
4. Be documented.
5. Have tests where practical.

Do not create dozens of flags merely to make the CLI appear feature-rich.

Prefer coherent options and profiles over an unnecessarily large number of independent switches.

---

## 26. Profiles

Profiles should represent meaningful operational modes.

Examples:

```text
quick
passive
network
web
full
```

A profile must actually change execution behavior.

Do not create profiles that are merely aliases with no meaningful difference.

Profiles must respect:

* Scope
* Concurrency limits
* Tool availability
* Active/passive policy
* Task dependencies

---

## 27. Testing Requirements

Every implemented phase must include appropriate tests.

At minimum, use the most relevant combination of:

* Unit tests
* Parser tests
* Model validation tests
* Integration tests
* Scheduler tests
* Scope tests
* Database tests
* CLI tests
* End-to-end tests

For external tools, prefer deterministic fixtures for parser tests.

Do not make the test suite depend on arbitrary public internet targets.

Network/integration tests should use controlled targets whenever possible.

A feature is not considered complete merely because the implementation compiles.

---

## 28. Test the Failure Paths

Tests should not only cover successful execution.

Where relevant, test:

* Timeout
* Non-zero exit code
* Empty output
* Malformed output
* Missing tool
* Invalid target
* Out-of-scope target
* Duplicate task
* Cancellation
* Partial result
* Database failure
* Parser failure
* Unexpected tool behavior

The system must fail safely.

---

## 29. External Tool Availability

Do not assume that every external binary exists on every system.

Tool availability should be detected or reported clearly.

A missing optional tool should not necessarily crash the entire scan.

However, the system MUST distinguish:

```text
Tool unavailable
```

from:

```text
Tool executed successfully and found nothing
```

Do not silently skip unavailable tools.

---

## 30. Reproducibility

A scan should be reproducible as far as practical.

Record enough metadata to understand how a result was produced:

* Project/application version
* Scan/session ID
* Configuration/profile
* Target
* Scope
* Tool versions
* Relevant command arguments
* Start/end timestamps
* Findings
* Evidence

Do not rely on undocumented runtime state.

---

## 31. Resume and State

If the current phase implements resumability, task state must be explicit.

Tasks should have distinguishable states such as:

```text
PENDING
RUNNING
COMPLETED
FAILED
CANCELLED
SKIPPED
```

Do not infer state from the existence of arbitrary files.

Resume logic must not accidentally duplicate expensive or intrusive tasks.

---

## 32. Minimal Diff Principle

Modify only what is necessary to satisfy the current phase.

Before changing a file, determine whether the change is actually required.

Avoid:

* Formatting unrelated files
* Renaming unrelated variables
* Rewriting working code
* Changing dependency versions unnecessarily
* Large-scale refactors
* Style migrations
* Repository-wide cleanup

A small correct change is preferred over a large "better" rewrite.

---

## 33. Dependency Discipline

Before adding a dependency, verify that:

1. The functionality cannot reasonably be implemented with the standard library.
2. An existing dependency cannot provide it.
3. The dependency is justified by the current phase.
4. It does not introduce unnecessary complexity or security risk.

Do not add dependencies for trivial functionality.

---

## 34. Documentation Discipline

Documentation should explain decisions and behavior that users/developers actually need.

Do not generate large amounts of generic documentation.

Documentation should focus on:

* How to use the implemented feature
* Important configuration
* Security constraints
* Architectural decisions
* Limitations
* Reproducibility
* Known behavior

Do not document features that do not exist.

---

## 35. No Fake Completion

Never claim that a feature is implemented if it is only:

* Stubbed
* Placeholder code
* Hardcoded
* Partially wired
* Returning fake data
* Returning static example results
* Implemented but not connected to the execution path

If something cannot be completed in the current phase, report it explicitly.

Do not hide incomplete functionality behind a successful CLI response.

---

## 36. Validation Before Completion

Before declaring a phase complete, the agent MUST verify:

### Code

* Implementation exists.
* Imports work.
* Types are valid.
* No obvious dead code was introduced.
* No required feature is stubbed.

### Tests

* New tests pass.
* Relevant existing tests pass.
* Failure paths are covered where applicable.

### Integration

* The implemented component is actually connected to the intended execution path.
* Configuration reaches the implementation.
* CLI options affect real behavior where applicable.
* Errors propagate correctly.

### Security

* Scope is enforced.
* Inputs are validated.
* Commands are safely executed.
* Secrets are not leaked.
* Active operations respect configured policy.

### Performance

* No obvious redundant execution was introduced.
* Concurrency is bounded.
* Expensive tools are not launched unnecessarily.
* Unnecessary I/O is avoided.

---

## 37. Definition of Done for Every Phase

A phase is DONE only when all of the following are true:

```text
[ ] Phase requirements implemented
[ ] Acceptance criteria satisfied
[ ] Relevant tests added
[ ] Relevant tests passing
[ ] Existing regression tests passing
[ ] Error paths considered
[ ] Scope enforcement preserved
[ ] Security constraints preserved
[ ] Concurrency remains bounded
[ ] No unnecessary subprocesses introduced
[ ] No unnecessary network requests introduced
[ ] No unnecessary dependencies introduced
[ ] No unrelated refactoring introduced
[ ] No dead/stub/fake implementation introduced
[ ] Documentation updated where necessary
[ ] Implementation is actually wired into the system
```

If any required item is not satisfied, the agent must not claim the phase is fully complete.

---

## 38. Agent Output Format

After completing a requested phase, the agent MUST provide a concise implementation report containing:

### 1. Summary

What was implemented.

### 2. Changed Files

List only files that were created or modified.

### 3. Tests

List the tests executed and their results.

### 4. Validation

Report relevant validation such as:

* CLI validation
* Type checking
* Linting
* Integration tests
* Tool execution tests

### 5. Performance Considerations

Mention relevant concurrency, I/O, subprocess, or network decisions.

### 6. Security Considerations

Mention relevant scope, input validation, command execution, and active-testing controls.

### 7. Known Limitations

Only real limitations. Do not invent hypothetical limitations.

### 8. Next Phase

State only the next phase name if useful.

Do NOT implement it.

---

## 39. Stop Condition

Once the requested phase satisfies its acceptance criteria:

**STOP IMPLEMENTING.**

Do not continue into the next phase.

Do not perform unrelated cleanup.

Do not add "nice to have" features.

Do not refactor unrelated code.

Do not optimize unrelated components.

The user will explicitly request the next phase.

---

# Agent Execution Contract

For every implementation request, follow this contract:

```text
READ:
  implementation.md
  Current phase requirements
  Relevant source files
  Relevant tests

UNDERSTAND:
  Existing architecture
  Current data flow
  Current constraints
  Dependencies
  Scope boundaries

IMPLEMENT:
  Requested phase only
  Minimal necessary changes
  Production-quality code
  Real functionality only

TEST:
  Unit tests
  Integration tests where relevant
  Failure paths
  Regression tests

VALIDATE:
  Security
  Scope
  Concurrency
  Performance
  Error handling
  CLI/configuration integration

REPORT:
  Summary
  Changed files
  Tests
  Validation
  Performance considerations
  Security considerations
  Known limitations

STOP:
  Do not implement future phases
  Do not perform unrelated refactoring
  Do not add speculative features
```

---

# Core Principle

The agent must optimize for:

```text
Correctness
    >
Security
    >
Evidence quality
    >
Reliability
    >
Performance
    >
Maintainability
    >
Feature count
```

The objective is not to produce the largest amount of code.

The objective is to produce the smallest amount of correct, tested, secure, maintainable code that satisfies the current phase and integrates cleanly with the existing architecture.
