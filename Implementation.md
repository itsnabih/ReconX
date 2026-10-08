# ReconX — Implementation Plan

## 1. Project Objective

Build a production-oriented CLI reconnaissance and VAPT orchestration framework named **ReconX**.

ReconX is NOT intended to replace existing security tools. Its purpose is to orchestrate existing command-line tools, normalize their outputs, correlate observations, reduce false positives, calculate/assist CVSS risk assessment, preserve evidence, and generate actionable VAPT reports.

The primary engineering priorities are:

1. Accuracy
2. Low false-positive rate
3. Performance
4. Efficient concurrency
5. Deterministic and reproducible results
6. Strong evidence preservation
7. Extensibility
8. Scope safety
9. High-quality reporting

The framework must be designed as an extensible engine rather than a collection of shell scripts.

---

# 2. Initial Supported Tools

The first implementation must support these external binaries:

## Domain / DNS

* whois
* dig
* host
* nslookup

## Network

* ping
* openssl
* nmap

## HTTP

* curl
* wget

## Web Discovery

* gobuster
* ffuf
* dirb

## Security Assessment

* nikto
* sqlmap

Every external tool must be implemented behind an adapter/interface.

Do NOT scatter subprocess calls throughout the codebase.

---

# 3. Recommended Technology Stack

Use:

* Python 3.12+
* Typer for CLI
* Pydantic for domain/data validation
* asyncio for orchestration of external processes
* ThreadPoolExecutor only where blocking operations genuinely require threads
* SQLite for persistent scan/session state
* YAML for scan profiles/configuration
* Jinja2 for HTML/Markdown report templates
* ReportLab for PDF generation
* pytest for testing

Use standard-library functionality wherever practical.

Avoid unnecessary dependencies.

---

# 4. High-Level Architecture

Implement the following architecture:

CLI
↓
Configuration
↓
Scope Validation
↓
Scan Coordinator
↓
Task Scheduler / DAG
↓
Tool Adapters
↓
Raw Results
↓
Parsers
↓
Normalized Observations
↓
Correlation Engine
↓
Finding Engine
↓
Deduplication
↓
Confidence Assessment
↓
Risk / CVSS Assessment
↓
Evidence Store
↓
Report Generator

The architecture must preserve separation between:

* execution
* parsing
* normalization
* correlation
* finding generation
* risk assessment
* reporting

Do not mix these responsibilities.

---

# 5. Project Structure

Implement approximately:

```text
reconx/
├── pyproject.toml
├── README.md
│
├── reconx/
│   ├── __main__.py
│   │
│   ├── cli/
│   │   ├── app.py
│   │   ├── commands.py
│   │   ├── arguments.py
│   │   └── output.py
│   │
│   ├── config/
│   │   ├── loader.py
│   │   ├── schema.py
│   │   └── defaults.py
│   │
│   ├── core/
│   │   ├── engine.py
│   │   ├── scheduler.py
│   │   ├── task.py
│   │   ├── runner.py
│   │   ├── session.py
│   │   └── cancellation.py
│   │
│   ├── scope/
│   │   ├── validator.py
│   │   └── models.py
│   │
│   ├── tools/
│   │   ├── base.py
│   │   ├── registry.py
│   │   ├── whois.py
│   │   ├── dig.py
│   │   ├── host.py
│   │   ├── nslookup.py
│   │   ├── ping.py
│   │   ├── openssl.py
│   │   ├── nmap.py
│   │   ├── curl.py
│   │   ├── wget.py
│   │   ├── gobuster.py
│   │   ├── ffuf.py
│   │   ├── dirb.py
│   │   ├── nikto.py
│   │   └── sqlmap.py
│   │
│   ├── parsers/
│   │   ├── base.py
│   │   ├── dns.py
│   │   ├── nmap.py
│   │   ├── http.py
│   │   ├── tls.py
│   │   ├── gobuster.py
│   │   ├── ffuf.py
│   │   ├── dirb.py
│   │   ├── nikto.py
│   │   └── sqlmap.py
│   │
│   ├── models/
│   │   ├── target.py
│   │   ├── asset.py
│   │   ├── observation.py
│   │   ├── endpoint.py
│   │   ├── service.py
│   │   ├── evidence.py
│   │   ├── finding.py
│   │   └── vulnerability.py
│   │
│   ├── engine/
│   │   ├── discovery.py
│   │   ├── correlation.py
│   │   ├── deduplication.py
│   │   ├── confidence.py
│   │   └── classification.py
│   │
│   ├── risk/
│   │   ├── cvss31.py
│   │   ├── cvss40.py
│   │   └── scoring.py
│   │
│   ├── storage/
│   │   ├── database.py
│   │   ├── migrations.py
│   │   └── repository.py
│   │
│   └── reporting/
│       ├── base.py
│       ├── json.py
│       ├── markdown.py
│       ├── html.py
│       └── pdf.py
│
├── profiles/
│   ├── quick.yaml
│   ├── passive.yaml
│   ├── network.yaml
│   ├── web.yaml
│   └── full.yaml
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── fixtures/
│   └── e2e/
│
└── docs/
    ├── architecture.md
    ├── cli.md
    ├── profiles.md
    └── findings.md
```

---

# 6. Core Data Model

The most important design requirement is to distinguish:

```text
Observation
Finding
Evidence
Risk
```

These are NOT interchangeable.

## Observation

An observation is raw normalized information discovered during reconnaissance.

Examples:

* open TCP port
* DNS A record
* HTTP status
* TLS certificate
* HTTP header
* discovered endpoint
* detected technology

Example:

```json
{
  "type": "open_port",
  "host": "192.0.2.10",
  "port": 443,
  "protocol": "tcp",
  "service": "https",
  "source": "nmap"
}
```

## Finding

A finding is a security-relevant conclusion derived from one or more observations/evidence.

Example:

```json
{
  "id": "RX-HTTP-001",
  "title": "Sensitive Configuration File Exposed",
  "severity": "HIGH",
  "confidence": 0.97
}
```

## Evidence

Evidence explains why a finding exists.

Evidence should include:

* tool
* tool version
* command
* target
* timestamp
* exit code
* relevant stdout/stderr
* HTTP request/response metadata where applicable
* parsed evidence
* raw evidence reference

## Risk

Risk contains:

* CVSS version
* CVSS vector
* CVSS score
* severity
* scoring rationale

---

# 7. External Tool Abstraction

Create a common interface:

```python
class ToolAdapter:
    name: str

    def check_available(self) -> bool:
        ...

    def version(self) -> str:
        ...

    def build_command(self, task) -> list[str]:
        ...

    def parse_result(self, result):
        ...
```

The actual interface may be improved during implementation, but all tools must follow the same abstraction.

Each adapter must:

1. Validate executable availability.
2. Build arguments safely.
3. Never construct shell command strings unnecessarily.
4. Execute through the centralized CommandRunner.
5. Preserve exit status.
6. Preserve stdout/stderr.
7. Parse output.
8. Return normalized objects.
9. Expose tool/version metadata.

Never use:

```python
subprocess.run(command, shell=True)
```

for target-derived input.

Prefer argument arrays.

---

# 8. CommandRunner

Implement a centralized execution layer.

Responsibilities:

* subprocess execution
* timeout
* cancellation
* stdout capture
* stderr capture
* exit-code capture
* execution duration
* process lifecycle management
* tool availability validation
* structured logging

Result model:

```text
CommandResult
├── command
├── executable
├── arguments
├── started_at
├── finished_at
├── duration
├── exit_code
├── stdout
├── stderr
└── timed_out
```

The runner must not decide whether a result represents a vulnerability.

---

# 9. Task Model

Every operation must become a Task.

Example:

```text
Task
├── id
├── type
├── target
├── dependencies
├── priority
├── timeout
├── retry_policy
├── resource_class
├── scope
└── state
```

Task states:

```text
PENDING
READY
RUNNING
COMPLETED
FAILED
TIMEOUT
CANCELLED
SKIPPED
```

---

# 10. Scheduler

Implement a dependency-aware scheduler.

Do NOT simply execute every tool simultaneously.

Example:

```text
DNS
 ↓
IP discovery
 ↓
Nmap
 ↓
Service classification
 ↓
HTTP discovery
 ↓
Web enumeration
 ↓
Security assessment
```

Tasks with no dependencies may run concurrently.

Tasks with dependencies must wait until required observations exist.

Use a DAG/task graph.

---

# 11. Concurrency

Implement configurable concurrency.

Example:

```yaml
concurrency:
  global: 20
  dns: 8
  network: 4
  http: 10
  discovery: 6
  vulnerability: 2
```

The scheduler must enforce both:

* global concurrency
* resource-specific concurrency

Do not create an unbounded number of processes.

Add:

* timeout
* retry
* cancellation
* graceful shutdown

---

# 12. Scope Guard

Scope enforcement is mandatory.

Before execution, every target must pass scope validation.

Support:

```yaml
scope:
  allowed_domains:
    - example.com
    - "*.example.com"

  allowed_ips:
    - "192.0.2.0/24"

  excluded_domains:
    - payment.example.com

  excluded_ips:
    - "192.0.2.50"
```

Any target outside scope must be rejected before tool execution.

Redirects and newly discovered assets must also be checked against scope before being scheduled.

The scope guard must operate centrally, not independently inside each adapter.

---

# 13. Discovery Pipeline

Implement discovery in stages.

## Stage 1 — Target normalization

Normalize:

```text
example.com
https://example.com
https://example.com/
EXAMPLE.COM
```

into canonical target representations.

## Stage 2 — DNS

Use:

* whois
* dig
* host
* nslookup

Collect:

* A
* AAAA
* MX
* NS
* TXT
* SOA
* CNAME
* relevant registrar/ASN information where available

## Stage 3 — Network

Use:

* ping
* nmap

Collect:

* IPs
* open ports
* protocols
* services
* versions where available

## Stage 4 — HTTP

For HTTP/HTTPS services:

* curl
* wget
* openssl

Collect:

* status code
* redirect chain
* headers
* cookies
* TLS certificate
* protocol
* certificate validity
* security headers
* server metadata

---

# 14. Adaptive Web Discovery

Only launch web-specific tasks when HTTP/HTTPS services are actually discovered.

Example:

```text
443/tcp → HTTPS
        ↓
curl
        ↓
TLS
        ↓
web discovery
```

Do not blindly run HTTP tools against every discovered port.

HTTP discovery should include a baseline response.

This is required for false-positive reduction.

For example:

```text
/random-nonexistent-path
```

may return HTTP 200.

Directory discovery must compare candidate responses against this baseline.

---

# 15. Directory and Endpoint Discovery

Support:

* gobuster
* ffuf
* dirb

Normalize all output into one endpoint model.

Example:

```json
{
  "url": "https://example.com/admin/",
  "status_code": 403,
  "content_length": 412,
  "source": "ffuf"
}
```

Deduplicate identical endpoints discovered by multiple tools.

Preserve source attribution.

Example:

```text
/admin
Sources:
- gobuster
- ffuf
```

---

# 16. False Positive Reduction

This is a core feature.

Do NOT treat every tool output as a confirmed vulnerability.

Implement:

```text
Detection
↓
Validation
↓
Evidence enrichment
↓
Confidence
↓
Finding
```

Every finding must have a confidence value.

Suggested model:

```text
0.00 - 0.29 = LOW confidence
0.30 - 0.59 = MEDIUM confidence
0.60 - 0.84 = HIGH confidence
0.85 - 1.00 = VERY HIGH confidence
```

These thresholds may be configurable.

Confidence must be independent from severity.

Example:

```text
CVSS 9.1
Confidence 0.42
```

is possible.

Do not automatically present such a result as a confirmed critical vulnerability.

---

# 17. Evidence-Based Detection

Where possible, detections should have multiple validation signals.

Example: exposed sensitive file.

Weak detection:

```text
HTTP 200
```

Better detection:

```text
HTTP 200
+
expected content type
+
expected file signature
+
expected content structure
```

The more independent evidence exists, the higher the confidence.

Avoid relying solely on:

* HTTP status
* banner
* version string
* tool assertion

unless no stronger evidence is possible.

---

# 18. Finding Deduplication

Multiple tools may report the same issue.

Example:

```text
curl     → missing CSP
nikto    → missing CSP
custom   → missing CSP
```

Merge into one finding.

Finding identity should be based on normalized attributes such as:

```text
asset
endpoint
finding_type
parameter
classification
```

Do not simply deduplicate using title strings.

Preserve all contributing sources.

---

# 19. Finding Classification

Every finding should attempt to include:

```text
Finding ID
Title
Description
Asset
Affected endpoint
Severity
Confidence
CWE
CVSS
Evidence
Impact
Remediation
References
Sources
```

Classification should be deterministic.

Do not create arbitrary severity solely from tool output.

---

# 20. CVSS

Support:

* CVSS 3.1
* CVSS 4.0

Store:

```text
cvss_version
vector
base_score
severity
scoring_rationale
```

Do not invent missing metrics.

If the evidence is insufficient:

```text
CVSS status: REQUIRES_REVIEW
```

is preferable to generating a false precision score.

Separate:

```text
Severity
```

from:

```text
Confidence
```

and from:

```text
CVSS score
```

---

# 21. Vulnerability Tool Integration

Integrate:

* nikto
* sqlmap

through adapters.

Their results must still pass through:

```text
raw output
↓
parser
↓
normalized observation
↓
validation/correlation
↓
finding
↓
confidence
↓
risk
```

Do not directly convert tool output into report findings.

For active vulnerability testing, implement explicit configuration modes.

Example:

```text
--safe
--passive
--active
```

The default should favor controlled, non-destructive behavior.

---

# 22. CLI Design

Primary command:

```bash
reconx scan --target example.com
```

Support:

```bash
reconx scan \
  --target example.com \
  --profile full
```

Modules:

```bash
reconx scan \
  --target example.com \
  --modules dns,http,tls
```

Support:

```text
--target
--targets-file
--profile
--modules
--exclude
--threads
--timeout
--connect-timeout
--rate-limit
--wordlist
--ports
--extensions
--depth
--follow-redirects
--safe
--passive
--active
--resume
--output
--format
--min-severity
--min-confidence
--cvss-version
--verbose
--quiet
--debug
--no-color
```

Do not expose every internal implementation detail as a CLI flag.

Use profiles for common workflows.

---

# 23. Profiles

Implement:

```text
profiles/
├── quick.yaml
├── passive.yaml
├── network.yaml
├── web.yaml
└── full.yaml
```

Example:

```yaml
name: web

modules:
  dns: true
  network: false
  http: true
  tls: true
  directory: true
  nikto: true
  sqlmap: false

concurrency:
  global: 12
```

CLI flags must override profile values.

Priority:

```text
defaults
↓
profile
↓
CLI arguments
```

---

# 24. Persistent Session

Use SQLite.

Store:

```text
scan
target
task
command execution
asset
observation
evidence
finding
risk assessment
```

Every scan must have a unique ID.

Example:

```text
scan-20261005-094211-a82f
```

Support:

```bash
reconx scan --resume <scan-id>
```

Completed tasks must not be rerun unnecessarily.

---

# 25. Resume Logic

When resuming:

```text
COMPLETED → skip
FAILED → retry according to policy
TIMEOUT → retry
CANCELLED → retry
RUNNING → recover safely
PENDING → execute
```

Never assume an interrupted process completed successfully.

---

# 26. Reporting

Implement four formats:

```text
JSON
Markdown
HTML
PDF
```

JSON is the canonical machine-readable report.

HTML should be the primary human-readable technical report.

PDF is generated from the same normalized report model.

Do NOT implement separate business logic for every output format.

Use:

```text
ReportModel
↓
JSON renderer
Markdown renderer
HTML renderer
PDF renderer
```

---

# 27. Report Structure

## Executive Summary

Include:

* target
* scan date
* duration
* scope
* total assets
* total findings
* severity distribution

## Attack Surface

Include:

* domains
* IP addresses
* ports
* services
* URLs
* endpoints
* technologies

## Findings

For each finding:

```text
ID
Title
Severity
Confidence
CVSS
Affected Asset
Description
Impact
Evidence
Remediation
References
```

## Appendix

Include:

* tool versions
* scan configuration
* executed modules
* excluded modules
* errors
* incomplete tasks

---

# 28. Secret Redaction

Raw scan data may contain:

* API keys
* passwords
* tokens
* cookies
* credentials

Reports must redact sensitive values by default.

Examples:

```text
password=********
Authorization: Bearer ****************
AWS_SECRET_ACCESS_KEY=****************
```

Do not intentionally print secrets into terminal output.

Allow raw evidence storage only when explicitly configured.

---

# 29. Logging

Implement structured logging.

Levels:

```text
DEBUG
INFO
WARNING
ERROR
```

Terminal output should distinguish:

```text
[INFO]
[SCAN]
[TASK]
[FOUND]
[WARN]
[ERROR]
```

Do not use logging as the primary data storage mechanism.

---

# 30. Error Handling

A failed tool must not terminate the entire scan.

Example:

```text
Nmap failed
↓
record task failure
↓
log error
↓
continue independent tasks
```

Only dependent tasks should be skipped when their prerequisites are unavailable.

Example:

```text
Nmap failed
↓
network-dependent tasks may be skipped
↓
DNS-independent tasks continue
```

---

# 31. Tool Availability

Before scanning, provide:

```bash
reconx tools check
```

Expected output:

```text
Tool       Status    Version
--------------------------------
whois      OK        ...
dig        OK        ...
nmap       OK        ...
curl       OK        ...
ffuf       OK        ...
nikto      OK        ...
sqlmap     OK        ...
```

If a tool is unavailable, the framework should clearly indicate:

```text
AVAILABLE
MISSING
BROKEN
UNKNOWN
```

Do not silently skip missing tools.

---

# 32. Testing Strategy

Testing is mandatory.

## Unit tests

Test:

* target normalization
* scope validation
* argument generation
* parser behavior
* deduplication
* confidence calculation
* CVSS calculation
* configuration precedence

## Parser fixtures

Store representative tool outputs in:

```text
tests/fixtures/
```

Do not depend on real network targets for parser unit tests.

## Integration tests

Test:

```text
adapter
→ runner
→ parser
→ observation
```

## End-to-end tests

Use intentionally controlled local test targets.

Examples:

* local HTTP server
* mock DNS responses
* fixture outputs
* local vulnerable test application

Do not make production internet targets part of automated tests.

---

# 33. Security Requirements for the Framework

The framework itself must be secure.

Requirements:

1. No unnecessary `shell=True`.
2. Validate all target-derived input.
3. Enforce scope centrally.
4. Prevent command injection.
5. Limit subprocess creation.
6. Implement timeouts.
7. Implement cancellation.
8. Prevent unbounded output buffering.
9. Redact secrets.
10. Avoid writing credentials into logs.
11. Restrict report file permissions where appropriate.
12. Never automatically expand scope based on discovered assets.
13. Require explicit configuration for aggressive/active modules.

---

# 34. Performance Requirements

The system must optimize for:

```text
high throughput
low process overhead
controlled concurrency
minimal redundant scanning
minimal duplicate requests
```

Implement:

* task deduplication
* result caching where safe
* concurrency limits
* connection reuse where applicable
* dependency-aware execution
* early filtering
* baseline response caching
* persistent scan state

Do not optimize by simply increasing thread count.

Measure:

```text
tasks/sec
targets/sec
requests/sec
average task duration
tool execution time
parser time
scheduler overhead
```

---

# 35. Observability

Each task should expose timing:

```text
queued_at
started_at
finished_at
duration
```

This allows performance profiling.

At scan completion:

```text
SCAN PERFORMANCE
----------------
Total duration: 137.4s
Tasks:          84
Completed:      79
Failed:          3
Skipped:         2

Tool execution:
nmap:            21.2s
ffuf:            38.7s
gobuster:        31.1s
nikto:           18.4s
```

---

# 36. Implementation Phases

Implement strictly in phases.

## Phase 0 — Repository bootstrap

Create:

* pyproject.toml
* package structure
* CLI entrypoint
* logging
* configuration
* test framework

Acceptance:

```bash
reconx --help
reconx --version
```

must work.

---

## Phase 1 — Core execution engine

Implement:

* CommandRunner
* Task
* TaskState
* Scheduler
* cancellation
* timeout
* retry
* structured result

Acceptance:

A dummy command can be scheduled, executed, timed out, retried, and recorded.

---

## Phase 2 — Scope engine

Implement:

* domain matching
* wildcard matching
* IP/CIDR matching
* exclusions
* redirect validation
* discovered asset validation

Acceptance:

An out-of-scope target can never reach CommandRunner.

---

## Phase 3 — Data models + SQLite

Implement:

* scan
* task
* asset
* observation
* evidence
* finding

Acceptance:

A complete scan state can be persisted and reloaded.

---

## Phase 4 — DNS adapters

Implement:

* whois
* dig
* host
* nslookup

Normalize results.

Acceptance:

All DNS tools produce the same normalized data structures.

---

## Phase 5 — Network adapters

Implement:

* ping
* nmap
* openssl

Create service/port models.

Acceptance:

Nmap output can generate downstream HTTP tasks only when appropriate services are detected.

---

## Phase 6 — HTTP engine

Implement:

* curl
* wget
* TLS parsing
* HTTP response model
* header analyzer
* redirect handling
* baseline response

Acceptance:

The engine can accurately distinguish a real discovered endpoint from a wildcard 200 response.

---

## Phase 7 — Web enumeration

Implement:

* gobuster
* ffuf
* dirb

Normalize and deduplicate endpoints.

Acceptance:

The same endpoint found by multiple tools becomes one normalized observation with multiple sources.

---

## Phase 8 — Vulnerability adapters

Implement:

* nikto
* sqlmap

Add safe/passive/active execution modes.

Acceptance:

Tool findings do not directly become final vulnerabilities; they pass through validation/correlation.

---

## Phase 9 — Finding intelligence

Implement:

* correlation
* deduplication
* classification
* confidence scoring
* evidence enrichment

Acceptance:

Multiple observations can produce a single high-confidence finding.

---

## Phase 10 — Risk engine

Implement:

* CVSS 3.1
* CVSS 4.0
* severity mapping
* scoring rationale
* manual review status

Acceptance:

Every risk score has a reproducible vector/rationale or is explicitly marked as requiring review.

---

## Phase 11 — Reporting

Implement:

* JSON
* Markdown
* HTML
* PDF

Acceptance:

All formats originate from the same ReportModel.

---

## Phase 12 — Profiles and resume

Implement:

* profiles
* CLI overrides
* resume
* scan sessions

Acceptance:

An interrupted scan can continue without unnecessarily repeating completed tasks.

---

## Phase 13 — Performance optimization

Measure first.

Optimize:

* scheduler
* subprocess handling
* parsing
* deduplication
* database operations
* concurrency

Do not perform premature optimization.

---

## Phase 14 — Production hardening

Add:

* comprehensive tests
* security checks
* documentation
* tool diagnostics
* graceful shutdown
* error recovery
* report validation
* packaging

---

# 37. Definition of Done

The project is considered production-ready only when:

* all adapters use the common execution abstraction
* scope enforcement is centralized
* task dependencies work correctly
* concurrency is bounded
* failed tools do not crash the entire scan
* observations are normalized
* duplicate findings are merged
* confidence and severity are separate
* CVSS is reproducible
* evidence is preserved
* reports are generated from a canonical data model
* scans can resume
* secrets are redacted
* parser tests exist for every supported tool
* end-to-end tests run against controlled targets
* missing tools are detected clearly
* CLI documentation exists
* architecture documentation exists
* no unsafe shell interpolation exists

---

# 38. Important Engineering Rule

Do NOT implement the entire system in one pass.

Implement one vertical slice first:

```text
CLI
↓
Target
↓
Scope
↓
Task
↓
CommandRunner
↓
One adapter
↓
Parser
↓
Observation
↓
SQLite
↓
JSON report
```

Use `dig` or `ping` as the first real adapter.

Once that vertical slice works end-to-end, generalize the architecture for the remaining tools.

This prevents building a large abstraction layer without proving that the execution model works.

---

# 39. Recommended First Milestone

The first milestone should produce:

```bash
reconx scan --target example.com --modules dns
```

with:

```text
ReconX
│
├── target normalization
├── scope validation
├── task creation
├── scheduler
├── dig adapter
├── command runner
├── parser
├── observation model
├── SQLite persistence
└── JSON report
```

Example result:

```text
Scan completed.

Target: example.com

DNS:
  A      93.x.x.x
  AAAA   ...
  MX     ...
  NS     ...
  TXT    ...

Tasks:
  completed: 4
  failed:    0

Report:
  report.json
```

Do not implement Nmap, Gobuster, FFUF, Nikto, or SQLMap before this first vertical slice is stable.

---

# 40. Agent Operating Instructions

When implementing this project:

1. Inspect the existing repository before modifying anything.
2. Do not overwrite existing architecture without understanding it.
3. Implement incrementally.
4. After each phase, run tests.
5. Do not create placeholder implementations that silently return fake data.
6. Do not claim a feature works unless it has a test.
7. Keep external-tool execution isolated behind adapters.
8. Keep security logic independent from presentation logic.
9. Prefer typed models.
10. Keep functions small and testable.
11. Document architectural decisions.
12. Preserve backwards compatibility for the CLI where practical.
13. Never silently ignore tool failures.
14. Never silently expand scan scope.
15. Never convert weak evidence into a confirmed vulnerability.
16. Never expose secrets in reports by default.
17. Never use arbitrary concurrency without resource limits.
18. Never use shell interpolation for user-controlled target values.

When a design decision is ambiguous, prioritize:

```text
accuracy
>
scope safety
>
evidence quality
>
reproducibility
>
performance
>
feature breadth
```

The framework should ultimately behave like a security assessment engine, not like a shell-script launcher.

# Universal Phase Execution Protocol

This protocol defines how the agent must interpret and execute all phase-related requests.

The user will normally provide short commands such as:

```text
implementasikan phase 4
review phase 4
Fix Phase 4 Review Findings
```

The agent MUST derive the requested phase number directly from the user's command.

The agent MUST NOT require the user to provide a long implementation prompt for every phase.

---

# 1. Phase Identification

When the user specifies a phase number, that phase number is the explicit requested phase.

Examples:

```text
implementasikan phase 4
```

means:

```text
REQUEST = IMPLEMENT
PHASE = 4
```

and:

```text
review phase 4
```

means:

```text
REQUEST = REVIEW
PHASE = 4
```

and:

```text
Fix Phase 4 Review Findings
```

means:

```text
REQUEST = FIX REVIEW FINDINGS
PHASE = 4
```

The agent MUST use the explicitly requested phase number.

Do not substitute another phase merely because `PROGRESS.md` reports a different phase.

---

# 2. Determine the Actual Project State

Before executing any phase-related request, the agent MUST determine the actual repository state.

Inspect, in this order:

1. `implementation.md`
2. `PROGRESS.md`
3. Git status
4. Recent Git history
5. Relevant source files
6. Relevant tests
7. Relevant configuration

The agent must compare the requested phase against the actual implementation state.

The agent MUST NOT rely on previous conversational memory.

The repository is the source of truth.

---

# 3. PROGRESS.md Is a State Hint, Not Absolute Truth

`PROGRESS.md` is used to understand project progress, but its contents must be verified against the repository.

For example, if:

```text
PROGRESS.md
Phase 4: COMPLETE
```

but the source code or tests show that Phase 4 is incomplete, the agent MUST NOT assume Phase 4 is complete.

Likewise, if:

```text
PROGRESS.md
Phase 4: IN_PROGRESS
```

but the implementation and acceptance criteria are already satisfied, the agent should identify that discrepancy.

Never blindly trust progress metadata.

---

# 4. Phase Consistency Check

Before implementation or review, determine:

```text
Requested Phase
Current Recorded Phase
Actual Repository State
Phase Acceptance Criteria
```

If these are consistent, proceed normally.

If they are inconsistent, do NOT silently guess.

The agent should report the inconsistency and determine whether the requested operation can safely proceed.

Examples of inconsistencies:

```text
Requested: Phase 4
PROGRESS.md: Phase 3 IN_PROGRESS
Repository: Phase 3 appears complete
```

or:

```text
Requested: Phase 4
PROGRESS.md: Phase 4 COMPLETE
Repository: Phase 4 acceptance criteria not satisfied
```

The agent should resolve the state from actual evidence before proceeding.

---

# 5. Implementation Command

When the user says:

```text
implementasikan phase N
```

interpret it as:

> Implement Phase N only.

The agent MUST:

1. Read the Phase N requirements in `implementation.md`.
2. Read the Phase N acceptance criteria.
3. Inspect the current implementation relevant to Phase N.
4. Inspect the current `PROGRESS.md`.
5. Inspect Git state.
6. Determine what Phase N work already exists.
7. Implement only the missing or incomplete Phase N functionality.
8. Avoid reimplementing working functionality.
9. Add/update relevant tests.
10. Run validation.
11. Update `PROGRESS.md`.
12. Report the result.
13. STOP.

---

# 6. Existing Partial Implementation

A phase may already be partially implemented.

The agent MUST NOT assume that a phase must start from zero.

Before modifying code, determine:

```text
Already implemented
Partially implemented
Missing
Incorrect
Untested
```

Only implement what is necessary.

Do not overwrite working code merely to produce a cleaner implementation.

Do not restart a phase unless the current implementation is demonstrably unusable or fundamentally incompatible with the requirements.

---

# 7. Implementation Acceptance Gate

Before marking Phase N as complete, verify:

```text
[ ] All Phase N requirements implemented
[ ] Phase N acceptance criteria satisfied
[ ] Relevant tests implemented
[ ] Relevant tests passing
[ ] Regression tests passing
[ ] Error handling verified
[ ] Security constraints preserved
[ ] Scope enforcement preserved
[ ] Performance constraints preserved
[ ] No unnecessary dependencies
[ ] No unnecessary abstractions
[ ] No fake/stub implementation
[ ] No unrelated changes
[ ] Implementation actually connected to the execution path
```

If any required criterion fails, Phase N MUST NOT be marked `COMPLETE`.

---

# 8. Updating PROGRESS.md After Implementation

After meaningful implementation progress, update `PROGRESS.md`.

For an active phase, use:

```text
Status: IN_PROGRESS
```

For a phase that has passed all acceptance criteria:

```text
Status: COMPLETE
```

The progress entry should contain:

```markdown
## Phase N

Status: COMPLETE

### Completed
- ...

### Tests
- ...

### Validation
- ...

### Known Issues
- None

### Next Phase
- Phase N+1

### Last Updated
- YYYY-MM-DD
```

Do not mark a phase complete merely because the code was written.

Completion requires verification.

---

# 9. Review Command

When the user says:

```text
review phase N
```

interpret it as:

> Perform a strict engineering review of Phase N.

The agent MUST:

1. Read Phase N requirements.
2. Read Phase N acceptance criteria.
3. Inspect the Phase N implementation.
4. Inspect relevant tests.
5. Inspect `PROGRESS.md`.
6. Inspect relevant Git changes.
7. Run appropriate tests.
8. Check for implementation defects.
9. Check for AI-slop.
10. Check security boundaries.
11. Check scope enforcement.
12. Check performance.
13. Check unnecessary complexity.
14. Check for incomplete integration.

The review MUST NOT implement new features.

---

# 10. Review Scope

The Phase N review must check at least:

### Correctness

- Does the implementation satisfy the specification?
- Does the actual execution path use the implementation?
- Are edge cases handled?
- Are failures handled correctly?

### Architecture

- Does it follow the architecture in `implementation.md`?
- Are abstractions justified?
- Is responsibility placed in the correct component?
- Is there unnecessary coupling?

### Anti-AI-Slop

Look specifically for:

- Unused functions
- Unused classes
- Unused imports
- Generic helper layers
- Excessive wrappers
- Duplicate logic
- Dead code
- Placeholder implementations
- Fake data
- Hardcoded behavior
- Speculative features
- Excessive comments
- Unnecessary configuration
- Unnecessary dependencies
- Unrelated refactoring

### Performance

Check for:

- Unnecessary subprocesses
- Duplicate tool execution
- Unnecessary network requests
- Unbounded concurrency
- Excessive memory usage
- Excessive file I/O
- Excessive database operations
- Repeated parsing
- Redundant work

### Security

Check for:

- Scope bypass
- Unsafe subprocess execution
- Shell injection risk
- Missing input validation
- Secret leakage
- Unsafe active scanning
- Incorrect handling of discovered assets

### Testing

Check:

- Happy path
- Failure path
- Invalid input
- Timeout
- Tool failure
- Empty output
- Boundary conditions
- Regression behavior

---

# 11. Review Output

After reviewing Phase N, report:

```text
Phase:
Review Status:

Requirements:
PASS / FAIL

Acceptance Criteria:
PASS / FAIL

Critical Findings:
- ...

Major Findings:
- ...

Minor Findings:
- ...

AI-Slop / Code Quality:
- ...

Performance:
- ...

Security:
- ...

Testing:
- ...

Recommendation:
READY FOR NEXT PHASE
or
REQUIRES FIXES
```

Do not implement fixes during the review unless the user explicitly asks for fixes.

STOP after the review.

---

# 12. Fix Review Findings Command

When the user says:

```text
Fix Phase N Review Findings
```

interpret it as:

> Fix only the confirmed findings identified during the Phase N review.

The agent MUST:

1. Read the previous Phase N review findings.
2. Read Phase N requirements.
3. Inspect the current implementation.
4. Fix only confirmed Phase N issues.
5. Avoid unrelated refactoring.
6. Avoid implementing Phase N+1.
7. Add/update tests for corrected behavior.
8. Run relevant tests.
9. Run regression tests.
10. Verify that the review findings are resolved.
11. Update `PROGRESS.md`.
12. Report the result.
13. STOP.

---

# 13. Fix Scope

During a review-fix operation, the agent MUST NOT:

- Add new features
- Implement future phases
- Perform unrelated cleanup
- Rewrite working components
- Add speculative abstractions
- Add unnecessary dependencies
- Change unrelated APIs
- Modify unrelated configuration

The fix should address the root cause of the identified finding with the smallest reasonable change.

---

# 14. Automatic Phase State Detection

The agent should automatically derive the following state:

```text
Requested Phase
        ↓
PROGRESS.md
        ↓
Git state
        ↓
Source implementation
        ↓
Tests
        ↓
Acceptance criteria
        ↓
Actual Phase State
```

Possible states:

```text
NOT_STARTED
IN_PROGRESS
BLOCKED
REVIEW_REQUIRED
COMPLETE
```

The agent should use the most conservative state supported by evidence.

For example:

If implementation exists but tests fail:

```text
IN_PROGRESS
```

not:

```text
COMPLETE
```

If implementation passes tests but acceptance criteria have not been verified:

```text
REVIEW_REQUIRED
```

not:

```text
COMPLETE
```

---

# 15. Automatic Resume

If the IDE, terminal, agent, or operating system was restarted, the agent MUST be able to resume without relying on previous conversation history.

When the user gives:

```text
implementasikan phase N
```

the agent should automatically determine whether Phase N is:

- Not started
- Partially implemented
- Previously implemented but unverified
- Complete
- Complete but requiring review
- Previously reviewed with unresolved findings

The agent should continue from the actual repository state.

Do not restart completed work.

Do not assume that an incomplete progress entry means the code is incomplete.

Verify the repository.

---

# 16. Phase Boundary Enforcement

The agent MUST enforce strict phase boundaries.

If the requested operation is:

```text
implementasikan phase 4
```

then:

```text
Phase 4 = IN SCOPE
Phase 5+ = OUT OF SCOPE
```

If Phase 4 requires a small interface needed by Phase 5, the interface may be created only if Phase 4 genuinely requires it.

Do not implement Phase 5 behavior.

The same rule applies to every phase.

---

# 17. User Command Interface

The following commands are valid:

### Implementation

```text
implementasikan phase N
```

### Review

```text
review phase N
```

### Fix

```text
Fix Phase N Review Findings
```

### Resume / Inspect

```text
resume project
```

or:

```text
check project status
```

The agent should understand these commands without requiring the user to provide additional implementation instructions.

---

# 18. Resume Project Command

When the user says:

```text
resume project
```

or:

```text
check project status
```

the agent MUST NOT modify code.

It should inspect:

- `implementation.md`
- `PROGRESS.md`
- Git status
- Recent Git commits
- Current source tree
- Relevant tests

Then report:

```text
Project Status

Current Phase:
Phase Status:

Completed Phases:
- ...

Current Work:
- ...

Remaining Work:
- ...

Tests:
- ...

Git:
- ...

Known Issues:
- ...

Recommended Next Command:
implementasikan phase N
```

Do not implement anything during this operation.

---

# 19. Command Interpretation Priority

When determining what to do, use this priority:

```text
1. Explicit user command
2. implementation.md requirements
3. Phase acceptance criteria
4. Actual repository state
5. PROGRESS.md
6. Git history
7. Previous conversation context
```

Previous conversational context MUST NOT override the actual repository state.

If the user explicitly requests Phase N, do not silently switch to another phase.

---

# 20. Final Rule

The user should only need to specify:

```text
implementasikan phase N
review phase N
Fix Phase N Review Findings
```

The agent is responsible for determining:

- What has already been implemented
- What remains
- What must be changed
- What tests are required
- Whether the phase is actually complete
- What the current project state is
- Where implementation should resume

The user MUST NOT be required to manually rewrite implementation prompts for every phase.

# Security Assessment Scope and Tool Integration Policy

This project is an authorized security assessment and VAPT orchestration framework.

Its purpose is to coordinate existing security assessment tools against explicitly authorized targets, collect their results, normalize evidence, correlate observations, assess risk, and generate reproducible reports.

The project does NOT attempt to create new exploitation capabilities.

---

## 1. Authorized Assessment Context

All active security testing performed by this project is intended for:

- Systems owned by the operator
- Systems for which the operator has explicit authorization
- Controlled laboratory environments
- Local test environments
- Purpose-built vulnerable applications
- Authorized penetration-testing engagements

The configured scope is a mandatory security boundary.

The agent must never assume that an arbitrary public target is authorized.

---

## 2. Existing Security Tools

Some phases integrate existing security assessment utilities.

Examples include:

- `nmap`
- `nikto`
- `gobuster`
- `ffuf`
- `dirb`
- `sqlmap`

These tools are treated as external executables.

The project does not reimplement their exploitation or vulnerability-testing engines.

The framework is responsible for:

- Scope validation
- Task scheduling
- Safe argument construction
- Execution control
- Timeouts
- Concurrency limits
- Output capture
- Parsing
- Evidence normalization
- Finding correlation
- Deduplication
- Confidence assessment
- Risk assessment
- Reporting

The underlying security tool remains responsible for its own specialized security-testing functionality.

---

## 3. No New Exploitation Engine

The agent MUST NOT implement a new exploitation engine.

Do not implement custom:

- SQL injection exploit engines
- Payload-generation frameworks
- Credential attack engines
- Shell exploitation frameworks
- Remote code execution engines
- Malware functionality
- Persistence mechanisms
- Evasion mechanisms
- Credential theft mechanisms

When an existing authorized security-testing utility is part of the project specification, the framework may provide a controlled adapter around that existing executable.

---

## 4. Vulnerability Tool Adapters

A vulnerability adapter is an orchestration component.

Its responsibility is to translate an authorized task into a controlled invocation of an existing assessment utility and convert the result into the project's internal data model.

Conceptually:

```text
Authorized Target
       ↓
Scope Validation
       ↓
Task Definition
       ↓
Tool Adapter
       ↓
Controlled External Execution
       ↓
Raw Result
       ↓
Parser
       ↓
Observation
       ↓
Evidence
       ↓
Finding / Risk Assessment
```

The adapter MUST NOT bypass the project's scope engine.

The adapter MUST NOT independently decide that a target is authorized.

---

## 5. SQL Injection Tool Integration

If `sqlmap` is included in the project specification, the implementation scope is limited to controlled integration with the existing executable.

The framework should focus on:

- Scope enforcement
- Target validation
- Explicit user-selected assessment mode
- Controlled command construction
- Timeout handling
- Process cancellation
- Output capture
- Exit-code handling
- Result parsing
- Evidence storage
- Finding normalization
- Reporting

Do not implement a replacement for `sqlmap`.

Do not develop a custom SQL injection exploitation engine.

Do not add autonomous target discovery outside the configured scope.

Do not automatically expand testing from one authorized target to unrelated discovered targets.

---

## 6. Active Testing Requires Explicit Authorization

Passive discovery and active vulnerability assessment must remain distinguishable.

Active vulnerability-testing tasks must only execute when:

1. The target is inside the configured scope.
2. The relevant task/profile explicitly enables active testing.
3. Required execution policy allows the operation.
4. The task has passed the scheduler and scope checks.

The framework must fail closed when scope authorization cannot be established.

---

## 7. Tool Adapter Safety Boundary

Every active tool adapter should receive an already validated target/task context.

Conceptually:

```python
validated_task = scope_guard.validate(task)

if not validated_task.allowed:
    skip_task()
```

The adapter must not accept arbitrary target strings and execute them without validation.

Tool arguments must be constructed as argument arrays rather than unsafe shell strings.

---

## 8. No Autonomous Exploitation

The framework is an orchestration and assessment system, not an autonomous attacker.

It must not:

- Discover arbitrary external targets and attack them
- Expand scope automatically
- Chain vulnerabilities into arbitrary compromise
- Maintain persistence
- Attempt lateral movement
- Exfiltrate credentials or sensitive data
- Execute arbitrary post-exploitation actions

Any vulnerability-testing behavior must remain bounded by the configured assessment scope and execution policy.

---

## 9. Evidence Over Exploitation

The primary output of vulnerability-testing phases is structured evidence.

The system should answer:

```text
What was tested?
Against which authorized target?
Using which tool?
Under which configuration?
What happened?
What evidence was produced?
How confident is the observation?
What security finding does it support?
What is the assessed risk?
```

The objective is not to maximize exploitation capability.

The objective is to produce reliable, reproducible security assessment results.

---

## 10. Agent Interpretation

When implementing a phase involving vulnerability-testing tools, interpret the task as:

> Integrate and orchestrate an existing authorized security assessment utility within the project's scope, execution, evidence, and reporting architecture.

Do NOT interpret it as:

> Develop a new hacking or exploitation tool.

The agent must follow the project's scope controls and security architecture.

---

## 11. Safety Classification of Phase Work

The following activities are considered part of the framework's normal implementation:

- Tool adapter design
- Argument validation
- Scope validation
- Process execution
- Timeout handling
- Cancellation
- Output capture
- Parsing
- Normalization
- Evidence handling
- Finding correlation
- Deduplication
- Confidence scoring
- Risk scoring
- Report generation
- Tests using controlled/local targets
- Integration tests using purpose-built vulnerable applications

Activities outside these boundaries require explicit project specification and must not be introduced speculatively.