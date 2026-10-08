# ReconX Architecture Guide

This document describes the design, component interactions, execution flow, and engineering guarantees of the ReconX orchestration framework.

---

## 1. Architectural Philosophy

ReconX is built upon four non-negotiable principles:
1. **Security-First Execution**: External binaries are untrusted workers. All executions are strictly isolated behind adapters and executed via `asyncio.create_subprocess_exec` using argument vectors (zero `shell=True`).
2. **Fail-Closed Scope**: Any target not explicitly approved in the scope policy is rejected before process spawning. Scope never expands automatically.
3. **Evidence-Based Intelligence**: Raw tool outputs are preserved as immutable evidence. Observations from disparate tools are clustered into canonical findings.
4. **Reproducibility & Resilience**: Scans are persistent in SQLite. Interrupted runs can be recovered and resumed without repeating completed tasks.

---

## 2. 5-Tier System Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│ 1. Interface & Configuration                                │
│    CLI Parser (reconx.cli) • ScanProfile • ProfileLoader    │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ 2. Orchestration & Control                                  │
│    DAG Scheduler • Heap Queue • Bounded Concurrency        │
│    ScopeValidator • CancellationToken • GracefulShutdown    │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ 3. Adapters & Subprocess Execution                          │
│    ToolAdapter Hierarchy • CommandRunner • Caching • Dedup  │
│    (dig, whois, nmap, curl, ffuf, gobuster, nikto, etc.)    │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ 4. Intelligence & Risk Analysis                             │
│    Parsers • Observation Model • Deduplication Engine       │
│    Confidence Scorer • CVSS 3.1 & 4.0 Base Calculators      │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ 5. Persistence & Reporting                                  │
│    SQLite Schema (WAL) • ScanSessionManager • ResumeEngine  │
│    Canonical ReportModel • Secret Redactor • Multi-Renderer │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Core Data Flow & Entity Lifecycle

1. **Target Normalization**: Input target is validated against `TargetSecurityValidator` and checked against `ScopeValidator`.
2. **Task Generation**: Enabled modules in `ScanProfile` instantiate `ToolAdapter` instances which generate schedulable `Task` objects.
3. **DAG Scheduling**:
   - `Scheduler` builds the dependency graph and verifies cycle freedom.
   - Tasks are enqueued in `ready_heap` ordered by priority descending using `heapq`.
   - Dual semaphores (global concurrency + resource-class concurrency) prevent resource exhaustion.
4. **Subprocess Execution**:
   - `CommandRunner` executes commands with timeout enforcement, child lifecycle termination (`SIGTERM` -> `SIGKILL`), and `max_output_bytes` protection.
   - Caching checks (`ResultCache`) bypass execution for identical command/target pairs.
5. **Observation Parsing**:
   - Specialized parsers (`NmapParser`, `CurlParser`, `NiktoParser`, `SqlmapParser`) convert stdout/stderr into typed models.
6. **Persistence**:
   - Task results, discovered assets, observations, and evidence are written to SQLite within an ACID transaction.
7. **Finding Correlation**:
   - `VulnerabilityDeduplicator` computes canonical fingerprints.
   - `ConfidenceScorer` and `CVSSCalculator` score severity and risk.
8. **Canonical Reporting**:
   - A single `ReportModel` is populated and validated via `ReportValidator`.
   - Four renderers (JSON, Markdown, HTML, PDF) produce consistent assessment reports.

---

## 4. Concurrency & Performance Model

- **Multi-Class Concurrency Bounds**:
  - Global default: 20 concurrent tasks.
  - Resource classes:
    - `dns`: 8 concurrent
    - `network`: 4 concurrent
    - `http`: 10 concurrent
    - `discovery`: 6 concurrent
    - `vulnerability`: 2 concurrent
- **Min-Heap Priority Queue**:
  - Tasks with higher priority execute first with $O(\log N)$ push/pop overhead.
- **SQLite Database Optimization**:
  - Write-Ahead Logging (`WAL`) mode.
  - `PRAGMA temp_store = MEMORY` and `PRAGMA cache_size = -32000` (32MB RAM page cache).
