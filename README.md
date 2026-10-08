# ReconX

> Production-oriented CLI reconnaissance and VAPT orchestration framework.

ReconX is a disciplined, modular security reconnaissance framework designed to orchestrate standard command-line network, DNS, web, and vulnerability assessment tools under strict security guardrails, bounded concurrency, centralized scope enforcement, and reproducible reporting.

---

## Key Highlights

- **Common Execution Layer**: All external binaries run via a centralized, safe `CommandRunner` without `shell=True` or uncontrolled string interpolation.
- **Fail-Closed Scope Enforcement**: Strict domain, wildcard, CIDR, and IP validation. Discovered assets never expand scope automatically.
- **Bounded Multi-Class Concurrency**: Isolated resource semaphores for DNS, network, HTTP, discovery, and vulnerability scanning.
- **Finding Intelligence & Deduplication**: Canonical fingerprinting, heuristic vs confirmed classification, confidence scoring (0.0–1.0), and CVSS 3.1 & 4.0 reproducible risk scoring.
- **Canonical Reporting Engine**: Single `ReportModel` source of truth generating JSON, Markdown, standalone interactive HTML, and pure-Python vector PDF reports with automated secret redaction.
- **Stateful Persistence & Scan Resume**: ACID SQLite transactions per scan; interrupted scans can be resumed without repeating completed work.
- **High Performance**: $O(\log N)$ min-heap priority scheduler, SHA-256 result caching, task deduplication, and SQLite RAM tuning.
- **Production Hardened**: Full tool diagnostics, cooperative graceful shutdown, target input sanitization, and report schema validation.

---

## Installation

```bash
git clone https://github.com/example/ReconX.git
cd ReconX
pip install -e .
```

Requirements:
- Python >= 3.12
- PyYAML >= 6.0

---

## Quick Start

### 1. Check Tool Availability & Diagnostics
Inspect the system PATH and verify installed reconnaissance tools:

```bash
reconx tools check
```

Expected output:
```text
Tool         Status       Version                Path
------------------------------------------------------------------------
curl         AVAILABLE    curl 8.5.0             /usr/bin/curl
dig          AVAILABLE    DiG 9.18.28            /usr/bin/dig
ffuf         AVAILABLE    v2.1.0                 /usr/bin/ffuf
nmap         AVAILABLE    Nmap version 7.94      /usr/bin/nmap
whois        AVAILABLE    version 5.5.21         /usr/bin/whois
------------------------------------------------------------------------
Summary: 14 tools checked (14 AVAILABLE, 0 MISSING, 0 BROKEN)
```

### 2. Execute a Reconnaissance Scan
Run a scan using the default or built-in scan profile:

```bash
reconx scan --target example.com --profile quick
```

Available profiles:
- `quick`: Fast initial assessment with DNS, network, and HTTP probing.
- `passive`: Passive-only OSINT and DNS enumeration without active port probing.
- `network`: Infrastructure mapping and service discovery.
- `web`: Web application footprinting, directory enumeration, and web diagnostics.
- `full`: Complete end-to-end reconnaissance and bounded vulnerability assessment.

### 3. List and Resume Interrupted Sessions
```bash
# List stored sessions
reconx session list

# Resume an interrupted session
reconx session resume <scan_id>
```

---

## Documentation

Detailed architectural and operational manuals are available in `docs/`:

- [Architecture Guide](docs/ARCHITECTURE.md): Technical deep-dive into the 5-tier architecture, pipeline lifecycle, and concurrency model.
- [CLI Reference Manual](docs/CLI.md): Comprehensive manual of command syntax, arguments, profiles, and exit codes.
- [Security Guide](docs/SECURITY.md): Security boundary specification, scope guard, command guardrails, and secret redaction.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
