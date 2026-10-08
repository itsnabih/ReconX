# ReconX Command-Line Interface (CLI) Manual

This manual provides reference documentation for all CLI subcommands, flags, configuration hierarchies, and exit codes.

---

## 1. Global Syntax

```bash
reconx [-h] [--version] [-v] <subcommand> [options]
```

### Global Options:
- `--version`: Displays the installed ReconX version.
- `-v, --verbose`: Enables verbose debug logging to stderr.
- `-h, --help`: Displays help information for the tool or subcommand.

---

## 2. Subcommands

### 2.1. `reconx scan`
Executes an end-to-end reconnaissance and security assessment against a target.

```bash
reconx scan --target <TARGET> [OPTIONS]
```

#### Arguments:
| Flag | Short | Type | Default | Description |
|---|---|---|---|---|
| `--target` | `-t` | String | *Required* | Target domain, IP, CIDR, or URL. |
| `--profile` | `-p` | String | `quick` | Profile name (`quick`, `passive`, `network`, `web`, `full`) or path to a custom YAML profile. |
| `--mode` | `-m` | String | Profile default | Scan aggressiveness mode: `safe`, `passive`, or `active`. |
| `--output-dir` | `-o` | Path | `reports/` | Directory where JSON, Markdown, HTML, and PDF reports are stored. |
| `--db` | - | Path | `reconx.db` | SQLite database file used for session snapshots and persistence. |
| `--concurrency`| `-c` | Integer | Profile default | Override global concurrent task limit. |

#### Examples:
```bash
# Quick scan with default settings
reconx scan -t example.com

# Passive scan without active port probing
reconx scan -t example.com -p passive

# Full scan with custom concurrency and output folder
reconx scan -t example.com -p full -c 15 -o /tmp/recon_reports/
```

---

### 2.2. `reconx tools check`
Performs environment diagnostics and inspects external binary availability, versions, and execution health.

```bash
reconx tools check [--tools <TOOLS>] [--json]
```

#### Arguments:
- `--tools`: Comma-separated list of specific tools to check (e.g. `nmap,curl,dig`).
- `--json`: Outputs diagnostic report in JSON format for automated tooling.

#### Example:
```bash
reconx tools check
```

---

### 2.3. `reconx session list`
Lists all historical and current scan sessions stored in the SQLite database.

```bash
reconx session list [--db <PATH>]
```

#### Example:
```bash
reconx session list
```

---

### 2.4. `reconx session resume`
Resumes an interrupted or failed scan session without re-executing completed tasks.

```bash
reconx session resume <SCAN_ID> [--db <PATH>]
```

#### Example:
```bash
reconx session resume 7f20beaa-83a1-4328-9844-325b01ce451b
```

---

## 3. Exit Codes

| Exit Code | Meaning | Description |
|---|---|---|
| `0` | Success | Scan or diagnostic command completed normally. |
| `1` | Operational Failure | Tool crash, missing configuration, or internal error. |
| `2` | Security Violation | Target contained injection characters or failed scope validation. |
| `130` | Interrupted | Scan was cancelled by user via SIGINT (Ctrl+C). |
