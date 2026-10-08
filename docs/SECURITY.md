# ReconX Security Guidelines & Guardrails

This document outlines the security architecture, scope policies, guardrails, and non-exploitation principles governing ReconX.

---

## 1. Ethical Assessment Policy

ReconX is designed strictly for authorized reconnaissance, attack surface discovery, and vulnerability posture assessment.

- **No Autonomous Exploitation**: ReconX never executes weaponized exploits, arbitrary command execution, interactive shells, payload tampering, or denial of service attacks.
- **Evidence Over Exploitation**: When potential vulnerabilities are identified, ReconX captures read-only indicators (e.g. response headers, error signatures, heuristics) rather than pursuing destructive post-exploitation.

---

## 2. Hard Security Boundaries

### 2.1. Centralized Scope Guard
- Scope is enforced centrally within the scheduler and adapters.
- New assets discovered during scanning (e.g. subdomains in certificate transparency logs, DNS lookups, or HTTP links) are **never automatically scanned** unless they explicitly match the user-configured scope rules.
- Redirects escaping the allowed scope boundaries are rejected.

### 2.2. Command Injection & Metacharacter Defense
- Target inputs are passed through `TargetSecurityValidator` prior to task generation.
- Shell metacharacters (`;`, `&`, `|`, `` ` ``, `$`, `\n`, `>`, `<`, quotes) are rejected immediately.
- Arguments starting with flags (e.g. `-oG`, `--script`) are rejected to prevent parameter injection.
- Commands are executed strictly as argument vectors via `asyncio.create_subprocess_exec` (`shell=False`).

### 2.3. Destructive Option Guardrails
- Offensive tools such as `sqlmap` and `nmap` are stripped of destructive flags.
- Flags such as `--os-shell`, `--sql-shell`, `--os-cmd`, `--os-pwn`, `--dump-all`, `--tamper` are blocked by `CommandSafetyAuditor`.

---

## 3. Secret Redaction & Data Privacy

- **Redaction Engine**: The built-in `SecretRedactor` automatically sanitizes API tokens, bearer keys, basic authorization headers, AWS credentials, and session cookies from all generated reports.
- **File Permissions**: Database files and report files containing assessment data are created with strict permissions (`0600` / `0640`) to prevent unauthorized local reading.
