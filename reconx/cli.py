"""Command Line Interface (CLI) entry point for ReconX.

Strictly adheres to Section 22, 31, and Phase 14 of Implementation.md:
- Subcommands: scan, tools check, session list, session resume
- Signal handling with GracefulShutdownHandler
- Centralized scope enforcement and TargetSecurityValidator
- Section 31 tool diagnostics output
"""

from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import sys
from typing import Sequence

from reconx import __version__
from reconx.config.profiles import ProfileLoader, ScanProfile
from reconx.core.cancellation import CancellationToken
from reconx.core.runner import CommandRunner
from reconx.core.scheduler import Scheduler, SchedulerConfig
from reconx.core.shutdown import GracefulShutdownHandler
from reconx.core.task import Task
from reconx.models.scan import Scan, ScanState, ScanStatus
from reconx.reporting.engine import ReportingEngine
from reconx.reporting.model import ReportModel
from reconx.scope import ScopePolicy, ScopeValidator
from reconx.security.audit import SecurityViolation, TargetSecurityValidator
from reconx.session.manager import ScanSessionManager
from reconx.session.resume import ResumeEngine
from reconx.tools.diagnostics import DiagnosticEngine
from reconx.tools.registry import get_default_registry

logger = logging.getLogger("reconx.cli")


def build_parser() -> argparse.ArgumentParser:
    """Construct command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="reconx",
        description="Production-oriented CLI reconnaissance and VAPT orchestration framework",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"ReconX {__version__}",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose debug logging",
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # 1. tools check
    tools_parser = subparsers.add_parser("tools", help="Tool availability and diagnostics")
    tools_sub = tools_parser.add_subparsers(dest="tools_action")
    check_parser = tools_sub.add_parser("check", help="Inspect installed tools and versions")
    check_parser.add_argument(
        "--tools",
        type=str,
        help="Comma-separated list of specific tool names to check",
    )
    check_parser.add_argument(
        "--json",
        action="store_true",
        help="Output diagnostics in JSON format",
    )

    # 2. scan
    scan_parser = subparsers.add_parser(
        "scan",
        help="Execute reconnaissance scan against target",
        description="Run an orchestrated reconnaissance scan against a target domain, URL, or IP.",
    )
    scan_parser.add_argument(
        "target_pos",
        nargs="?",
        metavar="TARGET",
        help="Target domain, URL, or IP address (can also be passed via -t/--target)",
    )
    scan_parser.add_argument(
        "--target", "-t",
        dest="target_flag",
        type=str,
        help="Primary target domain, URL, or IP address",
    )
    scan_parser.add_argument(
        "--profile", "-p",
        type=str,
        default="quick",
        help="Scan profile name (quick, passive, network, web, full) or YAML path (default: quick)",
    )
    scan_parser.add_argument(
        "--modules",
        type=str,
        help="Comma-separated modules to run (e.g. dns,network,http,tls,directory,nikto,sqlmap)",
    )
    scan_parser.add_argument(
        "--mode", "-m",
        choices=["safe", "passive", "active"],
        help="Override execution mode (safe, passive, active)",
    )
    scan_parser.add_argument(
        "--output-dir", "-o",
        type=str,
        default="reports",
        help="Directory to save generated reports (default: reports)",
    )
    scan_parser.add_argument(
        "--format", "-f",
        type=str,
        default="all",
        help="Report export format: json, markdown, html, pdf, or all (default: all)",
    )
    scan_parser.add_argument(
        "--timeout",
        type=float,
        help="Default task execution timeout in seconds",
    )
    scan_parser.add_argument(
        "--concurrency", "-c",
        type=int,
        help="Override global execution concurrency",
    )
    scan_parser.add_argument(
        "--wordlist", "-w",
        type=str,
        help="Path to custom wordlist for discovery/directory modules",
    )
    scan_parser.add_argument(
        "--db",
        type=str,
        default="reconx.db",
        help="Path to SQLite session database (default: reconx.db)",
    )

    # 3. session list / resume
    session_parser = subparsers.add_parser("session", help="Manage persistent scan sessions")
    session_sub = session_parser.add_subparsers(dest="session_action")

    list_sub = session_sub.add_parser("list", help="List persisted scan sessions")
    list_sub.add_argument(
        "--db",
        type=str,
        default="reconx.db",
        help="Path to SQLite session database",
    )

    resume_sub = session_sub.add_parser("resume", help="Resume an interrupted scan session")
    resume_sub.add_argument(
        "scan_id",
        type=str,
        help="Scan ID of the session to resume",
    )
    resume_sub.add_argument(
        "--db",
        type=str,
        default="reconx.db",
        help="Path to SQLite session database",
    )

    return parser


async def cmd_tools_check(args: argparse.Namespace) -> int:
    """Execute 'reconx tools check' per Section 31."""
    engine = DiagnosticEngine()
    tool_filter = [t.strip() for t in args.tools.split(",")] if getattr(args, "tools", None) else None
    report = await engine.run_diagnostics(tool_names=tool_filter)

    if getattr(args, "json", False):
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.format_table())

    return 0 if report.broken_count == 0 else 1


def cmd_session_list(args: argparse.Namespace) -> int:
    """Execute 'reconx session list'."""
    db_path = getattr(args, "db", "reconx.db")
    manager = ScanSessionManager(db_path)
    sessions = manager.list_sessions()

    if not sessions:
        print("No scan sessions found in database.")
        return 0

    print(f"{'Scan ID':<36} {'Status':<12} {'Target':<24} {'Created At'}")
    print("-" * 90)
    for s in sessions:
        targets_str = ", ".join(s["targets"]) if s["targets"] else "-"
        print(f"{s['id']:<36} {s['status']:<12} {targets_str:<24} {s['created_at']}")
    return 0


async def cmd_session_resume(args: argparse.Namespace) -> int:
    """Execute 'reconx session resume <scan_id>'."""
    db_path = getattr(args, "db", "reconx.db")
    scan_id = args.scan_id
    manager = ScanSessionManager(db_path)

    state = manager.load_session(scan_id)
    if state is None:
        print(f"Error: Session '{scan_id}' not found.", file=sys.stderr)
        return 1

    plan = ResumeEngine.prepare_resume(state)
    print(f"Resuming scan '{scan_id}'...")
    print(f"Total tasks: {plan.total_tasks} | Skipped: {plan.skipped_count} | To run: {plan.executable_count}")

    if not plan.can_resume:
        print("All tasks have already completed. Nothing to resume.")
        return 0

    token = CancellationToken()
    async with GracefulShutdownHandler(token):
        scheduler = ResumeEngine.create_scheduler(plan, cancellation_token=token)
        summary = await scheduler.run()

    final_state = ResumeEngine.merge_execution_summary(state, plan, summary)
    manager.save_session(final_state)
    print(f"Scan resumed successfully. Final status: {final_state.scan.status.value}")
    return 0


async def cmd_scan(args: argparse.Namespace) -> int:
    """Execute 'reconx scan'."""
    raw_target = getattr(args, "target_flag", None) or getattr(args, "target_pos", None)
    if not raw_target:
        print("Error: Target is required. Provide TARGET positional argument or --target/-t flag.", file=sys.stderr)
        return 2

    target = raw_target.strip()

    # 1. Target Security Audit (Section 33)
    try:
        TargetSecurityValidator.validate_target(target)
    except SecurityViolation as exc:
        print(f"Security Error: Invalid or unsafe target: {exc}", file=sys.stderr)
        return 2

    # Parse normalized host, port, URL, and address classification
    port_val: int | None = None
    if target.startswith(("http://", "https://")):
        parsed_url = urlparse(target)
        host_target = parsed_url.hostname or target
        port_val = parsed_url.port
        url_target = target
    elif "/" in target:
        host_target = target
        url_target = f"http://{target}"
    elif ":" in target and not target.startswith("["):
        parts = target.rsplit(":", 1)
        host_target = parts[0]
        try:
            port_val = int(parts[1])
        except ValueError:
            pass
        url_target = f"http://{target}"
    else:
        host_target = target
        url_target = f"http://{target}"

    is_ip = False
    try:
        ipaddress.ip_address(host_target)
        is_ip = True
    except ValueError:
        try:
            ipaddress.ip_network(host_target, strict=False)
            is_ip = True
        except ValueError:
            pass

    # 2. Scope Validation (Section 12 - Fail-Closed)
    if is_ip:
        scope = ScopeValidator(allowed_ips=(host_target,))
        scope_policy = ScopePolicy(allowed_ips=(host_target,))
    else:
        scope = ScopeValidator(allowed_domains=(host_target, f"*.{host_target}"))
        scope_policy = ScopePolicy(allowed_domains=(host_target, f"*.{host_target}"))

    decision = scope.check(target)
    if not decision.allowed:
        print(f"Scope Error: Target '{target}' is rejected by scope policy: {decision.detail}", file=sys.stderr)
        return 2

    # 3. Load Profile & CLI Overrides (Section 23)
    cli_overrides: dict[str, Any] = {}
    if getattr(args, "mode", None):
        cli_overrides["mode"] = args.mode
    if getattr(args, "concurrency", None):
        cli_overrides.setdefault("concurrency", {})["global"] = args.concurrency
    if getattr(args, "timeout", None):
        cli_overrides["timeout"] = args.timeout
    if getattr(args, "wordlist", None):
        cli_overrides.setdefault("wordlists", {})["directory"] = args.wordlist
    if getattr(args, "modules", None):
        mods = [m.strip().lower() for m in args.modules.split(",") if m.strip()]
        cli_overrides["modules"] = {
            "dns": "dns" in mods,
            "network": "network" in mods,
            "http": "http" in mods,
            "tls": "tls" in mods,
            "directory": "directory" in mods,
            "nikto": "nikto" in mods,
            "sqlmap": "sqlmap" in mods,
        }

    try:
        profile = ProfileLoader.load(name_or_path=args.profile, cli_overrides=cli_overrides)
    except ValueError as exc:
        print(f"Configuration Error: {exc}", file=sys.stderr)
        return 1

    print(f"[*] ReconX starting scan against: {target}")
    print(f"[*] Loaded profile: '{profile.name}' (Mode: {profile.mode})")

    # 4. Initialize Scan Session State & Database (Section 24)
    db_path = getattr(args, "db", "reconx.db")
    manager = ScanSessionManager(db_path)
    state = manager.create_session(
        targets=[target],
        scope=scope_policy,
    )
    state.scan.status = ScanStatus.RUNNING
    state.scan.started_at = datetime.now(timezone.utc)
    manager.save_session(state)

    # 5. Build Tasks from Registry and Active Modules
    sched_config = profile.to_scheduler_config()
    token = CancellationToken()
    runner = CommandRunner()
    scheduler = Scheduler(
        runner=runner,
        config=sched_config,
        cancellation_token=token,
        scope=scope,
    )

    registry = get_default_registry()

    # Module: DNS (only relevant for domain names, not raw IPs)
    if profile.is_module_enabled("dns") and not is_ip:
        for tool_name in ("dig", "host", "nslookup", "whois"):
            adapter = registry.get(tool_name)
            if adapter and adapter.check_available():
                task = adapter.create_task(
                    task_id=f"dns_{tool_name}_{host_target}",
                    target=host_target,
                    priority=10,
                )
                task.action = None  # Ensure serializable for SQLite persistence
                scheduler.add_task(task)
                state.tasks.append(task)

    # Module: Network (ping, nmap - uses host_target or port override)
    if profile.is_module_enabled("network"):
        ping_adapter = registry.get("ping")
        if ping_adapter and ping_adapter.check_available():
            task = ping_adapter.create_task(
                task_id=f"net_ping_{host_target}",
                target=host_target,
                priority=20,
            )
            task.action = None
            scheduler.add_task(task)
            state.tasks.append(task)

        nmap_adapter = registry.get("nmap")
        if nmap_adapter and nmap_adapter.check_available():
            nmap_kwargs = {}
            if port_val:
                nmap_kwargs["ports"] = str(port_val)
            task = nmap_adapter.create_task(
                task_id=f"net_nmap_{host_target}",
                target=host_target,
                priority=20,
                **nmap_kwargs,
            )
            task.action = None
            scheduler.add_task(task)
            state.tasks.append(task)

    # Module: HTTP & TLS (uses full URL or web host)
    if profile.is_module_enabled("http"):
        for tool_name in ("curl", "wget"):
            adapter = registry.get(tool_name)
            if adapter and adapter.check_available():
                task = adapter.create_task(
                    task_id=f"http_{tool_name}_{host_target}",
                    target=url_target,
                    priority=30,
                )
                task.action = None
                scheduler.add_task(task)
                state.tasks.append(task)

    if profile.is_module_enabled("tls"):
        adapter = registry.get("openssl")
        if adapter and adapter.check_available():
            task = adapter.create_task(
                task_id=f"tls_openssl_{host_target}",
                target=f"{host_target}:{port_val or 443}",
                priority=35,
            )
            task.action = None
            scheduler.add_task(task)
            state.tasks.append(task)

    # Module: Directory enumeration (requires full web URL)
    if profile.is_module_enabled("directory"):
        for tool_name in ("gobuster", "ffuf", "dirb"):
            adapter = registry.get(tool_name)
            if adapter and adapter.check_available():
                task = adapter.create_task(
                    task_id=f"dir_{tool_name}_{host_target}",
                    target=url_target,
                    priority=40,
                )
                task.action = None
                scheduler.add_task(task)
                state.tasks.append(task)

    # Module: Nikto
    if profile.is_module_enabled("nikto"):
        adapter = registry.get("nikto")
        if adapter and adapter.check_available():
            nikto_kwargs = {}
            if port_val:
                nikto_kwargs["port"] = port_val
            task = adapter.create_task(
                task_id=f"vuln_nikto_{host_target}",
                target=host_target,
                priority=50,
                **nikto_kwargs,
            )
            task.action = None
            scheduler.add_task(task)
            state.tasks.append(task)

    # Module: Sqlmap
    if profile.is_module_enabled("sqlmap"):
        adapter = registry.get("sqlmap")
        if adapter and adapter.check_available():
            task = adapter.create_task(
                task_id=f"vuln_sqlmap_{host_target}",
                target=url_target,
                priority=60,
            )
            task.action = None
            scheduler.add_task(task)
            state.tasks.append(task)

    # Checkpoint initial tasks
    manager.save_session(state)

    # 6. Run Scheduler with Graceful Shutdown Protection (Phase 14)
    async with GracefulShutdownHandler(token, on_shutdown=lambda: manager.save_session(state)):
        summary = await scheduler.run()

    # 7. Merge Results
    state.scan.status = ScanStatus.COMPLETED if summary.failed == 0 else ScanStatus.FAILED
    state.scan.finished_at = summary.finished_at
    manager.save_session(state)

    print(f"[+] Scan completed in {summary.duration:.2f}s "
          f"({summary.completed} completed, {summary.failed} failed, {summary.skipped} skipped)")

    # 8. Generate Reports (Section 26 & 27)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    engine = ReportingEngine()
    report_model = ReportModel.from_scan_state(state)

    fmt_choice = getattr(args, "format", "all").lower()
    paths: dict[str, Path] = {}
    if fmt_choice in ("all", "json"):
        paths["json"] = engine.export(report_model, out_dir / "report.json")
    if fmt_choice in ("all", "markdown", "md"):
        paths["markdown"] = engine.export(report_model, out_dir / "report.md")
    if fmt_choice in ("all", "html"):
        paths["html"] = engine.export(report_model, out_dir / "report.html")
    if fmt_choice in ("all", "pdf"):
        paths["pdf"] = engine.export(report_model, out_dir / "report.pdf")

    print(f"[+] Reports generated in '{out_dir}':")
    for fmt, p in paths.items():
        print(f"    - {fmt.upper()}: {p}")

    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint function."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")
    else:
        logging.basicConfig(level=logging.INFO, format="%(message)s")

    if not args.subcommand:
        parser.print_help()
        return 0

    if args.subcommand == "tools":
        if getattr(args, "tools_action", None) == "check":
            return asyncio.run(cmd_tools_check(args))
        parser.print_help()
        return 0

    if args.subcommand == "session":
        if getattr(args, "session_action", None) == "list":
            return cmd_session_list(args)
        if getattr(args, "session_action", None) == "resume":
            return asyncio.run(cmd_session_resume(args))
        parser.print_help()
        return 0

    if args.subcommand == "scan":
        return asyncio.run(cmd_scan(args))

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
