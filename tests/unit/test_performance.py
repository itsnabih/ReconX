"""Unit tests for Performance Profiling, Caching, Deduplication, and Optimization (Phase 13)."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import time
import unittest

from reconx.core.caching import ResultCache, TaskDeduplicator, make_cache_key
from reconx.core.cancellation import CancellationToken
from reconx.core.metrics import PerformanceMetrics, PerformanceProfiler
from reconx.core.runner import CommandResult, CommandRunner
from reconx.core.scheduler import Scheduler, SchedulerConfig
from reconx.core.task import Task, TaskResult, TaskState
from reconx.engine.deduplication import extract_url_path, normalize_parameter, normalize_url
from reconx.parsers.nmap import NmapParser
from reconx.scope.validator import ScopeValidator


class DummyFastRunner(CommandRunner):
    """Deterministic, fast command runner for benchmarking scheduler."""

    def __init__(self, delay: float = 0.001) -> None:
        super().__init__()
        self.delay = delay
        self.call_count = 0
        self.executed_commands: list[list[str]] = []

    async def run(
        self,
        command: list[str],
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout: float | None = None,
        cancellation_token: CancellationToken | None = None,
    ) -> CommandResult:
        self.call_count += 1
        self.executed_commands.append(list(command))
        if self.delay > 0:
            await asyncio.sleep(self.delay)
        return CommandResult(
            command=list(command),
            executable=command[0],
            arguments=list(command[1:]),
            started_at=datetime.now(timezone.utc),
            finished_at=datetime.now(timezone.utc),
            duration=self.delay,
            exit_code=0,
            stdout="dummy output",
            stderr="",
            timed_out=False,
            cancelled=False,
        )


# =============================================================================
# 1. METRICS & PROFILER TESTS
# =============================================================================

class TestPerformanceProfiler:
    """Tests for PerformanceProfiler and PerformanceMetrics conforming to Sections 34 & 35."""

    def test_profiler_lifecycle_and_metrics_calculation(self) -> None:
        profiler = PerformanceProfiler()
        profiler.start()

        with profiler.measure_tool("nmap"):
            time.sleep(0.01)

        with profiler.measure_tool("ffuf"):
            time.sleep(0.015)

        with profiler.measure_parser("nmap"):
            time.sleep(0.005)

        profiler.record_task("t1", 0.01, "COMPLETED", "nmap")
        profiler.record_task("t2", 0.015, "COMPLETED", "ffuf")
        profiler.record_task("t3", 0.005, "FAILED", "nikto")
        profiler.record_cache_hit()
        profiler.record_cache_miss()
        profiler.record_dedup_skip()

        profiler.stop()
        metrics = profiler.get_metrics(total_targets=2)

        assert metrics.total_tasks == 4  # 3 recorded + 1 dedup skipped
        assert metrics.completed_tasks == 2
        assert metrics.failed_tasks == 1
        assert metrics.skipped_tasks == 1
        assert metrics.cache_hits == 1
        assert metrics.cache_misses == 1
        assert metrics.duplicate_tasks_skipped == 1
        assert metrics.tasks_per_second > 0.0
        assert metrics.targets_per_second > 0.0
        assert "nmap" in metrics.tool_execution_seconds
        assert "ffuf" in metrics.tool_execution_seconds
        assert "nmap" in metrics.parser_execution_seconds

    def test_scan_performance_report_format(self) -> None:
        """Verify report matches Section 35 format specification."""
        metrics = PerformanceMetrics(
            total_duration=137.4,
            total_tasks=84,
            completed_tasks=79,
            failed_tasks=3,
            skipped_tasks=2,
            tasks_per_second=0.57,
            targets_per_second=0.01,
            average_task_duration=1.63,
            scheduler_overhead_seconds=4.2,
            tool_execution_seconds={
                "ffuf": 38.7,
                "gobuster": 31.1,
                "nmap": 21.2,
                "nikto": 18.4,
            },
            cache_hits=12,
            duplicate_tasks_skipped=5,
        )

        report = metrics.format_report()
        assert "SCAN PERFORMANCE" in report
        assert "Total duration: 137.4s" in report
        assert "Tasks:          84" in report
        assert "Completed:      79" in report
        assert "Failed:          3" in report
        assert "Skipped:         2" in report
        assert "Tool execution:" in report
        assert "ffuf:            38.7s" in report
        assert "gobuster:        31.1s" in report
        assert "nmap:            21.2s" in report
        assert "nikto:           18.4s" in report


# =============================================================================
# 2. RESULT CACHE & TASK DEDUPLICATION TESTS
# =============================================================================

class TestResultCacheAndDeduplication:
    """Tests for ResultCache and TaskDeduplicator."""

    def test_make_cache_key_deterministic(self) -> None:
        k1 = make_cache_key("nmap", "10.0.0.1", ["-sV", "-p80"])
        k2 = make_cache_key("nmap", "10.0.0.1", ["-sV", "-p80"])
        k3 = make_cache_key("nmap", "10.0.0.2", ["-sV", "-p80"])

        assert k1 == k2
        assert k1 != k3

    def test_result_cache_store_retrieve_ttl(self) -> None:
        cache = ResultCache(default_ttl=0.05)
        cache.set("key1", {"status": 200})

        assert cache.has("key1") is True
        assert cache.get("key1") == {"status": 200}
        assert cache.size() == 1

        # Wait for TTL expiration
        time.sleep(0.06)
        assert cache.has("key1") is False
        assert cache.get("key1") is None
        assert cache.size() == 0

    def test_task_deduplicator(self) -> None:
        dedup = TaskDeduplicator()

        t1 = Task(id="t1", type="dns", target="example.com", command=["dig", "example.com", "A"])
        t2 = Task(id="t2", type="dns", target="example.com", command=["dig", "example.com", "A"])
        t3 = Task(id="t3", type="dns", target="example.com", command=["dig", "example.com", "AAAA"])

        assert dedup.is_duplicate(t1) is False
        assert dedup.register(t1) is None

        # t2 is an exact duplicate of t1
        assert dedup.is_duplicate(t2) is True
        assert dedup.register(t2) == "t1"

        # t3 has different arguments
        assert dedup.is_duplicate(t3) is False
        assert dedup.register(t3) is None

    def test_filter_duplicates(self) -> None:
        dedup = TaskDeduplicator()
        t1 = Task(id="t1", type="http", target="http://example.com", command=["curl", "http://example.com"])
        t2 = Task(id="t2", type="http", target="http://example.com", command=["curl", "http://example.com"])
        t3 = Task(id="t3", type="http", target="http://test.com", command=["curl", "http://test.com"])

        unique, skipped = dedup.filter_duplicates([t1, t2, t3])
        assert len(unique) == 2
        assert len(skipped) == 1
        assert skipped[0].id == "t2"
        assert skipped[0].state == TaskState.SKIPPED
        assert "Duplicate of task 't1'" in (skipped[0].result.error_message or "")


# =============================================================================
# 3. RUNNER & PARSER OPTIMIZATIONS
# =============================================================================

class TestSubprocessAndParserOptimization:
    """Tests for LRU caching and compiled regex performance improvements."""

    def test_runner_executable_resolution_cached(self) -> None:
        runner = CommandRunner()
        # First call hits filesystem
        p1 = runner.resolve_executable("python3")
        # Second call hits LRU cache
        p2 = runner.resolve_executable("python3")
        assert p1 == p2
        assert p1 is not None

    def test_url_normalization_cached(self) -> None:
        u1 = normalize_url("http://EXAMPLE.COM//admin///")
        u2 = normalize_url("http://EXAMPLE.COM//admin///")
        assert u1 == "http://example.com/admin"
        assert u1 == u2

    def test_url_path_and_parameter_normalization_cached(self) -> None:
        p1 = extract_url_path("http://example.com/login?token=abc")
        assert p1 == "http://example.com/login"

        param1 = normalize_parameter("user_id(GET)")
        assert param1 == "user_id"

    def test_nmap_parser_precompiled_regex(self) -> None:
        parser = NmapParser()
        sample_output = """
Starting Nmap 7.92
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.050s latency).
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 6.6.1p1
80/tcp  open  http    Apache httpd 2.4.7
Nmap done: 1 IP address (1 host up) scanned in 0.42 seconds
"""
        res = parser.parse(sample_output, target="scanme.nmap.org")
        assert len(res.hosts) == 1
        assert res.hosts[0].host == "scanme.nmap.org"
        assert len(res.hosts[0].ports) == 2


# =============================================================================
# 4. SCHEDULER PERFORMANCE & CACHING INTEGRATION
# =============================================================================

class TestSchedulerPerformanceIntegration(unittest.IsolatedAsyncioTestCase):
    """Tests for Scheduler optimization, priority queue heap, and cache integration."""

    async def test_scheduler_priority_queue_ordering(self) -> None:
        """Verify priority queue respects priority descending using heapq."""
        runner = DummyFastRunner(delay=0.001)
        scheduler = Scheduler(runner=runner, config=SchedulerConfig(global_concurrency=1))

        execution_order: list[str] = []

        async def action_low(task: Task, r: CommandRunner, ct: CancellationToken) -> TaskResult:
            execution_order.append(task.id)
            return TaskResult(task_id=task.id, state=TaskState.COMPLETED)

        async def action_med(task: Task, r: CommandRunner, ct: CancellationToken) -> TaskResult:
            execution_order.append(task.id)
            return TaskResult(task_id=task.id, state=TaskState.COMPLETED)

        async def action_high(task: Task, r: CommandRunner, ct: CancellationToken) -> TaskResult:
            execution_order.append(task.id)
            return TaskResult(task_id=task.id, state=TaskState.COMPLETED)

        t_low = Task(id="t_low", type="dummy", priority=1, action=action_low)
        t_med = Task(id="t_med", type="dummy", priority=5, action=action_med)
        t_high = Task(id="t_high", type="dummy", priority=10, action=action_high)

        # Add in arbitrary order
        scheduler.add_task(t_low)
        scheduler.add_task(t_high)
        scheduler.add_task(t_med)

        summary = await scheduler.run()
        assert summary.completed == 3
        # High priority should execute first, then med, then low
        assert execution_order == ["t_high", "t_med", "t_low"]

    async def test_scheduler_caching_eliminates_redundant_execution(self) -> None:
        """Section 34: Result caching prevents duplicate tool execution."""
        runner = DummyFastRunner(delay=0.005)
        cache = ResultCache()
        profiler = PerformanceProfiler()
        scope = ScopeValidator(allowed_domains=("example.com",))

        scheduler = Scheduler(runner=runner, cache=cache, profiler=profiler, scope=scope)

        # Two identical tasks targeting the same service with the same command
        t1 = Task(id="t1", type="dns", target="example.com", command=["dig", "example.com", "A"])
        t2 = Task(id="t2", type="dns", target="example.com", command=["dig", "example.com", "A"], dependencies={"t1"})

        scheduler.add_task(t1)
        scheduler.add_task(t2)

        summary = await scheduler.run()
        assert summary.completed == 2

        # Runner should only have been called ONCE; second task was answered from cache!
        assert runner.call_count == 1
        assert summary.metrics is not None
        assert summary.metrics.cache_hits == 1
        assert summary.metrics.cache_misses == 1

    async def test_scheduler_deduplicator_prevents_redundant_scheduling(self) -> None:
        """Section 34: Task deduplication skips redundant tasks before execution."""
        runner = DummyFastRunner(delay=0.001)
        dedup = TaskDeduplicator()
        profiler = PerformanceProfiler()
        scope = ScopeValidator(allowed_domains=("example.com",))

        scheduler = Scheduler(runner=runner, deduplicator=dedup, profiler=profiler, scope=scope)

        t1 = Task(id="t1", type="http", target="http://example.com", command=["curl", "http://example.com"])
        t2 = Task(id="t2", type="http", target="http://example.com", command=["curl", "http://example.com"])

        scheduler.add_task(t1)
        scheduler.add_task(t2)  # Duplicate, should be skipped immediately

        summary = await scheduler.run()
        assert summary.completed == 1
        assert summary.skipped == 1
        assert runner.call_count == 1
        assert summary.metrics is not None
        assert summary.metrics.duplicate_tasks_skipped == 1
