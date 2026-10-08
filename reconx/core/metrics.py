"""Performance measurement, profiling, and observability engine (Phase 13).

Strictly adheres to Sections 34 & 35 of Implementation.md:
- Measure first before optimizing
- Observability: timing per task (queued_at, started_at, finished_at, duration)
- Scan Performance reporting (tasks/sec, average task duration, tool execution breakdown)
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import time
from typing import Any, Iterator


@dataclass
class PerformanceMetrics:
    """Consolidated performance profile of a scan execution run."""

    total_duration: float = 0.0
    total_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    skipped_tasks: int = 0
    tasks_per_second: float = 0.0
    targets_per_second: float = 0.0
    average_task_duration: float = 0.0
    scheduler_overhead_seconds: float = 0.0
    tool_execution_seconds: dict[str, float] = field(default_factory=dict)
    parser_execution_seconds: dict[str, float] = field(default_factory=dict)
    cache_hits: int = 0
    cache_misses: int = 0
    duplicate_tasks_skipped: int = 0

    def format_report(self) -> str:
        """Format the canonical SCAN PERFORMANCE report conforming to Section 35."""
        lines = [
            "SCAN PERFORMANCE",
            "----------------",
            f"Total duration: {self.total_duration:.1f}s",
            f"Tasks:          {self.total_tasks}",
            f"Completed:      {self.completed_tasks}",
            f"Failed:          {self.failed_tasks}",
            f"Skipped:         {self.skipped_tasks}",
            "",
            "Throughput:",
            f"Tasks/sec:       {self.tasks_per_second:.2f}",
            f"Avg task dur:    {self.average_task_duration:.2f}s",
            f"Sched overhead:  {self.scheduler_overhead_seconds:.2f}s",
        ]

        if self.cache_hits > 0 or self.duplicate_tasks_skipped > 0:
            lines.extend([
                "",
                "Optimization:",
                f"Cache hits:      {self.cache_hits}",
                f"Dedup skipped:   {self.duplicate_tasks_skipped}",
            ])

        if self.tool_execution_seconds:
            lines.extend(["", "Tool execution:"])
            # Sort tools by duration descending
            sorted_tools = sorted(
                self.tool_execution_seconds.items(), key=lambda item: item[1], reverse=True
            )
            for tool_name, dur in sorted_tools:
                lines.append(f"{tool_name + ':':<17}{dur:.1f}s")

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Convert metrics to a structured dictionary."""
        return {
            "total_duration": self.total_duration,
            "total_tasks": self.total_tasks,
            "completed_tasks": self.completed_tasks,
            "failed_tasks": self.failed_tasks,
            "skipped_tasks": self.skipped_tasks,
            "tasks_per_second": self.tasks_per_second,
            "targets_per_second": self.targets_per_second,
            "average_task_duration": self.average_task_duration,
            "scheduler_overhead_seconds": self.scheduler_overhead_seconds,
            "tool_execution_seconds": dict(self.tool_execution_seconds),
            "parser_execution_seconds": dict(self.parser_execution_seconds),
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "duplicate_tasks_skipped": self.duplicate_tasks_skipped,
        }


class PerformanceProfiler:
    """Collects and computes performance timings and efficiency metrics."""

    def __init__(self) -> None:
        self.start_mono: float | None = None
        self.stop_mono: float | None = None
        self.total_duration: float = 0.0

        self.total_tasks: int = 0
        self.completed_tasks: int = 0
        self.failed_tasks: int = 0
        self.skipped_tasks: int = 0

        self.task_durations: list[float] = []
        self.tool_execution_seconds: dict[str, float] = {}
        self.parser_execution_seconds: dict[str, float] = {}

        self.cache_hits: int = 0
        self.cache_misses: int = 0
        self.duplicate_tasks_skipped: int = 0

    def start(self) -> None:
        """Begin measuring overall scan duration."""
        self.start_mono = time.monotonic()
        self.stop_mono = None

    def stop(self) -> None:
        """Stop measuring overall scan duration."""
        self.stop_mono = time.monotonic()
        if self.start_mono is not None:
            self.total_duration = self.stop_mono - self.start_mono

    @contextmanager
    def measure_tool(self, tool_name: str) -> Iterator[None]:
        """Context manager to measure external tool execution time."""
        t0 = time.monotonic()
        try:
            yield
        finally:
            elapsed = time.monotonic() - t0
            self.tool_execution_seconds[tool_name] = (
                self.tool_execution_seconds.get(tool_name, 0.0) + elapsed
            )

    @contextmanager
    def measure_parser(self, parser_name: str) -> Iterator[None]:
        """Context manager to measure parser execution time."""
        t0 = time.monotonic()
        try:
            yield
        finally:
            elapsed = time.monotonic() - t0
            self.parser_execution_seconds[parser_name] = (
                self.parser_execution_seconds.get(parser_name, 0.0) + elapsed
            )

    def record_task(
        self,
        task_id: str,
        duration: float,
        state: str,
        tool_name: str | None = None,
    ) -> None:
        """Record task execution timing and outcome."""
        self.total_tasks += 1
        if state == "COMPLETED":
            self.completed_tasks += 1
        elif state in ("FAILED", "TIMEOUT", "CANCELLED"):
            self.failed_tasks += 1
        elif state == "SKIPPED":
            self.skipped_tasks += 1

        if duration > 0.0:
            self.task_durations.append(duration)
            if tool_name:
                self.tool_execution_seconds[tool_name] = (
                    self.tool_execution_seconds.get(tool_name, 0.0) + duration
                )

    def record_cache_hit(self) -> None:
        """Record a cache hit avoiding redundant execution."""
        self.cache_hits += 1

    def record_cache_miss(self) -> None:
        """Record a cache miss requiring execution."""
        self.cache_misses += 1

    def record_dedup_skip(self) -> None:
        """Record a task skipped because it was identical to an existing task."""
        self.total_tasks += 1
        self.duplicate_tasks_skipped += 1
        self.skipped_tasks += 1

    def get_metrics(self, total_targets: int = 1) -> PerformanceMetrics:
        """Compute consolidated PerformanceMetrics."""
        # Compute duration if stop() was not explicitly called
        duration = self.total_duration
        if duration <= 0.0 and self.start_mono is not None:
            end = self.stop_mono or time.monotonic()
            duration = end - self.start_mono

        duration = max(0.001, duration)

        avg_dur = (
            sum(self.task_durations) / len(self.task_durations)
            if self.task_durations
            else 0.0
        )
        tasks_per_sec = self.completed_tasks / duration if duration > 0 else 0.0
        targets_per_sec = total_targets / duration if duration > 0 else 0.0

        # Scheduler overhead is total duration minus maximum concurrency-adjusted tool time
        total_tool_time = sum(self.tool_execution_seconds.values())
        overhead = max(0.0, duration - min(duration, total_tool_time))

        return PerformanceMetrics(
            total_duration=duration,
            total_tasks=self.total_tasks,
            completed_tasks=self.completed_tasks,
            failed_tasks=self.failed_tasks,
            skipped_tasks=self.skipped_tasks,
            tasks_per_second=tasks_per_sec,
            targets_per_second=targets_per_sec,
            average_task_duration=avg_dur,
            scheduler_overhead_seconds=overhead,
            tool_execution_seconds=dict(self.tool_execution_seconds),
            parser_execution_seconds=dict(self.parser_execution_seconds),
            cache_hits=self.cache_hits,
            cache_misses=self.cache_misses,
            duplicate_tasks_skipped=self.duplicate_tasks_skipped,
        )


# Global default profiler instance for convenience
_default_profiler = PerformanceProfiler()


def get_global_profiler() -> PerformanceProfiler:
    """Get the process-wide PerformanceProfiler instance."""
    return _default_profiler
