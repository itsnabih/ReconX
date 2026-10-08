"""Task model, state definitions, retry policies, and structured task results."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from reconx.core.cancellation import CancellationToken
from reconx.core.runner import CommandResult, CommandRunner


class TaskState(str, Enum):
    """Lifecycle states of an orchestrated task."""

    PENDING = "PENDING"
    READY = "READY"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"
    SKIPPED = "SKIPPED"


@dataclass(frozen=True)
class RetryPolicy:
    """Configures retry behavior for tasks."""

    max_retries: int = 0
    backoff_factor: float = 0.0
    retry_on_timeout: bool = True
    retryable_exit_codes: tuple[int, ...] = ()

    def should_retry(self, attempt: int, exit_code: int | None, timed_out: bool) -> bool:
        """Determine whether another retry attempt is permitted.
        
        Args:
            attempt: Current 1-based attempt index.
            exit_code: Process exit code if available.
            timed_out: Whether execution timed out.
        """
        if attempt > self.max_retries:
            return False
        if timed_out and self.retry_on_timeout:
            return True
        if exit_code is not None and exit_code in self.retryable_exit_codes:
            return True
        return False


@dataclass
class TaskResult:
    """Structured result of a completed or terminated task."""

    task_id: str
    state: TaskState
    command_result: CommandResult | None = None
    output_data: Any = None
    error_message: str | None = None
    attempts: int = 1
    duration: float = 0.0

    @property
    def is_success(self) -> bool:
        return self.state == TaskState.COMPLETED


# Type alias for custom task action coroutine
TaskAction = Callable[["Task", CommandRunner, CancellationToken], Awaitable[TaskResult]]


@dataclass
class Task:
    """Represents an atomic, schedulable unit of work in ReconX.
    
    Adheres strictly to Section 9 of Implementation.md.
    """

    id: str
    type: str
    target: str = ""
    command: list[str] | None = None
    action: TaskAction | None = None
    dependencies: set[str] = field(default_factory=set)
    priority: int = 0
    timeout: float | None = None
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)
    resource_class: str = "default"
    state: TaskState = TaskState.PENDING

    # Observability & Timing (Section 35)
    queued_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration: float | None = None

    # Execution bookkeeping
    attempts: int = 0
    result: TaskResult | None = None

    def __post_init__(self) -> None:
        if isinstance(self.dependencies, (list, tuple)):
            self.dependencies = set(self.dependencies)

    @property
    def is_terminal(self) -> bool:
        """Return True if the task has reached a terminal state."""
        return self.state in {
            TaskState.COMPLETED,
            TaskState.FAILED,
            TaskState.TIMEOUT,
            TaskState.CANCELLED,
            TaskState.SKIPPED,
        }

    @property
    def is_successful(self) -> bool:
        """Return True if the task completed successfully."""
        return self.state == TaskState.COMPLETED

    def mark_queued(self) -> None:
        self.queued_at = datetime.now(timezone.utc)
        self.state = TaskState.PENDING

    def mark_ready(self) -> None:
        self.state = TaskState.READY

    def mark_running(self) -> None:
        self.state = TaskState.RUNNING
        if self.started_at is None:
            self.started_at = datetime.now(timezone.utc)

    def mark_finished(self, state: TaskState, result: TaskResult | None = None) -> None:
        self.state = state
        self.finished_at = datetime.now(timezone.utc)
        if self.started_at is not None:
            self.duration = (self.finished_at - self.started_at).total_seconds()
        self.result = result
