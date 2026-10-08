"""Base tool adapter abstraction for external reconnaissance binaries."""

from __future__ import annotations

from abc import ABC, abstractmethod
import logging
from typing import TYPE_CHECKING, Any

from reconx.core.cancellation import CancellationToken
from reconx.core.runner import CommandResult, CommandRunner
from reconx.core.task import Task, TaskResult, TaskState

if TYPE_CHECKING:
    from reconx.models.dns import DNSResult, RecordType

logger = logging.getLogger("reconx.tools.base")


class ToolAdapter(ABC):
    """Abstract base class for external tool wrappers.

    Adheres strictly to Section 7 of Implementation.md:
    1. Validate executable availability.
    2. Build arguments safely without shell execution.
    3. Execute through the centralized CommandRunner.
    4. Preserve exit status, stdout, and stderr.
    5. Parse output into normalized domain models.
    6. Expose tool and version metadata.
    """

    name: str
    executable: str
    resource_class: str = "default"

    def __init__(self, runner: CommandRunner | None = None) -> None:
        self.runner = runner if runner is not None else CommandRunner()

    def check_available(self) -> bool:
        """Check if the external executable is available on the system PATH."""
        return self.runner.is_available(self.executable)

    @abstractmethod
    async def version(self) -> str:
        """Query and return the installed version string, or fallback string."""
        ...

    @abstractmethod
    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """Safely construct command arguments array without shell strings."""
        ...

    @abstractmethod
    def parse_result(self, result: CommandResult | str, target: str = "") -> Any:
        """Parse raw process output or CommandResult into normalized data structures."""
        ...

    async def execute(
        self,
        target: str,
        timeout: float | None = None,
        cancellation_token: CancellationToken | None = None,
        **kwargs: Any,
    ) -> Any:
        """Execute the tool against a target and return the normalized parsed result."""
        cmd = self.build_command(target, **kwargs)
        cmd_res = await self.runner.run(
            command=cmd,
            timeout=timeout,
            cancellation_token=cancellation_token,
        )
        return self.parse_result(cmd_res, target=target)

    def create_task(
        self,
        task_id: str,
        target: str,
        priority: int = 0,
        timeout: float | None = None,
        dependencies: set[str] | None = None,
        **kwargs: Any,
    ) -> Task:
        """Create a schedulable Task instance for this tool execution."""
        cmd = self.build_command(target, **kwargs)

        async def _action(task: Task, runner: CommandRunner, token: CancellationToken) -> TaskResult:
            cmd_res = await runner.run(
                command=task.command or cmd,
                timeout=task.timeout,
                cancellation_token=token,
            )
            parsed_data = self.parse_result(cmd_res, target=target)

            if cmd_res.cancelled:
                state = TaskState.CANCELLED
            elif cmd_res.timed_out:
                state = TaskState.TIMEOUT
            elif cmd_res.success:
                state = TaskState.COMPLETED
            else:
                has_data = bool(
                    getattr(parsed_data, "records", None)
                    or getattr(parsed_data, "whois", None)
                    or getattr(parsed_data, "observations", None)
                    or (hasattr(parsed_data, "__len__") and len(parsed_data) > 0)
                )
                state = TaskState.COMPLETED if has_data else TaskState.FAILED

            err_msg = cmd_res.error
            if not err_msg and hasattr(parsed_data, "errors") and parsed_data.errors:
                err_msg = "; ".join(parsed_data.errors)

            return TaskResult(
                task_id=task.id,
                state=state,
                command_result=cmd_res,
                output_data=parsed_data,
                error_message=err_msg,
                attempts=task.attempts,
            )

        return Task(
            id=task_id,
            type=f"tool_{self.name}",
            target=target,
            command=cmd,
            action=_action,
            dependencies=dependencies or set(),
            priority=priority,
            timeout=timeout,
            resource_class=self.resource_class,
        )


class DNSToolAdapter(ToolAdapter):
    """Base adapter for DNS query tools (dig, host, nslookup)."""

    resource_class = "dns"

    @abstractmethod
    def build_command(
        self,
        target: str,
        record_type: str | RecordType = "A",
        nameserver: str | None = None,
        **kwargs: Any,
    ) -> list[str]:
        """Build command arguments for querying a specific DNS record type."""
        ...

    @abstractmethod
    def parse_result(self, result: CommandResult | str, target: str = "") -> DNSResult:
        """Parse DNS tool output into a normalized DNSResult."""
        ...
