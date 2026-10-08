"""Centralized command execution layer for external processes."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
import functools
import logging
import os
import shutil
import time
from typing import Sequence

from reconx.core.cancellation import CancellationToken

logger = logging.getLogger("reconx.core.runner")

# Maximum output size to prevent unbounded memory buffering (10 MB default)
DEFAULT_MAX_OUTPUT_BYTES = 10 * 1024 * 1024
DEFAULT_GRACE_PERIOD_SECONDS = 1.5


@dataclass(frozen=True)
class CommandResult:
    """Structured result of a command execution."""

    command: list[str]
    executable: str
    arguments: list[str]
    started_at: datetime
    finished_at: datetime
    duration: float
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    cancelled: bool = False
    error: str | None = None

    @property
    def success(self) -> bool:
        """Return True if command finished with exit code 0, without timeout or cancellation."""
        return self.exit_code == 0 and not self.timed_out and not self.cancelled and self.error is None


class CommandRunner:
    """Centralized and safe subprocess execution manager.
    
    Guarantees:
    - No shell=True execution (strictly argument arrays).
    - Strict timeout and cancellation enforcement.
    - Child process lifecycle management (no zombie processes).
    - Structured result collection.
    - Tool availability checks.
    """

    def __init__(
        self,
        default_timeout: float | None = 60.0,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
        grace_period: float = DEFAULT_GRACE_PERIOD_SECONDS,
    ) -> None:
        self.default_timeout = default_timeout
        self.max_output_bytes = max_output_bytes
        self.grace_period = grace_period

    @classmethod
    def is_available(cls, executable: str) -> bool:
        """Check if an external binary is available in the system PATH."""
        return cls.resolve_executable(executable) is not None

    @staticmethod
    @functools.lru_cache(maxsize=128)
    def resolve_executable(executable: str) -> str | None:
        """Resolve full path to executable, or return None if not found (cached)."""
        return shutil.which(executable)

    async def run(
        self,
        command: Sequence[str],
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout: float | None = None,
        cancellation_token: CancellationToken | None = None,
    ) -> CommandResult:
        """Execute a command safely using asyncio subprocess.
        
        Args:
            command: Sequence of strings representing executable and arguments.
            cwd: Working directory for subprocess.
            env: Custom environment variables, or None to inherit os.environ.
            timeout: Maximum execution duration in seconds, or None for runner default.
            cancellation_token: Optional token to trigger early termination.
            
        Returns:
            CommandResult containing execution metadata, outputs, and exit status.
        """
        if not command:
            raise ValueError("Command cannot be empty")

        cmd_list = [str(arg) for arg in command]
        executable = cmd_list[0]
        arguments = cmd_list[1:]
        effective_timeout = timeout if timeout is not None else self.default_timeout

        started_at = datetime.now(timezone.utc)
        start_mono = time.monotonic()

        # Check if already cancelled
        if cancellation_token is not None and cancellation_token.is_cancelled:
            finished_at = datetime.now(timezone.utc)
            duration = time.monotonic() - start_mono
            return CommandResult(
                command=cmd_list,
                executable=executable,
                arguments=arguments,
                started_at=started_at,
                finished_at=finished_at,
                duration=duration,
                exit_code=None,
                stdout="",
                stderr="",
                timed_out=False,
                cancelled=True,
                error="Cancelled before execution started",
            )

        # Validate executable existence
        resolved_path = self.resolve_executable(executable)
        if resolved_path is None:
            finished_at = datetime.now(timezone.utc)
            duration = time.monotonic() - start_mono
            logger.warning("Executable '%s' not found in PATH", executable)
            return CommandResult(
                command=cmd_list,
                executable=executable,
                arguments=arguments,
                started_at=started_at,
                finished_at=finished_at,
                duration=duration,
                exit_code=None,
                stdout="",
                stderr="",
                timed_out=False,
                cancelled=False,
                error=f"Executable '{executable}' not found in PATH",
            )

        # Merge environment variables
        process_env = os.environ.copy()
        if env:
            process_env.update(env)

        logger.debug("Executing command: %s (cwd=%s, timeout=%s)", cmd_list, cwd, effective_timeout)

        proc: asyncio.subprocess.Process | None = None
        timed_out = False
        cancelled = False
        error_msg: str | None = None
        stdout_str = ""
        stderr_str = ""

        try:
            proc = await asyncio.create_subprocess_exec(
                resolved_path,
                *arguments,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=process_env,
            )

            # Setup cancellation hook if token provided
            def _cancel_hook() -> None:
                if proc is not None and proc.returncode is None:
                    try:
                        proc.terminate()
                    except ProcessLookupError:
                        pass

            if cancellation_token is not None:
                cancellation_token.register_callback(_cancel_hook)

            try:
                # Wait for process with optional timeout
                if effective_timeout is not None and effective_timeout > 0:
                    stdout_bytes, stderr_bytes = await asyncio.wait_for(
                        proc.communicate(),
                        timeout=effective_timeout,
                    )
                else:
                    stdout_bytes, stderr_bytes = await proc.communicate()

                stdout_str = self._decode_output(stdout_bytes)
                stderr_str = self._decode_output(stderr_bytes)

            except asyncio.TimeoutError:
                timed_out = True
                error_msg = f"Command timed out after {effective_timeout}s"
                logger.warning("Command '%s' timed out after %ss", executable, effective_timeout)
                await self._terminate_process(proc)

            except asyncio.CancelledError:
                cancelled = True
                error_msg = "Command was cancelled"
                logger.info("Command '%s' cancelled during execution", executable)
                await self._terminate_process(proc)
                raise

            finally:
                if cancellation_token is not None:
                    cancellation_token.unregister_callback(_cancel_hook)

        except FileNotFoundError:
            error_msg = f"Executable '{executable}' not found"
            logger.error("Executable '%s' not found on start", executable)
        except Exception as exc:
            error_msg = f"Subprocess execution failed: {exc}"
            logger.error("Subprocess execution exception for '%s': %s", executable, exc)
            if proc is not None and proc.returncode is None:
                await self._terminate_process(proc)

        # Check if cancellation token fired during execution
        if cancellation_token is not None and cancellation_token.is_cancelled:
            cancelled = True
            if not error_msg:
                error_msg = "Command was cancelled via CancellationToken"

        finished_at = datetime.now(timezone.utc)
        duration = time.monotonic() - start_mono
        exit_code = proc.returncode if proc is not None else None

        logger.debug(
            "Finished command '%s' in %.3fs (exit_code=%s, timed_out=%s, cancelled=%s)",
            executable,
            duration,
            exit_code,
            timed_out,
            cancelled,
        )

        return CommandResult(
            command=cmd_list,
            executable=executable,
            arguments=arguments,
            started_at=started_at,
            finished_at=finished_at,
            duration=duration,
            exit_code=exit_code,
            stdout=stdout_str,
            stderr=stderr_str,
            timed_out=timed_out,
            cancelled=cancelled,
            error=error_msg,
        )

    async def _terminate_process(self, proc: asyncio.subprocess.Process) -> None:
        """Safely terminate a process with SIGTERM, falling back to SIGKILL."""
        if proc.returncode is not None:
            return

        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), timeout=self.grace_period)
        except (asyncio.TimeoutError, ProcessLookupError):
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
        except Exception as exc:
            logger.warning("Error while terminating process: %s", exc)

    def _decode_output(self, raw_bytes: bytes | None) -> str:
        """Decode output bytes safely, capping to max_output_bytes to prevent memory exhaustion."""
        if not raw_bytes:
            return ""
        if len(raw_bytes) > self.max_output_bytes:
            raw_bytes = raw_bytes[: self.max_output_bytes]
        return raw_bytes.decode("utf-8", errors="replace")
