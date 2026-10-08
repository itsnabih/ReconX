"""Result caching and task deduplication engine (Phase 13).

Strictly adheres to Section 34 of Implementation.md:
- Task deduplication
- Result caching where safe
- Minimal redundant scanning
- Minimal duplicate requests
- Early filtering
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
import hashlib
import json
import threading
import time
from typing import Any

from reconx.core.task import Task, TaskResult, TaskState


def make_cache_key(
    tool: str,
    target: str,
    arguments: Sequence[str] | None = None,
    extra: dict[str, Any] | None = None,
) -> str:
    """Generate a deterministic SHA256 cache key for an operation."""
    payload = {
        "tool": tool.strip().lower(),
        "target": target.strip().lower(),
        "args": list(arguments) if arguments else [],
        "extra": extra or {},
    }
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


@dataclass
class CacheEntry:
    """A cached execution output or observation."""

    key: str
    value: Any
    created_at: float = field(default_factory=time.monotonic)
    ttl: float | None = None

    @property
    def is_expired(self) -> bool:
        if self.ttl is None:
            return False
        return (time.monotonic() - self.created_at) > self.ttl


class ResultCache:
    """Thread-safe in-memory result cache with optional TTL."""

    def __init__(self, default_ttl: float | None = None) -> None:
        self.default_ttl = default_ttl
        self._entries: dict[str, CacheEntry] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Any | None:
        """Retrieve cached value if present and not expired."""
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if entry.is_expired:
                del self._entries[key]
                return None
            return entry.value

    def set(self, key: str, value: Any, ttl: float | None = None) -> None:
        """Store value in cache with optional TTL."""
        effective_ttl = ttl if ttl is not None else self.default_ttl
        with self._lock:
            self._entries[key] = CacheEntry(
                key=key,
                value=value,
                created_at=time.monotonic(),
                ttl=effective_ttl,
            )

    def has(self, key: str) -> bool:
        """Check if an unexpired cache entry exists."""
        return self.get(key) is not None

    def clear(self) -> None:
        """Clear all cached entries."""
        with self._lock:
            self._entries.clear()

    def size(self) -> int:
        """Return number of cached entries."""
        with self._lock:
            # Clean expired on size inquiry
            now = time.monotonic()
            expired = [k for k, e in self._entries.items() if e.ttl and (now - e.created_at) > e.ttl]
            for k in expired:
                del self._entries[k]
            return len(self._entries)


class TaskDeduplicator:
    """Identifies and eliminates redundant tasks before scheduling or execution."""

    def __init__(self) -> None:
        self._seen_signatures: dict[str, str] = {}  # signature -> canonical_task_id
        self._lock = threading.Lock()

    @staticmethod
    def compute_signature(task: Task) -> str:
        """Compute canonical signature of a Task based on type, target, and command."""
        cmd_args = task.command[1:] if task.command and len(task.command) > 1 else ()
        tool_name = task.command[0] if task.command else task.type
        return make_cache_key(
            tool=tool_name,
            target=task.target,
            arguments=cmd_args,
        )

    def is_duplicate(self, task: Task) -> bool:
        """Check if an identical task has already been registered."""
        sig = self.compute_signature(task)
        with self._lock:
            return sig in self._seen_signatures and self._seen_signatures[sig] != task.id

    def register(self, task: Task) -> str | None:
        """Register a task signature.

        Returns:
            canonical_task_id of the existing task if duplicate, or None if unique.
        """
        sig = self.compute_signature(task)
        with self._lock:
            if sig in self._seen_signatures:
                existing_id = self._seen_signatures[sig]
                if existing_id != task.id:
                    return existing_id
            else:
                self._seen_signatures[sig] = task.id
            return None

    def filter_duplicates(self, tasks: Sequence[Task]) -> tuple[list[Task], list[Task]]:
        """Filter a list of tasks into unique tasks and redundant/skipped tasks.

        Redundant tasks are marked as SKIPPED with an explanatory error_message.

        Returns:
            (unique_tasks, skipped_duplicate_tasks)
        """
        unique: list[Task] = []
        skipped: list[Task] = []

        for task in tasks:
            existing_id = self.register(task)
            if existing_id is not None:
                # Mark as skipped duplicate
                task.mark_finished(
                    TaskState.SKIPPED,
                    TaskResult(
                        task_id=task.id,
                        state=TaskState.SKIPPED,
                        error_message=f"Duplicate of task '{existing_id}'; redundant execution skipped",
                    ),
                )
                skipped.append(task)
            else:
                unique.append(task)

        return unique, skipped
