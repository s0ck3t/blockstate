"""TaskFrame and TaskStack pushdown automata execution context.

Provides discrete frame-level slot isolation, locked leaf-path immutability
protection, and bounded call-stack management for conversational digressions.
"""

from collections.abc import Iterable, Iterator, Mapping
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

from blockstate.errors import StackOverflowError, UnauthorisedMutationError


@dataclass(slots=True)
class TaskFrame:
    """Discrete unit of execution context for an active conversational stage.

    Tracks partially hydrated slots, locked leaf paths, turn counts, and
    permitted digressions while providing strict lock protection against
    unauthorised slot overwrites.
    """

    stage_id: str
    target_model: type[BaseModel] | None = None
    slots: dict[str, Any] = field(default_factory=dict)
    locked_slots: set[str] = field(default_factory=set)
    allow_slot_overrides: bool = False
    turn_count: int = 0
    max_turns: int | None = 5
    allowed_tools: frozenset[str] = field(default_factory=frozenset)
    allowed_digressions: frozenset[str] = field(default_factory=frozenset)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def partial_slots(self) -> dict[str, Any]:
        """Access the frame's active slot dictionary."""
        return self.slots

    def is_locked(self, path: str) -> bool:
        """Check whether a specific leaf slot path, ancestor, or descendant is locked."""
        for locked in self.locked_slots:
            if locked == path:
                return True
            if path.startswith(f"{locked}."):
                return True
            if locked.startswith(f"{path}."):
                return True
        return False

    def lock_slot(self, path: str) -> None:
        """Lock a leaf slot path to prevent silent or unauthorised overwrites."""
        self.locked_slots.add(path)

    def lock_slots(self, paths: Iterable[str]) -> None:
        """Lock multiple leaf slot paths simultaneously."""
        self.locked_slots.update(paths)

    def unlock_slot(self, path: str) -> None:
        """Unlock a leaf slot path, permitting subsequent mutations."""
        self.locked_slots.discard(path)

    @staticmethod
    def _extract_all_paths(updates: Mapping[str, Any], prefix: str = "") -> list[str]:
        """Extract flat and dot-separated paths for all candidate keys."""
        paths: list[str] = []
        for key, value in updates.items():
            full_path = f"{prefix}.{key}" if prefix else str(key)
            paths.append(full_path)
            if isinstance(value, Mapping):
                paths.extend(TaskFrame._extract_all_paths(value, prefix=full_path))
        return paths

    def get_slot(self, path: str, default: Any = None) -> Any:
        """Retrieve a slot value by flat identifier or dot-separated path."""
        if path in self.slots:
            return self.slots[path]

        parts = path.split(".")
        current: Any = self.slots
        for part in parts:
            if isinstance(current, Mapping) and part in current:
                current = current[part]
            elif hasattr(current, part):
                current = getattr(current, part)
            else:
                return default
        return current

    def set_slot(
        self,
        path: str,
        value: Any,
        *,
        lock: bool = False,
        force: bool = False,
    ) -> None:
        """Set a slot value with mandatory locked-slot immutability enforcement.

        Raises UnauthorisedMutationError (BLK-SEC-002) if attempting to overwrite
        a locked slot without explicit override authorisation.
        """
        if self.is_locked(path) and not force and not self.allow_slot_overrides:
            raise UnauthorisedMutationError(
                f"Cannot overwrite locked slot '{path}' without explicit authorisation",
                code="BLK-SEC-002",
                stage=self.stage_id,
                field_path=path,
            )

        if "." not in path:
            self.slots[path] = value
        else:
            parts = path.split(".")
            current = self.slots
            for part in parts[:-1]:
                if part not in current or not isinstance(current[part], dict):
                    current[part] = {}
                current = current[part]
            current[parts[-1]] = value

        if lock:
            self.lock_slot(path)

    def update_slots(
        self,
        updates: Mapping[str, Any],
        *,
        lock: bool = True,
        force: bool = False,
    ) -> None:
        """Update multiple slots, checking locked-slot boundaries across all candidates."""
        # Pre-validate all candidate keys to ensure fail-closed atomic mutation
        candidate_paths = self._extract_all_paths(updates)
        if not force and not self.allow_slot_overrides:
            for path in candidate_paths:
                if self.is_locked(path):
                    raise UnauthorisedMutationError(
                        f"Cannot overwrite locked slot '{path}' without explicit authorisation",
                        code="BLK-SEC-002",
                        stage=self.stage_id,
                        field_path=path,
                    )

        for key, value in updates.items():
            self.set_slot(key, value, lock=lock, force=True)
            if lock and isinstance(value, Mapping):
                for subpath in self._extract_all_paths(value, prefix=str(key)):
                    self.lock_slot(subpath)

    def copy(self) -> "TaskFrame":
        """Create a deep copy of this TaskFrame with isolated slot memory."""
        return TaskFrame(
            stage_id=self.stage_id,
            target_model=self.target_model,
            slots=deepcopy(self.slots),
            locked_slots=set(self.locked_slots),
            allow_slot_overrides=self.allow_slot_overrides,
            turn_count=self.turn_count,
            max_turns=self.max_turns,
            allowed_tools=self.allowed_tools,
            allowed_digressions=self.allowed_digressions,
            metadata=deepcopy(self.metadata),
        )


class TaskStack:
    """Bounded Last-In, First-Out (LIFO) execution stack of TaskFrames.

    Governs multi-turn conversational detours and pushdown automata execution,
    strictly enforcing max_stack_depth (default 6).
    """

    def __init__(self, max_stack_depth: int = 6) -> None:
        self._frames: list[TaskFrame] = []
        self._max_stack_depth = max_stack_depth

    @property
    def max_stack_depth(self) -> int:
        """Return the maximum permitted stack depth."""
        return self._max_stack_depth

    @property
    def top(self) -> TaskFrame | None:
        """Return the active top frame on the stack without removing it."""
        return self._frames[-1] if self._frames else None

    @property
    def frames(self) -> tuple[TaskFrame, ...]:
        """Return an immutable snapshot of all frames in the stack."""
        return tuple(self._frames)

    def push(self, frame: TaskFrame) -> None:
        """Push a child TaskFrame onto the stack.

        Raises StackOverflowError (BLK-SEC-003) if stack depth exceeds limit.
        """
        if len(self._frames) >= self._max_stack_depth:
            raise StackOverflowError(
                f"TaskStack depth exceeds maximum limit of {self._max_stack_depth}",
                code="BLK-SEC-003",
                stage=frame.stage_id,
                current_depth=len(self._frames),
                max_stack_depth=self._max_stack_depth,
            )
        self._frames.append(frame)

    def pop(self) -> TaskFrame:
        """Pop and return the top TaskFrame from the stack.

        Raises IndexError if the stack is empty.
        """
        if not self._frames:
            raise IndexError("Cannot pop from an empty TaskStack")
        return self._frames.pop()

    def peek(self) -> TaskFrame | None:
        """Return the top TaskFrame without popping, or None if empty."""
        return self.top

    def __len__(self) -> int:
        return len(self._frames)

    def __iter__(self) -> Iterator[TaskFrame]:
        return iter(self._frames)

    def __repr__(self) -> str:
        stages = [f.stage_id for f in self._frames]
        return (
            f"TaskStack(depth={len(self._frames)}, "
            f"max_depth={self._max_stack_depth}, frames={stages!r})"
        )


__all__: list[str] = [
    "TaskFrame",
    "TaskStack",
]
