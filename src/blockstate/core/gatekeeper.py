"""Zero-Trust physical tool gatekeeper and ephemeral dispatch table engine.

Enforces strict per-stage tool containment: builds ephemeral, immutable
MappingProxyType dispatch tables containing exclusively the tools whitelisted
for the active stage, injects isolated RunContext[Deps], detokenises
Detokenise[T] arguments on ingress, and re-sanitises outputs upon egress.
"""

import inspect
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, get_origin

from blockstate.core.stack import ReadOnlySessionView
from blockstate.errors import SecurityViolationError
from blockstate.security.annotations import is_detokenise


@dataclass(frozen=True, slots=True)
class RunContext[Deps]:
    """Isolated execution context passed into whitelisted stage tools."""

    deps: Deps
    session_id: str = "default"
    turn_index: int = 0
    session: ReadOnlySessionView | None = None
    vault: Any | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def detokenise(self, token: str) -> str:
        """Detokenise a vaulted token using the active session vault."""
        if self.vault is not None and hasattr(self.vault, "detokenise"):
            return str(self.vault.detokenise(token, session_id=self.session_id))
        return token


class ToolGatekeeper:
    """Zero-trust ephemeral tool gatekeeper and dispatch table engine.

    Guarantees no global callable tool registry exists in runtime memory.
    Dispatches tool calls exclusively through ephemeral MappingProxyType tables
    scoped to the active stage's declared whitelist.
    """

    def __init__(self, tools: Mapping[str, Callable[..., Any]] | None = None) -> None:
        self._tools: dict[str, Callable[..., Any]] = dict(tools) if tools else {}

    def register_tool(self, name: str, fn: Callable[..., Any]) -> None:
        """Register a callable tool with a unique name on this gatekeeper instance."""
        if not name or not isinstance(name, str):
            raise ValueError("Tool name must be a non-empty string identifier")
        self._tools[name] = fn

    def register_tools(self, tools: Mapping[str, Callable[..., Any]]) -> None:
        """Register multiple tools simultaneously on this gatekeeper instance."""
        for name, fn in tools.items():
            self.register_tool(name, fn)

    def get_tool(self, name: str) -> Callable[..., Any] | None:
        """Retrieve a registered tool callable by name, or None."""
        return self._tools.get(name)

    def build_dispatch_table(
        self, allowed_tools: Iterable[str]
    ) -> MappingProxyType[str, Callable[..., Any]]:
        """Construct an ephemeral, immutable dispatch table containing only whitelisted tools."""
        allowed_set = frozenset(allowed_tools)
        dispatch: dict[str, Callable[..., Any]] = {
            name: fn for name, fn in self._tools.items() if name in allowed_set
        }
        return MappingProxyType(dispatch)

    def build_tool_schema(self, allowed_tools: Iterable[str]) -> list[dict[str, Any]]:
        """Construct outbound JSON schema schemas containing solely whitelisted stage tools."""
        allowed_set = frozenset(allowed_tools)
        schemas: list[dict[str, Any]] = []

        for name in sorted(allowed_set):
            fn = self._tools.get(name)
            if fn is None:
                continue

            doc = inspect.getdoc(fn) or f"Execute tool {name}"
            sig = inspect.signature(fn)

            properties: dict[str, Any] = {}
            required: list[str] = []

            for param_name, param in sig.parameters.items():
                if self._is_context_param(param):
                    continue

                prop: dict[str, Any] = {"type": "string"}
                if param.annotation is int:
                    prop = {"type": "integer"}
                elif param.annotation is float:
                    prop = {"type": "number"}
                elif param.annotation is bool:
                    prop = {"type": "boolean"}
                elif param.annotation is list or get_origin(param.annotation) is list:
                    prop = {"type": "array"}
                elif param.annotation is dict or get_origin(param.annotation) is dict:
                    prop = {"type": "object"}

                properties[param_name] = prop

                if param.default is inspect._empty:
                    required.append(param_name)

            schemas.append(
                {
                    "type": "function",
                    "function": {
                        "name": name,
                        "description": doc,
                        "parameters": {
                            "type": "object",
                            "properties": properties,
                            "required": required,
                        },
                    },
                }
            )

        return schemas

    @staticmethod
    def _is_context_param(param: inspect.Parameter) -> bool:
        """Check whether a parameter represents RunContext."""
        if param.name in ("context", "ctx"):
            return True
        annotation = param.annotation
        if annotation is RunContext:
            return True
        origin = get_origin(annotation)
        if origin is RunContext:
            return True
        return bool(isinstance(annotation, type) and issubclass(annotation, RunContext))

    def _prepare_arguments(
        self,
        fn: Callable[..., Any],
        arguments: Mapping[str, Any],
        context: RunContext[Any] | None = None,
        vault: Any | None = None,
    ) -> dict[str, Any]:
        """Prepare and validate arguments, detokenising Detokenise[T] parameters."""
        sig = inspect.signature(fn)
        resolved_kwargs: dict[str, Any] = {}
        session_id = context.session_id if context else "default"

        for param_name, param in sig.parameters.items():
            if self._is_context_param(param):
                resolved_kwargs[param_name] = context
                continue

            if param_name in arguments:
                val = arguments[param_name]
                if is_detokenise(param.annotation) and vault is not None:
                    val = self._detokenise_value(val, vault=vault, session_id=session_id)
                resolved_kwargs[param_name] = val
            elif param.default is not inspect._empty:
                resolved_kwargs[param_name] = param.default

        return resolved_kwargs

    @staticmethod
    def _detokenise_value(val: Any, vault: Any, session_id: str) -> Any:
        """Recursively detokenise values through the vault."""
        if isinstance(val, str) and hasattr(vault, "detokenise"):
            return vault.detokenise(val, session_id=session_id)
        if isinstance(val, Mapping) and hasattr(vault, "detokenise"):
            return {
                k: vault.detokenise(v, session_id=session_id) if isinstance(v, str) else v
                for k, v in val.items()
            }
        if isinstance(val, (list, tuple)) and hasattr(vault, "detokenise"):
            return type(val)(
                vault.detokenise(item, session_id=session_id) if isinstance(item, str) else item
                for item in val
            )
        return val

    def _resanitise_result(self, result: Any, vault: Any | None, session_id: str) -> Any:
        """Re-sanitise tool output before returning to session state or Pass 2."""
        if vault is None:
            return result
        if isinstance(result, str) and hasattr(vault, "sanitise_sync"):
            return vault.sanitise_sync(result, session_id=session_id).sanitised_text
        if isinstance(result, Mapping) and hasattr(vault, "sanitise_mapping_sync"):
            return vault.sanitise_mapping_sync(result, session_id=session_id)
        return result

    async def invoke(
        self,
        tool_name: str,
        allowed_tools: Iterable[str],
        arguments: Mapping[str, Any],
        context: RunContext[Any] | None = None,
        vault: Any | None = None,
    ) -> Any:
        """Invoke a whitelisted tool with physical tool gating and zero-trust parameter handling.

        Raises SecurityViolationError (BLK-SEC-001) if tool is unpermitted or unknown.
        """
        allowed_set = frozenset(allowed_tools)
        if tool_name not in allowed_set:
            raise SecurityViolationError(
                f"Tool '{tool_name}' is not permitted by active stage whitelist",
                code="BLK-SEC-001",
                tool_name=tool_name,
            )

        fn = self._tools.get(tool_name)
        if fn is None:
            raise SecurityViolationError(
                f"Tool '{tool_name}' is unknown or not registered",
                code="BLK-SEC-001",
                tool_name=tool_name,
            )

        resolved_kwargs = self._prepare_arguments(fn, arguments, context=context, vault=vault)
        session_id = context.session_id if context else "default"

        if inspect.iscoroutinefunction(fn):
            raw_result = await fn(**resolved_kwargs)
        else:
            raw_result = fn(**resolved_kwargs)

        return self._resanitise_result(raw_result, vault=vault, session_id=session_id)

    def invoke_sync(
        self,
        tool_name: str,
        allowed_tools: Iterable[str],
        arguments: Mapping[str, Any],
        context: RunContext[Any] | None = None,
        vault: Any | None = None,
    ) -> Any:
        """Synchronously invoke a whitelisted tool with physical tool gating.

        Raises SecurityViolationError (BLK-SEC-001) if tool is unpermitted or unknown.
        """
        allowed_set = frozenset(allowed_tools)
        if tool_name not in allowed_set:
            raise SecurityViolationError(
                f"Tool '{tool_name}' is not permitted by active stage whitelist",
                code="BLK-SEC-001",
                tool_name=tool_name,
            )

        fn = self._tools.get(tool_name)
        if fn is None:
            raise SecurityViolationError(
                f"Tool '{tool_name}' is unknown or not registered",
                code="BLK-SEC-001",
                tool_name=tool_name,
            )

        if inspect.iscoroutinefunction(fn):
            raise TypeError(
                f"Tool '{tool_name}' is an asynchronous coroutine function; use invoke() instead"
            )

        resolved_kwargs = self._prepare_arguments(fn, arguments, context=context, vault=vault)
        session_id = context.session_id if context else "default"
        raw_result = fn(**resolved_kwargs)
        return self._resanitise_result(raw_result, vault=vault, session_id=session_id)


__all__: list[str] = [
    "RunContext",
    "ToolGatekeeper",
]
