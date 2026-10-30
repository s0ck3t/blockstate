"""LangChain and LangGraph transactional compliance execution enclave adapter.

Exposes Declarative Control Grammar agents as LangChain-compatible tools via as_tool(),
isolating internal dispatch tables and mutable engine state while returning typed
BlockstateTurnYield, BlockstateTurnAborted, or BlockstateTurnComplete DTOs.
"""

import asyncio
import inspect
from collections.abc import Mapping
from typing import Any, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from blockstate.adapters.storage.memory import InMemoryStateStore
from blockstate.core.agent import Agent
from blockstate.core.engine import StatechartEngine
from blockstate.errors import BlockstateError
from blockstate.ports.storage import StorageBackend, TurnEnvelope
from blockstate.ports.wire import (
    BlockstateTurnAborted,
    BlockstateTurnComplete,
    BlockstateTurnYield,
)

T = TypeVar("T")


class EnclaveToolInput(BaseModel):
    """Input argument schema for Blockstate compliance execution enclave tools."""

    model_config = ConfigDict(extra="forbid")

    session_id: str = Field(
        default="default_session",
        description="Unique session identifier for the conversational compliance workflow.",
    )
    user_message: str = Field(
        default="",
        description="Inbound user utterance or directive to process within the enclave.",
    )
    initial_context: dict[str, Any] | None = Field(
        default=None,
        description="Optional initial session state context to seed the enclave.",
    )


class BlockstateEnclaveTool:
    """LangChain-compatible tool wrapper for a Blockstate compliance execution enclave.

    Enforces strict isolation between outer orchestrators (such as LangGraph) and the
    internal statechart engine. The outer orchestrator can only pass (session_id,
    user_message, initial_context) and receive the discriminated union of wire DTOs:
    - BlockstateTurnYield: Workflow requires further user input.
    - BlockstateTurnComplete: Workflow reached terminal completion with typed result.
    - BlockstateTurnAborted: Execution halted due to security violation or error.
    """

    def __init__(
        self,
        agent: Agent,
        *,
        name: str | None = None,
        description: str | None = None,
        storage: StorageBackend | None = None,
        engine: StatechartEngine | None = None,
        **engine_kwargs: Any,
    ) -> None:
        self._agent = agent
        self.name: str = name or agent.__class__.__name__
        self.description: str = (
            description
            or inspect.getdoc(agent.__class__)
            or f"Transactional compliance execution enclave for {self.name}."
        )
        self.args_schema: type[BaseModel] = EnclaveToolInput

        self._storage: StorageBackend = (
            storage or getattr(engine, "storage", None) or InMemoryStateStore()
        )
        if engine is not None:
            self._engine = engine
        else:
            self._engine = StatechartEngine(
                agent=self._agent,
                storage=self._storage,
                **engine_kwargs,
            )

    @property
    def enclave(self) -> Agent:
        """Access the underlying agent instance."""
        return self._agent

    async def ainvoke(
        self,
        input_data: dict[str, Any] | EnclaveToolInput | str,
        config: Any = None,
        **kwargs: Any,
    ) -> BlockstateTurnYield | BlockstateTurnComplete[Any] | BlockstateTurnAborted:
        """Asynchronously invoke the enclave tool with dictionary or model input."""
        if isinstance(input_data, str):
            raw_session_id = kwargs.get("session_id")
            session_id = raw_session_id if raw_session_id else "default_session"
            user_message = input_data
            initial_context = kwargs.get("initial_context")
        elif isinstance(input_data, EnclaveToolInput):
            session_id = input_data.session_id if input_data.session_id else "default_session"
            user_message = input_data.user_message
            initial_context = input_data.initial_context
        elif isinstance(input_data, dict):
            raw_session_id = input_data.get("session_id") or kwargs.get("session_id")
            session_id = str(raw_session_id) if raw_session_id else "default_session"
            user_message = str(input_data.get("user_message", kwargs.get("user_message", "")))
            initial_context = input_data.get("initial_context", kwargs.get("initial_context"))
        else:
            raw_session_id = kwargs.get("session_id")
            session_id = str(raw_session_id) if raw_session_id else "default_session"
            user_message = str(kwargs.get("user_message", ""))
            initial_context = kwargs.get("initial_context")

        return await self.arun(
            session_id=session_id,
            user_message=user_message,
            initial_context=initial_context,
        )

    def invoke(
        self,
        input_data: dict[str, Any] | EnclaveToolInput | str,
        config: Any = None,
        **kwargs: Any,
    ) -> BlockstateTurnYield | BlockstateTurnComplete[Any] | BlockstateTurnAborted:
        """Synchronously invoke the enclave tool."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is not None and loop.is_running():
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                fut = pool.submit(lambda: asyncio.run(self.ainvoke(input_data, config, **kwargs)))
                return fut.result()
        return asyncio.run(self.ainvoke(input_data, config, **kwargs))

    async def arun(
        self,
        session_id: str | None = None,
        user_message: str = "",
        initial_context: Mapping[str, Any] | None = None,
    ) -> BlockstateTurnYield | BlockstateTurnComplete[Any] | BlockstateTurnAborted:
        """Asynchronously execute a conversational turn within the enclave."""
        resolved_session_id = session_id if session_id else "default_session"
        try:
            checkpoint = await self._storage.load_checkpoint(resolved_session_id)
            turn_index = (checkpoint.revision_id + 1) if checkpoint else 1
            envelope = TurnEnvelope(
                session_id=resolved_session_id,
                turn_index=turn_index,
                user_message=user_message,
                initial_context=dict(initial_context or {}),
            )
            step_result = await self._engine.step(envelope)
            object.__setattr__(step_result, "_user_message", user_message)
            object.__setattr__(step_result, "_initial_context", dict(initial_context or {}))
            return step_result
        except BlockstateError as err:
            aborted = BlockstateTurnAborted(
                session_id=resolved_session_id,
                error_code=err.code,
                reason=err.message,
            )
            object.__setattr__(aborted, "_user_message", user_message)
            object.__setattr__(aborted, "_initial_context", dict(initial_context or {}))
            return aborted
        except Exception as exc:
            aborted_generic = BlockstateTurnAborted(
                session_id=resolved_session_id,
                error_code="BLK-GEN-001",
                reason=str(exc) or "Internal enclave execution error",
            )
            object.__setattr__(aborted_generic, "_user_message", user_message)
            object.__setattr__(aborted_generic, "_initial_context", dict(initial_context or {}))
            return aborted_generic

    def run(
        self,
        session_id: str | None = None,
        user_message: str = "",
        initial_context: Mapping[str, Any] | None = None,
    ) -> BlockstateTurnYield | BlockstateTurnComplete[Any] | BlockstateTurnAborted:
        """Synchronously execute a conversational turn within the enclave."""
        return self.invoke(
            {
                "session_id": session_id if session_id else "default_session",
                "user_message": user_message,
                "initial_context": dict(initial_context or {}),
            }
        )

    def __call__(
        self,
        session_id: str | None = None,
        user_message: str = "",
        initial_context: Mapping[str, Any] | None = None,
    ) -> BlockstateTurnYield | BlockstateTurnComplete[Any] | BlockstateTurnAborted:
        """Direct callable invocation."""
        return self.run(session_id, user_message, initial_context)

    # Dict-like access for backward compatibility with test_agent.py
    def __getitem__(self, key: str) -> Any:
        if key == "name":
            return self.name
        if key == "enclave":
            return self._agent
        if key == "description":
            return self.description
        if key == "args_schema":
            return self.args_schema
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key: str) -> bool:
        return key in ("name", "enclave", "description", "args_schema")


def as_tool(
    agent_or_cls: type[Agent] | Agent,
    name: str | None = None,
    description: str | None = None,
    *,
    storage: StorageBackend | None = None,
    engine: StatechartEngine | None = None,
    **kwargs: Any,
) -> BlockstateEnclaveTool:
    """Mount a Declarative Control Grammar Agent as a compliance execution enclave tool.

    Accepts an Agent class or instance, encapsulating its deterministic statechart,
    isolated ToolGatekeeper, and cryptographic TurnLedger behind a LangChain-compatible
    tool boundary.
    """
    if isinstance(agent_or_cls, type) and issubclass(agent_or_cls, Agent):
        agent_instance = agent_or_cls()
    elif isinstance(agent_or_cls, Agent):
        agent_instance = agent_or_cls
    else:
        raise TypeError(f"Expected Agent subclass or instance, got {type(agent_or_cls).__name__}")

    return BlockstateEnclaveTool(
        agent=agent_instance,
        name=name,
        description=description,
        storage=storage,
        engine=engine,
        **kwargs,
    )


async def run_as_subflow(
    agent_or_cls: type[Agent] | Agent,
    session_id: str | None = None,
    user_message: str = "",
    initial_context: Mapping[str, Any] | None = None,
    *,
    storage: StorageBackend | None = None,
    engine: StatechartEngine | None = None,
    **kwargs: Any,
) -> BlockstateTurnYield | BlockstateTurnComplete[Any] | BlockstateTurnAborted:
    """Execute a single conversational turn through an Agent sub-flow enclave.

    Convenience async helper returning the typed discriminated wire DTO.
    """
    tool = as_tool(agent_or_cls, storage=storage, engine=engine, **kwargs)
    return await tool.arun(
        session_id=session_id if session_id else "default_session",
        user_message=user_message,
        initial_context=initial_context,
    )


# Attach adapter methods to Agent base class
Agent.as_tool = as_tool  # type: ignore[assignment]
Agent.run_as_subflow = run_as_subflow  # type: ignore[assignment]


__all__: list[str] = [
    "BlockstateEnclaveTool",
    "EnclaveToolInput",
    "as_tool",
    "run_as_subflow",
]
