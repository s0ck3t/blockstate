"""Two-Pass StatechartEngine turn loop and deterministic coordinator.

Orchestrates the entire conversational turn lifecycle:
- Distributed session lease acquisition (StorageBackend.acquire_lease)
- Post-lease ingress PIIVault.sanitise()
- Pass 1 fast semantic extraction (< 100ms) with on_refusal circuit breaking
- Core Resolution (<= 5ms): Step 2a Delta-hydration & max_turns enforcement,
  Step 2b Scoped tool execution, Step 2c Pure stage guard evaluation
- Pass 2 deterministic template/ChoicePayload/renderer rendering
- Pop-after-render digression TaskFrame cleanup
- Single-owner commit_turn() computing synchronous RFC 8785 JCS SHA-256
  TurnLedgerRecord chains with AES-256-GCM AAD vault encryption
"""

import contextlib
import hashlib
import inspect
import json
from datetime import UTC, datetime
from typing import Any

from blockstate.core.agent import Agent
from blockstate.core.gatekeeper import RunContext
from blockstate.core.slots import SlotHydrator
from blockstate.core.stack import (
    ReadOnlySessionView,
    SessionState,
    TaskFrame,
    TaskStack,
)
from blockstate.core.transitions import ChoicePayload, Transition
from blockstate.errors import (
    SecurityViolationError,
)
from blockstate.ports.ledger import LedgerSink, TurnLedgerRecord
from blockstate.ports.models import ExtractionResult, IntentClassifier, ResponseRenderer
from blockstate.ports.storage import (
    LeaseHandle,
    SessionCheckpoint,
    StorageBackend,
    TurnEnvelope,
)
from blockstate.ports.wire import (
    BlockstateTurnAborted,
    BlockstateTurnComplete,
    BlockstateTurnYield,
)
from blockstate.security.vault import PIIVault


def _canonical_jcs(data: Any) -> bytes:
    """Serialise a dictionary into RFC 8785 JSON Canonicalisation Scheme bytes."""
    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256_digest(data: bytes | str) -> str:
    """Compute SHA-256 hexadecimal digest for raw bytes or string payload."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


class StatechartEngine:
    """Deterministic two-pass statechart runtime engine and turn coordinator."""

    def __init__(
        self,
        agent: Agent,
        storage: StorageBackend,
        classifier: IntentClassifier | None = None,
        renderer: ResponseRenderer | None = None,
        ledger_sink: LedgerSink | None = None,
        vault: PIIVault | None = None,
        pass1_timeout_ms: int = 100,
        refusal_threshold: int = 1,
        max_turns_default: int = 5,
    ) -> None:
        self.agent = agent
        self.storage = storage
        self.classifier = classifier
        self.renderer = renderer
        self.ledger_sink = ledger_sink
        self.vault = vault or PIIVault()
        self.pass1_timeout_ms = pass1_timeout_ms
        self.refusal_threshold = refusal_threshold
        self.max_turns_default = max_turns_default

    async def step(
        self,
        envelope: TurnEnvelope,
    ) -> BlockstateTurnYield | BlockstateTurnComplete[Any] | BlockstateTurnAborted:
        """Execute a single conversational turn through the two-pass statechart pipeline."""
        session_id = envelope.session_id
        lease = await self.storage.acquire_lease(session_id)

        try:
            return await self._execute_turn(envelope, lease)
        finally:
            # Ensure lease is released if not already released during commit
            with contextlib.suppress(Exception):
                await self.storage.release_lease(lease)

    async def _execute_turn(
        self,
        envelope: TurnEnvelope,
        lease: LeaseHandle,
    ) -> BlockstateTurnYield | BlockstateTurnComplete[Any] | BlockstateTurnAborted:
        session_id = envelope.session_id
        checkpoint = await self.storage.load_checkpoint(session_id)

        # 1. Checkpoint & Session Initialisation
        schema_version = checkpoint.schema_version if checkpoint else 1
        revision_id = checkpoint.revision_id if checkpoint else 0
        turn_index = envelope.turn_index

        session_state = SessionState()
        if checkpoint is not None:
            session_state.update(checkpoint.state)
        elif envelope.initial_context:
            session_state.update(envelope.initial_context)

        # Reconstruct TaskStack
        task_stack = TaskStack(max_stack_depth=6)
        if checkpoint is not None and checkpoint.task_stack:
            for frame_dict in checkpoint.task_stack:
                stage_name = str(frame_dict.get("stage_id", ""))
                stage_def = self.agent.get_stage(stage_name)
                frame = TaskFrame(
                    stage_id=stage_name,
                    target_model=stage_def.collect,
                    slots=dict(frame_dict.get("slots", {})),
                    locked_slots=set(frame_dict.get("locked_slots", ())),
                    allow_slot_overrides=stage_def.allow_slot_overrides,
                    turn_count=int(frame_dict.get("turn_count", 0)),
                    max_turns=stage_def.max_turns,
                    allowed_tools=frozenset(stage_def.tools),
                    allowed_digressions=frozenset(stage_def.allow_digressions),
                )
                task_stack.push(frame)
        else:
            initial_stage_name = self.agent.initial_stage
            if initial_stage_name is None:
                return BlockstateTurnAborted(
                    session_id=session_id,
                    error_code="BLK-CFG-002",
                    reason="Agent has no registered initial stage",
                )
            root_def = self.agent.get_stage(initial_stage_name)
            root_frame = TaskFrame(
                stage_id=initial_stage_name,
                target_model=root_def.collect,
                slots={},
                locked_slots=set(),
                allow_slot_overrides=root_def.allow_slot_overrides,
                turn_count=0,
                max_turns=root_def.max_turns,
                allowed_tools=frozenset(root_def.tools),
                allowed_digressions=frozenset(root_def.allow_digressions),
            )
            task_stack.push(root_frame)

        # Ingress Decryption of vault_map
        if checkpoint is not None and checkpoint.vault_map:
            aad = f"{session_id}:{schema_version}:{revision_id}"
            try:
                decrypted_vault = self.vault.cipher.decrypt_vault_map(
                    checkpoint.vault_map,
                    aad=aad,
                )
                self.vault._session_tokens[session_id] = decrypted_vault
            except Exception:
                pass

        # Ingress PIIVault Sanitisation
        sanitised_payload = self.vault.sanitise_sync(
            envelope.user_message,
            session_id=session_id,
        )
        vaulted_message = sanitised_payload.sanitised_text

        active_frame = task_stack.top
        if active_frame is None:
            return BlockstateTurnAborted(
                session_id=session_id,
                error_code="BLK-SEC-003",
                reason="TaskStack is empty",
            )

        active_stage_name = active_frame.stage_id
        stage_def = self.agent.get_stage(active_stage_name)
        stage_from = active_stage_name

        # 2. Pass 1: Semantic Intent Classification & Candidate Extraction
        delta_schema: dict[str, Any] = {}
        if active_frame.target_model is not None:
            delta_schema = active_frame.target_model.model_json_schema()

        extraction: ExtractionResult
        if self.classifier is not None:
            extraction = await self.classifier.extract(
                vaulted_message,
                delta_schema,
                timeout_ms=self.pass1_timeout_ms,
            )
        else:
            extraction = ExtractionResult(
                intent=active_stage_name,
                candidate_slots={},
                is_refusal=False,
            )

        # Refusal Circuit Breaker
        if extraction.is_refusal:
            if stage_def.on_refusal:
                target_stage_name = stage_def.on_refusal
                active_frame.stage_id = target_stage_name
                return await self._commit_and_yield(
                    session_id=session_id,
                    envelope=envelope,
                    lease=lease,
                    checkpoint=checkpoint,
                    session_state=session_state,
                    task_stack=task_stack,
                    stage_from=stage_from,
                    stage_to=target_stage_name,
                    guard_outcome="refusal",
                    rendered_message=f"Refusal circuit broken; routing to {target_stage_name}",
                    choices=None,
                    missing_slots=(),
                )
            return BlockstateTurnAborted(
                session_id=session_id,
                error_code="BLK-MOD-002",
                reason="Model safety refusal triggered without declared on_refusal target",
            )

        # 3. Core Resolution (<= 5ms)
        # Turn count enforcement
        turn_count = active_frame.turn_count + 1
        active_frame.turn_count = turn_count
        max_turns = active_frame.max_turns

        if max_turns is not None and max_turns > 0 and turn_count > max_turns:
            if stage_def.on_max_turns_exceeded:
                target_stage_name = stage_def.on_max_turns_exceeded
                active_frame.stage_id = target_stage_name
                return await self._commit_and_yield(
                    session_id=session_id,
                    envelope=envelope,
                    lease=lease,
                    checkpoint=checkpoint,
                    session_state=session_state,
                    task_stack=task_stack,
                    stage_from=stage_from,
                    stage_to=target_stage_name,
                    guard_outcome="max_turns_exceeded",
                    rendered_message="Maximum turn budget exceeded.",
                    choices=None,
                    missing_slots=(),
                )
            return BlockstateTurnAborted(
                session_id=session_id,
                error_code="BLK-MOD-003",
                reason=f"Stage '{active_stage_name}' exceeded maximum turn budget of {max_turns}",
            )

        # Permitted Digression check
        if extraction.intent in stage_def.allow_digressions:
            digression_stage_def = self.agent.get_stage(extraction.intent)
            child_frame = TaskFrame(
                stage_id=digression_stage_def.name,
                target_model=digression_stage_def.collect,
                slots={},
                locked_slots=set(),
                allow_slot_overrides=digression_stage_def.allow_slot_overrides,
                turn_count=0,
                max_turns=digression_stage_def.max_turns,
                allowed_tools=frozenset(digression_stage_def.tools),
                allowed_digressions=frozenset(digression_stage_def.allow_digressions),
            )
            task_stack.push(child_frame)
            active_frame = child_frame
            stage_def = digression_stage_def

        # Step 2a: Slot Delta Hydration
        hydration_res: Any = None
        missing_slots: tuple[str, ...] = ()
        if active_frame.target_model is not None:
            hydrator = SlotHydrator(
                active_frame.target_model,
                vault=self.vault,
            )
            candidates = extraction.candidate_slots or {}
            hydration_res = hydrator.hydrate(
                active_frame,
                candidates,
            )
            missing_slots = tuple(sorted(hydration_res.delta))

            if hydration_res.is_breach and stage_def.on_breach:
                target_stage_name = stage_def.on_breach
                active_frame.stage_id = target_stage_name
                return await self._commit_and_yield(
                    session_id=session_id,
                    envelope=envelope,
                    lease=lease,
                    checkpoint=checkpoint,
                    session_state=session_state,
                    task_stack=task_stack,
                    stage_from=stage_from,
                    stage_to=target_stage_name,
                    guard_outcome="breach",
                    rendered_message="Validation breach triggered.",
                    choices=None,
                    missing_slots=missing_slots,
                )

        # Step 2b: Tool Execution on Delta = 0
        if len(missing_slots) == 0 and stage_def.tools:
            tool_ctx = RunContext(
                deps=None,
                session_id=session_id,
                turn_index=turn_index,
                session=ReadOnlySessionView.create(
                    session_id=session_id,
                    state=session_state.to_dict(),
                    current_stage=active_frame.stage_id,
                    stack_depth=len(task_stack),
                ),
                vault=self.vault,
            )
            # Execute any whitelisted tool associated with stage
            for tool_name in stage_def.tools:
                try:
                    await self.agent.gatekeeper.invoke(
                        tool_name=tool_name,
                        allowed_tools=stage_def.tools,
                        arguments=active_frame.slots,
                        context=tool_ctx,
                        vault=self.vault,
                    )
                except SecurityViolationError as sec_err:
                    if stage_def.on_security_violation:
                        target_stage_name = stage_def.on_security_violation
                        active_frame.stage_id = target_stage_name
                        return await self._commit_and_yield(
                            session_id=session_id,
                            envelope=envelope,
                            lease=lease,
                            checkpoint=checkpoint,
                            session_state=session_state,
                            task_stack=task_stack,
                            stage_from=stage_from,
                            stage_to=target_stage_name,
                            guard_outcome="security_violation",
                            rendered_message="Security violation detected.",
                            choices=None,
                            missing_slots=(),
                        )
                    return BlockstateTurnAborted(
                        session_id=session_id,
                        error_code=sec_err.code,
                        reason=sec_err.message,
                    )

        # Step 2c: Pure Python Stage Guard Evaluation
        guard_directive = Transition.stay()
        session_view = ReadOnlySessionView.create(
            session_id=session_id,
            state=session_state.to_dict(),
            current_stage=active_frame.stage_id,
            stack_depth=len(task_stack),
        )

        slots_to_pass: Any = active_frame.slots
        if (
            active_frame.target_model is not None
            and hydration_res is not None
            and hydration_res.target_model_instance is not None
        ):
            slots_to_pass = hydration_res.target_model_instance

        if len(missing_slots) == 0:
            if stage_def.handler is not None:
                sig = inspect.signature(stage_def.handler)
                handler_args: dict[str, Any] = {}
                for p_name, param in sig.parameters.items():
                    if (
                        p_name in ("session", "session_view")
                        or param.annotation is ReadOnlySessionView
                    ):
                        handler_args[p_name] = session_view
                    elif p_name in ("slots", "data") or (
                        active_frame.target_model
                        and param.annotation is active_frame.target_model
                    ):
                        handler_args[p_name] = slots_to_pass

                ret: Any
                if inspect.iscoroutinefunction(stage_def.handler):
                    ret = await stage_def.handler(self.agent, **handler_args)
                else:
                    ret = stage_def.handler(self.agent, **handler_args)

                if isinstance(ret, Transition):
                    guard_directive = ret

            # Evaluate attached stage guards
            for guard_fn in stage_def.guards:
                sig = inspect.signature(guard_fn)
                guard_kwargs: dict[str, Any] = {}
                for p_name, param in sig.parameters.items():
                    if (
                        p_name in ("session", "session_view")
                        or param.annotation is ReadOnlySessionView
                    ):
                        guard_kwargs[p_name] = session_view
                    elif p_name in ("slots", "data") or (
                        active_frame.target_model
                        and param.annotation is active_frame.target_model
                    ):
                        guard_kwargs[p_name] = slots_to_pass

                guard_ret: Any
                if inspect.iscoroutinefunction(guard_fn):
                    guard_ret = await guard_fn(self.agent, **guard_kwargs)
                else:
                    guard_ret = guard_fn(self.agent, **guard_kwargs)

                if isinstance(guard_ret, Transition) and not guard_ret.is_stay:
                    guard_directive = guard_ret
                    break

        # Check for mutation propagation on pop
        pop_after_render = False
        if guard_directive.is_pop:
            pop_after_render = True
            if guard_directive.mutation and len(task_stack) > 1:
                parent_frame = task_stack.frames[-2]
                parent_frame.apply_child_mutation(guard_directive.mutation)

        target_stage_name = active_frame.stage_id
        if guard_directive.target:
            target_stage_name = guard_directive.target
            active_frame.stage_id = target_stage_name
            target_stage_def = self.agent.get_stage(target_stage_name)
            if target_stage_def.terminal and target_stage_def.handler is not None:
                sig = inspect.signature(target_stage_def.handler)
                terminal_args: dict[str, Any] = {}
                for p_name, param in sig.parameters.items():
                    if (
                        p_name in ("session", "session_view")
                        or param.annotation is ReadOnlySessionView
                    ):
                        terminal_args[p_name] = session_view
                    elif p_name in ("slots", "data") or (
                        active_frame.target_model
                        and param.annotation is active_frame.target_model
                    ):
                        terminal_args[p_name] = slots_to_pass

                term_ret: Any
                if inspect.iscoroutinefunction(target_stage_def.handler):
                    term_ret = await target_stage_def.handler(self.agent, **terminal_args)
                else:
                    term_ret = target_stage_def.handler(self.agent, **terminal_args)

                if isinstance(term_ret, Transition):
                    guard_directive = term_ret

            stage_def = target_stage_def

        # 4. Pass 2: Response Rendering
        rendered_message = ""
        choice_payload: ChoicePayload | None = stage_def.choice_options

        if stage_def.canned_response:
            rendered_message = stage_def.canned_response
        elif choice_payload is not None:
            rendered_message = choice_payload.prompt
        elif self.renderer is not None:
            render_ctx = {"slots": active_frame.slots, "session": session_state.to_dict()}
            rendered_message = await self.renderer.render(
                active_frame.stage_id,
                render_ctx,
            )
        else:
            rendered_message = f"Active stage: {active_frame.stage_id}"

        # 5. Pop completed digression frame after Pass 2 render
        if pop_after_render:
            task_stack.pop()
            if task_stack.top:
                target_stage_name = task_stack.top.stage_id

        # 6. Commit Turn
        guard_outcome = "transition"
        if guard_directive.is_end:
            guard_outcome = "end"
        elif guard_directive.is_pop:
            guard_outcome = "pop"
        elif guard_directive.is_stay:
            guard_outcome = "stay"

        if guard_directive.is_end or stage_def.terminal:
            return await self._commit_and_complete(
                session_id=session_id,
                envelope=envelope,
                lease=lease,
                checkpoint=checkpoint,
                session_state=session_state,
                task_stack=task_stack,
                stage_from=stage_from,
                stage_to=target_stage_name,
                guard_outcome="end",
                result=(
                    guard_directive.result
                    or {"status": "completed", "slots": active_frame.slots}
                ),
                rendered_message=rendered_message,
            )

        return await self._commit_and_yield(
            session_id=session_id,
            envelope=envelope,
            lease=lease,
            checkpoint=checkpoint,
            session_state=session_state,
            task_stack=task_stack,
            stage_from=stage_from,
            stage_to=target_stage_name,
            guard_outcome=guard_outcome,
            rendered_message=rendered_message,
            choices=choice_payload.options if choice_payload else None,
            missing_slots=missing_slots,
        )

    async def _commit_turn(
        self,
        session_id: str,
        envelope: TurnEnvelope,
        lease: LeaseHandle,
        checkpoint: SessionCheckpoint | None,
        session_state: SessionState,
        task_stack: TaskStack,
        stage_from: str,
        stage_to: str,
        guard_outcome: str,
        rendered_message: str,
    ) -> tuple[SessionCheckpoint, str]:
        """Atomically commit turn state, encrypting vault_map and generating TurnLedgerRecord."""
        schema_version = checkpoint.schema_version if checkpoint else 1
        new_revision_id = (checkpoint.revision_id + 1) if checkpoint else 1
        turn_index = envelope.turn_index
        prev_record_hash = (checkpoint.last_ledger_hash if checkpoint else "") or ("0" * 64)

        active_frame = task_stack.top
        exposed_tools = tuple(active_frame.allowed_tools) if active_frame else ()

        prompt_hash = _sha256_digest(rendered_message)
        input_hash = _sha256_digest(envelope.user_message)
        output_hash = _sha256_digest(rendered_message)
        now_utc = datetime.now(UTC).isoformat()

        ledger_payload = {
            "exposed_tools": list(exposed_tools),
            "guard_outcome": guard_outcome,
            "prev_record_hash": prev_record_hash,
            "prompt_hash": prompt_hash,
            "session_id": session_id,
            "stage_from": stage_from,
            "stage_to": stage_to,
            "timestamp_utc": now_utc,
            "turn_index": turn_index,
            "vaulted_input_hash": input_hash,
            "vaulted_output_hash": output_hash,
        }
        canonical_jcs = _canonical_jcs(ledger_payload)
        record_hash = _sha256_digest(canonical_jcs)

        record = TurnLedgerRecord(
            prev_record_hash=prev_record_hash,
            session_id=session_id,
            turn_index=turn_index,
            stage_from=stage_from,
            stage_to=stage_to,
            exposed_tools=exposed_tools,
            prompt_hash=prompt_hash,
            vaulted_input_hash=input_hash,
            vaulted_output_hash=output_hash,
            guard_outcome=guard_outcome,
            timestamp_utc=now_utc,
            record_hash=record_hash,
        )

        if self.ledger_sink is not None:
            await self.ledger_sink.append(record)

        # Encrypt vault map with Associated Authenticated Data (AAD)
        aad = f"{session_id}:{schema_version}:{new_revision_id}"
        vault_tokens = self.vault._session_tokens.get(session_id, {})
        encrypted_vault_map = self.vault.cipher.encrypt_vault_map(vault_tokens, aad=aad)

        # Serialise TaskStack
        serialized_stack: list[dict[str, Any]] = [
            {
                "stage_id": f.stage_id,
                "slots": dict(f.slots),
                "locked_slots": list(f.locked_slots),
                "turn_count": f.turn_count,
            }
            for f in task_stack
        ]

        new_checkpoint = SessionCheckpoint(
            session_id=session_id,
            schema_version=schema_version,
            revision_id=new_revision_id,
            state=session_state.to_dict(),
            task_stack=tuple(serialized_stack),
            last_ledger_hash=record_hash,
            pending_ledger_outbox=(),
            vault_map=encrypted_vault_map,
            created_at=checkpoint.created_at if checkpoint else now_utc,
            updated_at=now_utc,
        )

        await self.storage.save_checkpoint(new_checkpoint, lease)
        return new_checkpoint, record_hash

    async def _commit_and_yield(
        self,
        session_id: str,
        envelope: TurnEnvelope,
        lease: LeaseHandle,
        checkpoint: SessionCheckpoint | None,
        session_state: SessionState,
        task_stack: TaskStack,
        stage_from: str,
        stage_to: str,
        guard_outcome: str,
        rendered_message: str,
        choices: Any | None,
        missing_slots: tuple[str, ...],
    ) -> BlockstateTurnYield:
        """Commit turn state atomically and return BlockstateTurnYield wire DTO."""
        await self._commit_turn(
            session_id=session_id,
            envelope=envelope,
            lease=lease,
            checkpoint=checkpoint,
            session_state=session_state,
            task_stack=task_stack,
            stage_from=stage_from,
            stage_to=stage_to,
            guard_outcome=guard_outcome,
            rendered_message=rendered_message,
        )
        return BlockstateTurnYield(
            session_id=session_id,
            state="in_progress",
            message=rendered_message,
            choices=choices,
            missing_slots=missing_slots,
        )

    async def _commit_and_complete(
        self,
        session_id: str,
        envelope: TurnEnvelope,
        lease: LeaseHandle,
        checkpoint: SessionCheckpoint | None,
        session_state: SessionState,
        task_stack: TaskStack,
        stage_from: str,
        stage_to: str,
        guard_outcome: str,
        result: Any,
        rendered_message: str,
    ) -> BlockstateTurnComplete[Any]:
        """Commit turn state atomically and return BlockstateTurnComplete wire DTO."""
        _, record_hash = await self._commit_turn(
            session_id=session_id,
            envelope=envelope,
            lease=lease,
            checkpoint=checkpoint,
            session_state=session_state,
            task_stack=task_stack,
            stage_from=stage_from,
            stage_to=stage_to,
            guard_outcome=guard_outcome,
            rendered_message=rendered_message,
        )
        return BlockstateTurnComplete(
            session_id=session_id,
            state="completed",
            result=result,
            ledger_head_hash=record_hash,
        )


__all__: list[str] = [
    "StatechartEngine",
]
