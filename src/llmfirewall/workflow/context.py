"""Thread-safe, tenant-isolated workflow context manager and storage coordinator.

Phase 3: Cross-Step Agent Security.
Guarantees:
- Strict tenant boundary enforcement (cross-tenant lookup is rejected).
- Monotonic concurrency isolation via per-manager locks.
- Bounded in-memory LRU tracking preventing memory leaks.
- Fail-closed storage error handling (disk/database errors reject execution).
- Pluggable backing persistence via LLMFirewall's persistence layer.
"""

from __future__ import annotations

import collections
import json
import logging
import threading
import time
from typing import Any, Dict, List, Optional

from llmfirewall.persistence.base import BasePersistenceAdapter
from llmfirewall.persistence.models import PersistenceRecord
from llmfirewall.workflow.models import (
    CrossTenantViolationError,
    ScopedPermission,
    WorkflowCancelledError,
    WorkflowExpiredError,
    WorkflowSecurityContext,
    WorkflowSecurityError,
    WorkflowStatus,
    WorkflowThreatState,
)

logger = logging.getLogger("llmfirewall.workflow.context")


class WorkflowContextManager:
    """Coordinates lifecycle, tenant-isolated lookup, and thread-safe persistence of workflow contexts."""

    def __init__(
        self,
        store: Optional[BasePersistenceAdapter] = None,
        max_in_memory: int = 1000,
    ) -> None:
        """
        Args:
            store: Optional persistence store (MemoryStore, SQLiteStore, JSONLStore).
            max_in_memory: Maximum concurrent workflows kept in active memory.
        """
        self._store = store
        self._max_in_memory = max_in_memory
        self._lock = threading.RLock()
        self._active_contexts: collections.OrderedDict[str, WorkflowSecurityContext] = collections.OrderedDict()

    def create_workflow(
        self,
        tenant_id: str,
        workflow_id: Optional[str] = None,
        agent_id: str = "default_agent",
        session_id: Optional[str] = None,
        scoped_permissions: Optional[Dict[str, ScopedPermission]] = None,
        allowed_tools: Optional[List[str]] = None,
        denied_tools: Optional[List[str]] = None,
        max_steps: int = 50,
        max_tool_calls: int = 30,
        ttl_seconds: float = 3600.0,
        idle_timeout_seconds: float = 300.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> WorkflowSecurityContext:
        """Initialize and persist a new cross-step workflow security context."""
        if not tenant_id or not tenant_id.strip():
            raise ValueError("tenant_id must be a non-empty string for workflow security isolation.")

        ctx = WorkflowSecurityContext(
            workflow_id=workflow_id or f"wf-{time.time_ns():x}",
            tenant_id=tenant_id.strip(),
            agent_id=agent_id.strip() if agent_id else "default_agent",
            session_id=session_id,
            scoped_permissions=scoped_permissions or {},
            allowed_tools=allowed_tools,
            denied_tools=denied_tools or [],
            max_steps=max_steps,
            max_tool_calls=max_tool_calls,
            ttl_seconds=ttl_seconds,
            idle_timeout_seconds=idle_timeout_seconds,
            metadata=metadata or {},
        )

        with self._lock:
            # Enforce in-memory LRU bounds
            if len(self._active_contexts) >= self._max_in_memory:
                self._active_contexts.popitem(last=False)
            self._active_contexts[ctx.workflow_id] = ctx

            # Persist to backing store if configured
            if self._store is not None:
                try:
                    record = PersistenceRecord(
                        id=ctx.workflow_id,
                        record_type="workflow_context",
                        payload=ctx.model_dump(),
                        tenant_id=ctx.tenant_id,
                    )
                    self._store.save(record)
                except Exception as exc:
                    logger.error(f"Failed to persist workflow context {ctx.workflow_id}: {exc}")
                    raise WorkflowSecurityError(
                        f"Storage failure during workflow creation: {exc}",
                        workflow_id=ctx.workflow_id,
                        tenant_id=ctx.tenant_id,
                    ) from exc

        return ctx

    def get_workflow(
        self,
        workflow_id: str,
        tenant_id: str,
    ) -> WorkflowSecurityContext:
        """Retrieve an active workflow context, enforcing strict tenant isolation and expiration."""
        if not tenant_id or not tenant_id.strip():
            raise CrossTenantViolationError("tenant_id must be provided to access workflow context.")

        with self._lock:
            ctx = self._active_contexts.get(workflow_id)

            # Try restoring from persistence store if not in active memory
            if ctx is None and self._store is not None:
                try:
                    record = self._store.get(workflow_id)
                    if record is not None and record.record_type == "workflow_context":
                        payload = record.payload
                        if isinstance(payload, str):
                            payload = json.loads(payload)
                        ctx = WorkflowSecurityContext(**payload)
                        self._active_contexts[workflow_id] = ctx
                except Exception as exc:
                    logger.error(f"Storage retrieval error for workflow {workflow_id}: {exc}")
                    raise WorkflowSecurityError(
                        f"Storage failure: failing closed to prevent unauthorized operation: {exc}",
                        workflow_id=workflow_id,
                        tenant_id=tenant_id,
                    ) from exc

            if ctx is None:
                raise WorkflowSecurityError(
                    f"Workflow '{workflow_id}' not found or has been purged.",
                    workflow_id=workflow_id,
                    tenant_id=tenant_id,
                )

            # Enforce immutable tenant isolation
            ctx.assert_tenant(tenant_id)

            # Check expiration
            if ctx.is_expired():
                ctx.status = WorkflowStatus.TIMED_OUT
                self.update_workflow(ctx)
                raise WorkflowExpiredError(
                    f"Workflow '{workflow_id}' has expired (TTL {ctx.ttl_seconds}s or idle {ctx.idle_timeout_seconds}s exceeded).",
                    workflow_id=workflow_id,
                    tenant_id=tenant_id,
                )

            # Check explicit cancellation
            if ctx.status == WorkflowStatus.CANCELLED:
                raise WorkflowCancelledError(
                    f"Workflow '{workflow_id}' was cancelled: {ctx.cancellation_reason or 'No reason provided'}.",
                    workflow_id=workflow_id,
                    tenant_id=tenant_id,
                )

            # Refresh LRU position and touch timestamp
            self._active_contexts.move_to_end(workflow_id)
            ctx.touch()
            return ctx

    def update_workflow(self, context: WorkflowSecurityContext) -> None:
        """Persist state mutations back to active memory and backing store."""
        with self._lock:
            self._active_contexts[context.workflow_id] = context
            if self._store is not None:
                try:
                    record = PersistenceRecord(
                        id=context.workflow_id,
                        record_type="workflow_context",
                        payload=context.model_dump(),
                        tenant_id=context.tenant_id,
                    )
                    self._store.save(record)
                except Exception as exc:
                    logger.error(f"Failed to update workflow context {context.workflow_id}: {exc}")
                    raise WorkflowSecurityError(
                        f"Storage failure during context update: {exc}",
                        workflow_id=context.workflow_id,
                        tenant_id=context.tenant_id,
                    ) from exc

    def cancel_workflow(
        self,
        workflow_id: str,
        tenant_id: str,
        reason: str = "Explicit cancellation request",
    ) -> WorkflowSecurityContext:
        """Cancel an ongoing workflow and prevent any subsequent tool execution."""
        with self._lock:
            ctx = self.get_workflow(workflow_id, tenant_id)
            ctx.status = WorkflowStatus.CANCELLED
            ctx.cancellation_reason = reason
            self.update_workflow(ctx)
            return ctx

    def complete_workflow(
        self,
        workflow_id: str,
        tenant_id: str,
    ) -> WorkflowSecurityContext:
        """Mark a multi-step workflow as cleanly completed."""
        with self._lock:
            ctx = self.get_workflow(workflow_id, tenant_id)
            ctx.status = WorkflowStatus.COMPLETED
            self.update_workflow(ctx)
            return ctx

    def cleanup_expired_workflows(self) -> int:
        """Identify and transition expired workflows, pruning inactive contexts from active memory."""
        now = time.time()
        purged = 0
        with self._lock:
            for wid, ctx in list(self._active_contexts.items()):
                if ctx.is_expired(now):
                    ctx.status = WorkflowStatus.TIMED_OUT
                    del self._active_contexts[wid]
                    purged += 1
                    if self._store is not None:
                        try:
                            record = PersistenceRecord(
                                id=ctx.workflow_id,
                                record_type="workflow_context",
                                payload=ctx.model_dump(),
                                tenant_id=ctx.tenant_id,
                            )
                            self._store.save(record)
                        except Exception:
                            pass
        return purged

    def count(self, tenant_id: Optional[str] = None) -> int:
        """Return total active workflows in memory (optionally filtered by tenant)."""
        with self._lock:
            if tenant_id is None:
                return len(self._active_contexts)
            return sum(1 for c in self._active_contexts.values() if c.tenant_id == tenant_id)
