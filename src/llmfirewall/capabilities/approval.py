"""Interfaces and providers for human-in-the-loop and automated action approval gates."""

from abc import ABC, abstractmethod
from typing import Callable, Dict, Optional
import time

from llmfirewall.capabilities.models import ActionRequest, ApprovalRequest


class ApprovalProvider(ABC):
    """Abstract interface for human-in-the-loop or policy approval providers."""

    @abstractmethod
    def request_approval(self, request: ApprovalRequest) -> bool:
        """Present or evaluate approval request. Return True if approved, False otherwise."""
        pass


class DenyAllApprovalProvider(ApprovalProvider):
    """Default secure fallback when no interactive approval provider is attached (Non-interactive mode)."""

    def request_approval(self, request: ApprovalRequest) -> bool:
        # Strict invariant: If approval is required but no human provider is present, default to DENY
        return False


class CallbackApprovalProvider(ApprovalProvider):
    """Approval provider delegating approval decisions to a registered user callback."""

    def __init__(self, callback: Callable[[ApprovalRequest], bool]) -> None:
        self.callback = callback

    def request_approval(self, request: ApprovalRequest) -> bool:
        try:
            return bool(self.callback(request))
        except Exception:
            return False


class MemoryApprovalProvider(ApprovalProvider):
    """Interactive / programmatic approval provider caching decisions in memory for tests or administrative APIs."""

    def __init__(self) -> None:
        self._pre_approved_actions: Dict[str, ApprovalRequest] = {}  # action_id -> ApprovalRequest

    def pre_approve(
        self,
        action_id: str,
        agent_id: str,
        capability_name: str,
        resource: Optional[str] = None,
        approved_by: str = "security_admin",
        ttl_seconds: float = 300.0,
    ) -> ApprovalRequest:
        """Register a pre-authorized approval bound specifically to an action and resource."""
        req = ApprovalRequest(
            action_id=action_id,
            agent_id=agent_id,
            capability_name=capability_name,
            resource=resource,
            approved=True,
            approved_by=approved_by,
            expires_at=time.time() + ttl_seconds,
        )
        self._pre_approved_actions[action_id] = req
        return req

    def request_approval(self, request: ApprovalRequest) -> bool:
        cached = self._pre_approved_actions.get(request.action_id)
        if not cached:
            return False

        if cached.is_expired():
            del self._pre_approved_actions[request.action_id]
            return False

        # Verify strict binding
        if (
            cached.agent_id == request.agent_id
            and cached.capability_name == request.capability_name
            and cached.resource == request.resource
        ):
            request.approved = True
            request.approved_by = cached.approved_by
            # Remove to enforce single-use / replay prevention
            del self._pre_approved_actions[request.action_id]
            return True

        return False
