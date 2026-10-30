"""Multi-step IT Support & Operations Agent protected by LLMFirewall Phase 3.

Demonstrates cross-step security correlation across:
1. User prompt scanning.
2. Retrieved knowledge base (RAG) context verification.
3. Pre-execution scoped tool authorization (@fw.protect_tool).
4. Tool output inspection and taint propagation.
5. Strict tenant boundary isolation.
"""

from typing import Any, Dict, List, Optional

from llmfirewall import (
    Action,
    CrossTenantViolationError,
    Firewall,
    ScopedPermission,
    ToolAuthorizationError,
    WorkflowCancelledError,
    WorkflowExpiredError,
    WorkflowSecurityContext,
    WorkflowSecurityError,
    WorkflowThreatState,
)


class SupportOperationsAgent:
    """Enterprise AI support agent with multi-step cross-step security enforcement."""

    def __init__(self, firewall: Optional[Firewall] = None) -> None:
        self.fw = firewall or Firewall()
        # Mock operational datastores
        self._user_accounts = {
            "user_101": {"name": "Alice Smith", "role": "engineer", "status": "active"},
            "user_102": {"name": "Bob Jones", "role": "sales", "status": "suspended"},
        }
        self._system_services = {
            "web_gateway": "running",
            "payment_processor": "running",
            "cache_layer": "running",
        }

    def start_session(
        self,
        tenant_id: str,
        workflow_id: Optional[str] = None,
        agent_id: str = "it_support_bot",
    ) -> WorkflowSecurityContext:
        """Initialize a protected multi-step workflow context with granular permissions."""
        return self.fw.create_workflow(
            tenant_id=tenant_id,
            workflow_id=workflow_id,
            agent_id=agent_id,
            scoped_permissions={
                "lookup_user": ScopedPermission(
                    tool_name="lookup_user",
                    allowed_actions=["query"],
                    allowed_resources=["*"],
                ),
                "restart_service": ScopedPermission(
                    tool_name="restart_service",
                    allowed_actions=["restart"],
                    denied_actions=["shutdown", "delete", "destroy"],
                    allowed_resources=["web_gateway", "cache_layer"],
                    denied_resources=["payment_processor"],
                    requires_clean_workflow=True,
                ),
            },
            allowed_tools=["lookup_user", "restart_service", "search_kb"],
            max_steps=20,
            max_tool_calls=10,
        )

    def process_user_query(
        self,
        workflow_id: str,
        tenant_id: str,
        prompt: str,
    ) -> Dict[str, Any]:
        """Boundary 1: Scan user prompt before LLM reasoning."""
        res = self.fw.cross_step_enforcer.enforce_prompt(
            workflow_id=workflow_id,
            prompt=prompt,
            tenant_id=tenant_id,
        )
        if res.is_blocked:
            return {"status": "blocked", "message": f"Prompt blocked: {res.decision.reason}"}
        return {"status": "allowed", "processed_text": res.processed_text}

    def retrieve_context(
        self,
        workflow_id: str,
        tenant_id: str,
        documents: List[str],
    ) -> Dict[str, Any]:
        """Boundary 2: Scan retrieved RAG documents for indirect injections before prompt construction."""
        rag_dec = self.fw.cross_step_enforcer.enforce_rag(
            workflow_id=workflow_id,
            chunks=documents,
            tenant_id=tenant_id,
        )
        return {
            "action": rag_dec.action.value,
            "secured_chunks": [it.content for it in rag_dec.approved_items],
            "quarantined_count": len(rag_dec.quarantined_items),
        }

    def lookup_user(
        self,
        workflow_id: str,
        tenant_id: str,
        user_id: str,
    ) -> Dict[str, Any]:
        """Boundary 3: Execute read-only user query tool."""
        # Pre-execution authorization check
        self.fw.check_tool_call(
            tool_call_or_name="lookup_user",
            arguments={"action": "query", "user_id": user_id},
            workflow_id=workflow_id,
            tenant_id=tenant_id,
        )

        user = self._user_accounts.get(user_id)
        result_text = str(user) if user else "User not found"

        # Boundary 4: Inspect tool output
        self.fw.check_tool_result(
            tool_result_or_name="lookup_user",
            output=result_text,
            workflow_id=workflow_id,
            tenant_id=tenant_id,
        )

        return {"user": user}

    def restart_service(
        self,
        workflow_id: str,
        tenant_id: str,
        service_name: str,
    ) -> Dict[str, Any]:
        """Boundary 3: Execute privileged operational tool."""
        # Pre-execution authorization check (enforces clean workflow and resource whitelist)
        self.fw.check_tool_call(
            tool_call_or_name="restart_service",
            arguments={"action": "restart", "service": service_name},
            workflow_id=workflow_id,
            tenant_id=tenant_id,
        )

        # Execute restart
        if service_name in self._system_services:
            self._system_services[service_name] = "restarted"
            return {"status": "success", "service": service_name, "state": "restarted"}
        return {"status": "error", "message": f"Service '{service_name}' not found"}
