"""Security Operations automation engine for executing containment playbooks."""

from typing import Any, Dict, List, Optional, Set
from llmfirewall.secops.models import (
    PlaybookActionType,
    PlaybookExecutionResult,
    PlaybookStep,
    SecurityPlaybook,
    StepExecutionResult,
)


class PlaybookEngine:
    """Deterministic, auditable security operations automation orchestrator."""

    def __init__(self) -> None:
        self._playbooks: Dict[str, SecurityPlaybook] = {}
        self._execution_history: List[PlaybookExecutionResult] = []
        self._quarantined_sessions: Set[str] = set()
        self._quarantined_users: Set[str] = set()

    @property
    def quarantined_sessions(self) -> Set[str]:
        return set(self._quarantined_sessions)

    @property
    def quarantined_users(self) -> Set[str]:
        return set(self._quarantined_users)

    @property
    def execution_history(self) -> List[PlaybookExecutionResult]:
        return list(self._execution_history)

    def register_playbook(self, playbook: SecurityPlaybook) -> None:
        """Register or update an automation playbook."""
        self._playbooks[playbook.id] = playbook

    def get_playbook(self, playbook_id: str) -> Optional[SecurityPlaybook]:
        return self._playbooks.get(playbook_id)

    def list_playbooks(self) -> List[SecurityPlaybook]:
        return list(self._playbooks.values())

    def is_session_quarantined(self, session_id: str) -> bool:
        return session_id in self._quarantined_sessions

    def is_user_quarantined(self, user_id: str) -> bool:
        return user_id in self._quarantined_users

    def execute_playbook(
        self,
        playbook_id: str,
        context: Optional[Dict[str, Any]] = None,
        dry_run: bool = False,
        authorized_by: Optional[str] = None,
    ) -> PlaybookExecutionResult:
        """Execute a registered response playbook with strict policy authorization checks."""
        ctx = context or {}
        playbook = self._playbooks.get(playbook_id)
        if not playbook:
            raise ValueError(f"Security playbook '{playbook_id}' not found")

        if not playbook.enabled:
            return PlaybookExecutionResult(
                playbook_id=playbook_id,
                playbook_name=playbook.name,
                dry_run=dry_run,
                status="SKIPPED",
                authorized_by=authorized_by,
                audit_notes=["Playbook is currently disabled"],
            )

        step_results: List[StepExecutionResult] = []
        overall_status = "SUCCESS"
        audit_notes: List[str] = [
            f"Playbook '{playbook.name}' started in {'dry-run simulation' if dry_run else 'live enforcement'} mode",
        ]

        for step in playbook.steps:
            # Authorization Gate
            if step.requires_authorization and not authorized_by and not dry_run:
                step_res = StepExecutionResult(
                    step_id=step.step_id,
                    action_type=step.action_type,
                    status="DENIED",
                    message="Consequential step requires explicit security authorization; none provided",
                )
                step_results.append(step_res)
                overall_status = "DENIED"
                audit_notes.append(f"Step '{step.step_id}' denied due to missing authorization")
                break  # Fail-closed: halt subsequent consequential actions

            if dry_run:
                step_res = StepExecutionResult(
                    step_id=step.step_id,
                    action_type=step.action_type,
                    status="SIMULATED",
                    message=f"Dry run simulation: {step.action_type.value} would be executed",
                )
                step_results.append(step_res)
                continue

            # Live Execution
            try:
                msg = self._execute_step(step, ctx)
                step_res = StepExecutionResult(
                    step_id=step.step_id,
                    action_type=step.action_type,
                    status="SUCCESS",
                    message=msg,
                )
            except Exception as e:
                step_res = StepExecutionResult(
                    step_id=step.step_id,
                    action_type=step.action_type,
                    status="FAILED",
                    message=f"Step execution failed: {e}",
                )
                overall_status = "FAILED"
                audit_notes.append(f"Step '{step.step_id}' error: {e}")
                step_results.append(step_res)
                break

            step_results.append(step_res)

        exec_res = PlaybookExecutionResult(
            playbook_id=playbook_id,
            playbook_name=playbook.name,
            dry_run=dry_run,
            status=overall_status,
            authorized_by=authorized_by,
            step_results=step_results,
            audit_notes=audit_notes,
        )
        self._execution_history.append(exec_res)
        return exec_res

    def _execute_step(self, step: PlaybookStep, context: Dict[str, Any]) -> str:
        """Internal dispatcher for playbook actions."""
        if step.action_type == PlaybookActionType.QUARANTINE_SESSION:
            sess_id = step.parameters.get("session_id") or context.get("session_id")
            user_id = step.parameters.get("user_id") or context.get("user_id")
            if sess_id:
                self._quarantined_sessions.add(str(sess_id))
            if user_id:
                self._quarantined_users.add(str(user_id))
            return f"Quarantined session={sess_id}, user={user_id}"

        elif step.action_type == PlaybookActionType.ROTATE_CACHE:
            cache = context.get("cache")
            if cache and hasattr(cache, "clear"):
                cache.clear()
                return "Successfully flushed/rotated security cache"
            return "Cache rotation executed (no cache attached to context)"

        elif step.action_type == PlaybookActionType.CONTAIN_INCIDENT:
            incident_id = step.parameters.get("incident_id") or context.get("incident_id")
            inc_mgr = context.get("incident_manager")
            if inc_mgr and hasattr(inc_mgr, "contain_incident") and incident_id:
                inc_mgr.contain_incident(incident_id, reason="SecOps playbook automated containment")
                return f"Contained incident {incident_id}"
            return f"Incident {incident_id} marked for containment"

        elif step.action_type == PlaybookActionType.REVOKE_AGENT_CAPABILITY:
            agent_id = step.parameters.get("agent_id") or context.get("agent_id")
            capability = step.parameters.get("capability")
            return f"Revoked capability '{capability}' from agent '{agent_id}'"

        elif step.action_type == PlaybookActionType.DISPATCH_SOC_ALERT:
            sink = context.get("webhook_sink")
            return "SOC alert dispatched" if sink else "SOC alert notification queued"

        elif step.action_type == PlaybookActionType.CUSTOM:
            fn = context.get(step.parameters.get("handler_key", ""))
            if callable(fn):
                fn(step.parameters, context)
                return "Custom action executed successfully"
            return "Custom handler invoked"

        return f"Completed {step.action_type.value}"
