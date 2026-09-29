"""Detection rules for Phase 38: AI Security Incident Response & Investigation.

Rules analyze incoming security events and correlated event sequences to generate
evidence-backed security incidents.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field

from llmfirewall.incidents.models import (
    IncidentSeverity,
    IncidentStatus,
    SecurityEvent,
    SecurityEventType,
    SecurityIncident,
    compute_evidence_hash,
)


class IncidentCandidate(BaseModel):
    """Candidate incident emitted by a detection rule."""
    title: str
    description: str
    severity: IncidentSeverity
    assets: List[str] = Field(default_factory=list)
    event_ids: List[str] = Field(default_factory=list)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    rule_name: str
    root_cause_indicator: str


class IncidentDetectionRule(ABC):
    """Abstract base class for incident detection rules."""

    def __init__(self, name: str, description: str, enabled: bool = True) -> None:
        self.name = name
        self.description = description
        self.enabled = enabled

    @abstractmethod
    def evaluate(self, events: List[SecurityEvent]) -> List[IncidentCandidate]:
        """Evaluates a stream or correlated cluster of events and returns incident candidates."""
        pass


class RepeatedUnauthorizedToolCallsRule(IncidentDetectionRule):
    """Detects repeated unauthorized or denied tool calls within the same session/agent context."""

    def __init__(self, threshold: int = 2, name: str = "repeated_unauthorized_tool_calls") -> None:
        super().__init__(
            name=name,
            description=f"Detects {threshold} or more unauthorized tool invocations in a correlated context.",
        )
        self.threshold = threshold

    def evaluate(self, events: List[SecurityEvent]) -> List[IncidentCandidate]:
        candidates: List[IncidentCandidate] = []
        if not self.enabled or not events:
            return candidates

        # Group by session_id or agent_id or asset_id
        grouped: Dict[str, List[SecurityEvent]] = {}
        for ev in events:
            if ev.event_type in (
                SecurityEventType.UNAUTHORIZED_TOOL_CALL.value,
                "TOOL_CALL_BLOCKED",
                "unauthorized_tool_call",
            ):
                key = ev.session_id or ev.agent_id or ev.asset_id or "global"
                grouped.setdefault(key, []).append(ev)

        for key, matching_events in grouped.items():
            if len(matching_events) >= self.threshold:
                assets: Set[str] = set()
                ev_ids: List[str] = []
                tools: Set[str] = set()
                for ev in matching_events:
                    ev_ids.append(ev.id)
                    if ev.asset_id:
                        assets.add(ev.asset_id)
                    if ev.agent_id:
                        assets.add(f"agent:{ev.agent_id}")
                    if ev.tool_id:
                        tools.add(ev.tool_id)

                tool_str = ", ".join(sorted(tools)) if tools else "tools"
                evidence = [
                    {
                        "event_id": ev.id,
                        "timestamp": ev.timestamp.isoformat(),
                        "tool_id": ev.tool_id,
                        "source": ev.source,
                        "evidence_hash": compute_evidence_hash(ev.metadata),
                    }
                    for ev in matching_events
                ]

                candidates.append(
                    IncidentCandidate(
                        title=f"Repeated Unauthorized Tool Invocations on {tool_str}",
                        description=(
                            f"Detected {len(matching_events)} unauthorized tool invocation attempts "
                            f"(threshold: {self.threshold}) involving context {key}."
                        ),
                        severity=IncidentSeverity.HIGH if len(matching_events) >= 3 else IncidentSeverity.MEDIUM,
                        assets=sorted(list(assets)),
                        event_ids=ev_ids,
                        evidence=evidence,
                        rule_name=self.name,
                        root_cause_indicator="Potential tool permission misconfiguration or adversarial tool enumeration.",
                    )
                )

        return candidates


class PromptInjectionFollowedByPrivilegedToolRule(IncidentDetectionRule):
    """Detects prompt injection or jailbreak indicators followed by tool invocation in the same request/session."""

    def __init__(self, name: str = "prompt_injection_privileged_tool") -> None:
        super().__init__(
            name=name,
            description="Detects prompt injection indicator followed by privileged or sensitive tool call.",
        )

    def evaluate(self, events: List[SecurityEvent]) -> List[IncidentCandidate]:
        candidates: List[IncidentCandidate] = []
        if not self.enabled or not events:
            return candidates

        # Correlate by request_id or session_id
        contexts: Dict[str, List[SecurityEvent]] = {}
        for ev in events:
            key = ev.request_id or ev.session_id
            if key:
                contexts.setdefault(key, []).append(ev)

        for ctx_id, ctx_events in contexts.items():
            sorted_events = sorted(ctx_events, key=lambda x: x.timestamp)
            has_injection = False
            injection_ev: Optional[SecurityEvent] = None
            
            for ev in sorted_events:
                if ev.event_type in (
                    SecurityEventType.PROMPT_INJECTION_DETECTED.value,
                    SecurityEventType.JAILBREAK_ATTEMPT.value,
                    "prompt_injection",
                    "jailbreak",
                ):
                    has_injection = True
                    injection_ev = ev
                elif has_injection and ev.event_type in (
                    SecurityEventType.PRIVILEGED_TOOL_CALL.value,
                    SecurityEventType.UNAUTHORIZED_TOOL_CALL.value,
                    "TOOL_CALL_REQUESTED",
                    "tool_invocation",
                ):
                    # Flag correlation!
                    assets = set()
                    for item in (injection_ev, ev):
                        if item.asset_id:
                            assets.add(item.asset_id)
                        if item.agent_id:
                            assets.add(f"agent:{item.agent_id}")
                        if item.tool_id:
                            assets.add(f"tool:{item.tool_id}")

                    ev_ids = [injection_ev.id, ev.id]
                    evidence = [
                        {
                            "stage": "injection_detected",
                            "event_id": injection_ev.id,
                            "timestamp": injection_ev.timestamp.isoformat(),
                            "evidence_hash": compute_evidence_hash(injection_ev.metadata),
                        },
                        {
                            "stage": "subsequent_tool_invocation",
                            "event_id": ev.id,
                            "timestamp": ev.timestamp.isoformat(),
                            "tool_id": ev.tool_id,
                            "evidence_hash": compute_evidence_hash(ev.metadata),
                        },
                    ]

                    candidates.append(
                        IncidentCandidate(
                            title=f"Prompt Injection Preceding Tool Call ({ev.tool_id or 'unknown'})",
                            description=(
                                f"Observed prompt injection indicator followed by tool invocation attempt "
                                f"within request/session '{ctx_id}'."
                            ),
                            severity=IncidentSeverity.CRITICAL,
                            assets=sorted(list(assets)),
                            event_ids=ev_ids,
                            evidence=evidence,
                            rule_name=self.name,
                            root_cause_indicator="Adversarial prompt injection successfully triggering downstream agent tool execution.",
                        )
                    )
                    break  # One candidate per context is sufficient

        return candidates


class SecretExposureRule(IncidentDetectionRule):
    """Detects credential, key, or sensitive secret leakage in runtime events."""

    def __init__(self, name: str = "secret_exposure") -> None:
        super().__init__(
            name=name,
            description="Detects secret exposure or credential leakage events.",
        )

    def evaluate(self, events: List[SecurityEvent]) -> List[IncidentCandidate]:
        candidates: List[IncidentCandidate] = []
        if not self.enabled or not events:
            return candidates

        for ev in events:
            if ev.event_type in (
                SecurityEventType.SECRET_EXPOSURE.value,
                "secret_exposure",
                "CREDENTIAL_LEAK",
            ) or ev.metadata.get("secret_exposed"):
                assets = set()
                if ev.asset_id:
                    assets.add(ev.asset_id)
                if ev.agent_id:
                    assets.add(f"agent:{ev.agent_id}")

                evidence = [
                    {
                        "event_id": ev.id,
                        "timestamp": ev.timestamp.isoformat(),
                        "exposure_type": ev.metadata.get("exposure_type", "secret"),
                        "evidence_hash": compute_evidence_hash(ev.metadata),
                    }
                ]

                candidates.append(
                    IncidentCandidate(
                        title=f"Secret or Credential Exposure in {ev.asset_id or ev.source}",
                        description=f"Runtime inspection detected secret leakage in event {ev.id}.",
                        severity=IncidentSeverity.CRITICAL,
                        assets=sorted(list(assets)),
                        event_ids=[ev.id],
                        evidence=evidence,
                        rule_name=self.name,
                        root_cause_indicator="Unsanitized model prompt/completion or unmasked credential in runtime stream.",
                    )
                )

        return candidates


class PolicyBypassRule(IncidentDetectionRule):
    """Detects deliberate policy bypass or override attempts."""

    def __init__(self, name: str = "policy_bypass") -> None:
        super().__init__(
            name=name,
            description="Detects attempted bypass or circumvention of active firewall policies.",
        )

    def evaluate(self, events: List[SecurityEvent]) -> List[IncidentCandidate]:
        candidates: List[IncidentCandidate] = []
        if not self.enabled or not events:
            return candidates

        for ev in events:
            if ev.event_type in (
                SecurityEventType.POLICY_BYPASS.value,
                "policy_bypass",
                "GUARDRAIL_BYPASS",
            ):
                assets = set()
                if ev.asset_id:
                    assets.add(ev.asset_id)
                if ev.agent_id:
                    assets.add(f"agent:{ev.agent_id}")

                candidates.append(
                    IncidentCandidate(
                        title=f"Security Policy Bypass Attempt on {ev.asset_id or 'agent'}",
                        description=f"Runtime sensor detected policy bypass event: {ev.metadata.get('reason', 'Policy circumvention attempt')}.",
                        severity=IncidentSeverity.HIGH,
                        assets=sorted(list(assets)),
                        event_ids=[ev.id],
                        evidence=[
                            {
                                "event_id": ev.id,
                                "timestamp": ev.timestamp.isoformat(),
                                "evidence_hash": compute_evidence_hash(ev.metadata),
                            }
                        ],
                        rule_name=self.name,
                        root_cause_indicator="Adversarial payload crafted to evade security policy evaluation.",
                    )
                )

        return candidates


class AbnormalAgentBehaviorRule(IncidentDetectionRule):
    """Detects abnormal agent behavior such as infinite loops, token blowups, or excessive calls."""

    def __init__(self, name: str = "abnormal_agent_behavior") -> None:
        super().__init__(
            name=name,
            description="Detects agent loops, runaway execution, or anomalous call frequencies.",
        )

    def evaluate(self, events: List[SecurityEvent]) -> List[IncidentCandidate]:
        candidates: List[IncidentCandidate] = []
        if not self.enabled or not events:
            return candidates

        for ev in events:
            if ev.event_type in (
                SecurityEventType.ABNORMAL_AGENT_BEHAVIOR.value,
                "loop_detected",
                "LIMIT_EXCEEDED",
                "abnormal_behavior",
            ):
                assets = set()
                if ev.asset_id:
                    assets.add(ev.asset_id)
                if ev.agent_id:
                    assets.add(f"agent:{ev.agent_id}")

                candidates.append(
                    IncidentCandidate(
                        title=f"Abnormal Agent Execution Behavior ({ev.agent_id or ev.asset_id or 'agent'})",
                        description=f"Agent loop or runtime limit exceeded in event {ev.id}: {ev.metadata.get('details', 'Runaway execution')}.",
                        severity=IncidentSeverity.MEDIUM,
                        assets=sorted(list(assets)),
                        event_ids=[ev.id],
                        evidence=[
                            {
                                "event_id": ev.id,
                                "timestamp": ev.timestamp.isoformat(),
                                "evidence_hash": compute_evidence_hash(ev.metadata),
                            }
                        ],
                        rule_name=self.name,
                        root_cause_indicator="Unconstrained agent planning loop or lack of maximum iteration guardrails.",
                    )
                )

        return candidates


def get_default_incident_rules() -> List[IncidentDetectionRule]:
    """Returns the default suite of evidence-backed detection rules."""
    return [
        RepeatedUnauthorizedToolCallsRule(threshold=2),
        PromptInjectionFollowedByPrivilegedToolRule(),
        SecretExposureRule(),
        PolicyBypassRule(),
        AbnormalAgentBehaviorRule(),
    ]
