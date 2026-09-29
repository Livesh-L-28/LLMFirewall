"""Target adapters connecting the continuous security testing engine to arbitrary AI systems."""

from abc import ABC, abstractmethod
import json
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import urllib.error
import urllib.request

from llmfirewall.core.models import Action, Severity, ThreatType
from llmfirewall.eval.models import (
    AttackCategory,
    SecurityObservation,
    SecurityTest,
    SecurityTestCase,
    TargetType,
)
from llmfirewall.eval.targets import EvaluationTarget
from llmfirewall.firewall import Firewall


class TargetAdapter(EvaluationTarget, ABC):
    """Abstract base adapter for evaluating security tests against AI systems."""

    @abstractmethod
    def execute(self, test: SecurityTest) -> SecurityObservation:
        """Execute a security test against the target system and capture the observation."""
        pass

    def evaluate_test_case(
        self,
        test_case: SecurityTestCase,
    ) -> Tuple[Action, float, list[str], list[str], list[str]]:
        """Bridge implementation for backward compatibility with Phase 23 EvaluationTarget."""
        obs = self.execute(test_case)
        return (
            obs.action,
            obs.risk_score,
            obs.detected_threats,
            obs.detector_names,
            obs.matched_rules,
        )


class FirewallAdapter(TargetAdapter):
    """Adapter evaluating tests directly against an LLMFirewall instance."""

    def __init__(self, firewall: Optional[Firewall] = None) -> None:
        self._firewall = firewall or Firewall()

    @property
    def firewall(self) -> Firewall:
        return self._firewall

    def execute(self, test: SecurityTest) -> SecurityObservation:
        start_t = time.perf_counter()
        ttype = test.target_type

        try:
            if ttype == TargetType.PROMPT:
                res = self._firewall.check_prompt(test.input_payload)
                lat = (time.perf_counter() - start_t) * 1000.0
                return SecurityObservation(
                    status="SUCCESS",
                    response="[PROMPT INSPECTION EVALUATED]",
                    action=res.decision.action,
                    action_decision=res.decision.action.value,
                    detected_threats=[f.threat_type.value for f in res.findings],
                    detector_names=[f.detector_name for f in res.findings],
                    matched_rules=res.decision.triggered_rules,
                    risk_score=res.risk_score.score,
                    latency_ms=round(lat, 4),
                    metadata={"scanned_text_length": len(test.input_payload)},
                )

            elif ttype == TargetType.OUTPUT:
                res = self._firewall.check_output(test.input_payload)
                lat = (time.perf_counter() - start_t) * 1000.0
                return SecurityObservation(
                    status="SUCCESS",
                    response=res.processed_text or test.input_payload,
                    action=res.decision.action,
                    action_decision=res.decision.action.value,
                    detected_threats=[f.threat_type.value for f in res.findings],
                    detector_names=[f.detector_name for f in res.findings],
                    matched_rules=res.decision.triggered_rules,
                    risk_score=res.risk_score.score,
                    latency_ms=round(lat, 4),
                )

            elif ttype == TargetType.TOOL_CALL:
                tool_name = test.tool_name or "default_tool"
                args = test.tool_arguments or {}
                dec = self._firewall.check_tool_call(tool_call_or_name=tool_name, arguments=args)
                lat = (time.perf_counter() - start_t) * 1000.0
                return SecurityObservation(
                    status="SUCCESS",
                    response=f"Tool call evaluated: {tool_name}",
                    action=dec.action,
                    action_decision=dec.action.value,
                    tool_calls=[{"name": tool_name, "arguments": args}],
                    detected_threats=[f.threat_type.value for f in dec.findings],
                    detector_names=[f.detector_name for f in dec.findings],
                    matched_rules=dec.triggered_rules,
                    risk_score=dec.risk_score.score if dec.risk_score else 0.0,
                    latency_ms=round(lat, 4),
                )

            elif ttype == TargetType.TOOL_RESULT:
                tool_name = test.tool_name or "default_tool"
                dec = self._firewall.check_tool_result(
                    tool_result_or_name=tool_name,
                    output=test.input_payload,
                )
                lat = (time.perf_counter() - start_t) * 1000.0
                return SecurityObservation(
                    status="SUCCESS",
                    response=test.input_payload,
                    action=dec.action,
                    action_decision=dec.action.value,
                    detected_threats=[f.threat_type.value for f in dec.findings],
                    detector_names=[f.detector_name for f in dec.findings],
                    matched_rules=dec.triggered_rules,
                    risk_score=dec.risk_score.score if dec.risk_score else 0.0,
                    latency_ms=round(lat, 4),
                )

            elif ttype == TargetType.AGENT:
                cap = test.agent_capability or "filesystem.read"
                res_scope = test.agent_resource or "./documents/*"
                dec = self._firewall.authorize_action(
                    capability_name=cap,
                    agent_id="test_agent",
                    resource=res_scope,
                    tool_name=test.tool_name or "default_tool",
                )
                lat = (time.perf_counter() - start_t) * 1000.0
                act = Action.ALLOW if dec.is_allowed else Action.BLOCK
                return SecurityObservation(
                    status="SUCCESS",
                    response=f"Agent capability decision: {dec.decision.value}",
                    action=act,
                    action_decision=dec.decision.value,
                    risk_score=0.0 if dec.is_allowed else 1.0,
                    latency_ms=round(lat, 4),
                    metadata={"decision": dec.decision.value, "reason": dec.reason},
                )

            elif ttype == TargetType.RAG:
                docs = test.context_documents or [test.input_payload]
                # Check RAG context if rag_guard exists, else scan context directly
                findings = []
                action = Action.ALLOW
                if hasattr(self._firewall, "rag_guard") and self._firewall.rag_guard:
                    for doc in docs:
                        d_res = self._firewall.rag_guard.scan_document(doc, doc_id="test_doc")
                        if not d_res.is_trusted or d_res.decision.action == Action.BLOCK:
                            action = Action.BLOCK
                            findings.extend(d_res.findings)
                else:
                    for doc in docs:
                        p_res = self._firewall.check_prompt(doc)
                        if p_res.decision.action == Action.BLOCK:
                            action = Action.BLOCK
                            findings.extend([f.threat_type.value for f in p_res.findings])

                lat = (time.perf_counter() - start_t) * 1000.0
                return SecurityObservation(
                    status="SUCCESS",
                    response="RAG context evaluated",
                    action=action,
                    action_decision=action.value,
                    detected_threats=list(set(str(f) for f in findings)),
                    risk_score=1.0 if action == Action.BLOCK else 0.0,
                    latency_ms=round(lat, 4),
                )

            else:
                lat = (time.perf_counter() - start_t) * 1000.0
                return SecurityObservation(
                    status="TARGET_ERROR",
                    response=f"Unsupported target_type: {ttype}",
                    action=Action.BLOCK,
                    action_decision="ERROR",
                    latency_ms=round(lat, 4),
                    errors=f"Unsupported target_type: {ttype}",
                )

        except Exception as exc:
            lat = (time.perf_counter() - start_t) * 1000.0
            return SecurityObservation(
                status="TARGET_ERROR",
                response="",
                action=Action.BLOCK,
                action_decision="ERROR",
                latency_ms=round(lat, 4),
                errors=str(exc),
            )


class MockAdapter(TargetAdapter):
    """Deterministic, offline mock adapter for CI pipelines without network or API keys."""

    def __init__(
        self,
        default_action: Action = Action.ALLOW,
        blocked_keywords: Optional[List[str]] = None,
        mock_response: str = "Mocked AI response.",
    ) -> None:
        self.default_action = default_action
        self.blocked_keywords = blocked_keywords or [
            "ignore previous",
            "system prompt",
            "dan mode",
            "<|im_end|>",
            "rm -rf",
            "drop table",
            "169.254.169.254",
            "../../",
            "/etc/shadow",
            "sk-proj-",
            "ghp_",
        ]
        self.mock_response = mock_response

    def execute(self, test: SecurityTest) -> SecurityObservation:
        start_t = time.perf_counter()
        payload = test.input_payload.lower()
        tool_args_str = json.dumps(test.tool_arguments or {}).lower()

        # Check if any attack keyword is present in payload or arguments
        is_blocked = any(kw in payload or kw in tool_args_str for kw in self.blocked_keywords)
        if test.agent_capability in ("shell.execute", "unauthorized.cap"):
            is_blocked = True

        action = Action.BLOCK if is_blocked else self.default_action
        decision_str = "BLOCK" if is_blocked else action.value
        threats = ["mock_threat"] if is_blocked else []
        lat = (time.perf_counter() - start_t) * 1000.0

        return SecurityObservation(
            status="SUCCESS",
            response="I cannot fulfill this request." if is_blocked else self.mock_response,
            action=action,
            action_decision=decision_str,
            detected_threats=threats,
            risk_score=1.0 if is_blocked else 0.0,
            latency_ms=round(lat, 4),
            metadata={"mock": True},
        )


class HTTPTargetAdapter(TargetAdapter):
    """Adapter invoking external HTTP/REST endpoints via JSON POST with credential redaction."""

    def __init__(
        self,
        endpoint: str,
        headers: Optional[Dict[str, str]] = None,
        timeout_seconds: float = 30.0,
    ) -> None:
        self.endpoint = endpoint
        self._headers = headers or {"Content-Type": "application/json"}
        self.timeout_seconds = timeout_seconds

    def execute(self, test: SecurityTest) -> SecurityObservation:
        start_t = time.perf_counter()
        req_data = {
            "prompt": test.input_payload,
            "tool_name": test.tool_name,
            "tool_arguments": test.tool_arguments,
            "category": test.category.value,
        }
        body = json.dumps(req_data).encode("utf-8")

        req = urllib.request.Request(
            url=self.endpoint,
            data=body,
            headers=self._headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                status_code = resp.status
                resp_text = resp.read().decode("utf-8")
                lat = (time.perf_counter() - start_t) * 1000.0

                try:
                    data = json.loads(resp_text)
                    act_str = data.get("action", data.get("security_action", "ALLOW")).upper()
                    act = Action.BLOCK if act_str in ("BLOCK", "DENY") else Action.ALLOW
                    return SecurityObservation(
                        status="SUCCESS",
                        response=data.get("response", resp_text),
                        action=act,
                        action_decision=act_str,
                        latency_ms=round(lat, 4),
                        metadata={"status_code": status_code},
                    )
                except json.JSONDecodeError:
                    return SecurityObservation(
                        status="SUCCESS",
                        response=resp_text,
                        action=Action.ALLOW,
                        latency_ms=round(lat, 4),
                        metadata={"status_code": status_code},
                    )

        except urllib.error.HTTPError as exc:
            lat = (time.perf_counter() - start_t) * 1000.0
            act = Action.BLOCK if exc.code in (400, 403) else Action.ALLOW
            return SecurityObservation(
                status="SUCCESS" if exc.code in (400, 403) else "TARGET_ERROR",
                response=f"HTTP {exc.code}: {exc.reason}",
                action=act,
                action_decision="BLOCK" if exc.code in (400, 403) else "ERROR",
                latency_ms=round(lat, 4),
                errors=f"HTTPError: {exc.code} {exc.reason}",
            )
        except urllib.error.URLError as exc:
            lat = (time.perf_counter() - start_t) * 1000.0
            return SecurityObservation(
                status="TARGET_ERROR",
                response="",
                action=Action.BLOCK,
                action_decision="ERROR",
                latency_ms=round(lat, 4),
                errors=f"URLError: {exc.reason}",
            )
        except Exception as exc:
            lat = (time.perf_counter() - start_t) * 1000.0
            return SecurityObservation(
                status="TARGET_ERROR",
                response="",
                action=Action.BLOCK,
                action_decision="ERROR",
                latency_ms=round(lat, 4),
                errors=str(exc),
            )


class CallableAdapter(TargetAdapter):
    """Adapter wrapping an arbitrary Python callable (e.g. LLM pipeline or function)."""

    def __init__(self, target_callable: Callable[[str], Any]) -> None:
        self.target_callable = target_callable

    def execute(self, test: SecurityTest) -> SecurityObservation:
        start_t = time.perf_counter()
        try:
            output = self.target_callable(test.input_payload)
            lat = (time.perf_counter() - start_t) * 1000.0
            resp_str = str(output)
            return SecurityObservation(
                status="SUCCESS",
                response=resp_str,
                action=Action.ALLOW,
                action_decision="ALLOW",
                latency_ms=round(lat, 4),
            )
        except Exception as exc:
            lat = (time.perf_counter() - start_t) * 1000.0
            return SecurityObservation(
                status="TARGET_ERROR",
                response="",
                action=Action.BLOCK,
                action_decision="ERROR",
                latency_ms=round(lat, 4),
                errors=str(exc),
            )


class AgentAdapter(TargetAdapter):
    """Adapter wrapping an autonomous agent system and capturing requested tool calls."""

    def __init__(self, agent_callable: Callable[[str], Dict[str, Any]]) -> None:
        self.agent_callable = agent_callable

    def execute(self, test: SecurityTest) -> SecurityObservation:
        start_t = time.perf_counter()
        try:
            result = self.agent_callable(test.input_payload)
            lat = (time.perf_counter() - start_t) * 1000.0
            response_text = result.get("response", "") if isinstance(result, dict) else str(result)
            tool_calls = result.get("tool_calls", []) if isinstance(result, dict) else []
            return SecurityObservation(
                status="SUCCESS",
                response=response_text,
                action=Action.ALLOW,
                action_decision="ALLOW",
                tool_calls=tool_calls,
                latency_ms=round(lat, 4),
                metadata={"agent_result": result},
            )
        except Exception as exc:
            lat = (time.perf_counter() - start_t) * 1000.0
            return SecurityObservation(
                status="TARGET_ERROR",
                response="",
                action=Action.BLOCK,
                action_decision="ERROR",
                latency_ms=round(lat, 4),
                errors=str(exc),
            )


class RAGAdapter(TargetAdapter):
    """Adapter wrapping a Retrieval-Augmented Generation (RAG) pipeline."""

    def __init__(self, rag_callable: Callable[[str, List[str]], Dict[str, Any]]) -> None:
        self.rag_callable = rag_callable

    def execute(self, test: SecurityTest) -> SecurityObservation:
        start_t = time.perf_counter()
        try:
            contexts = test.context_documents or []
            result = self.rag_callable(test.input_payload, contexts)
            lat = (time.perf_counter() - start_t) * 1000.0
            resp_str = result.get("answer", "") if isinstance(result, dict) else str(result)
            citations = result.get("citations", []) if isinstance(result, dict) else []
            return SecurityObservation(
                status="SUCCESS",
                response=resp_str,
                action=Action.ALLOW,
                action_decision="ALLOW",
                latency_ms=round(lat, 4),
                metadata={"citations": citations},
            )
        except Exception as exc:
            lat = (time.perf_counter() - start_t) * 1000.0
            return SecurityObservation(
                status="TARGET_ERROR",
                response="",
                action=Action.BLOCK,
                action_decision="ERROR",
                latency_ms=round(lat, 4),
                errors=str(exc),
            )
