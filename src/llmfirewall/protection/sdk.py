"""SDK decorators, tool wrappers, and middleware for Phase 39: AI Security Runtime Protection."""

from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, Dict, Optional, Union

from llmfirewall.core.exceptions import LLMFirewallError
from llmfirewall.core.models import Action
from llmfirewall.protection.models import PolicyDecision, RuntimeRequest


class SecurityBlockError(LLMFirewallError):
    """Raised when a protected agent invocation or tool is blocked by policy."""

    def __init__(self, reason: str, decision: Any = None) -> None:
        super().__init__(f"Security Block: {reason}")
        self.reason = reason
        self.decision = decision


def protect(
    engine_or_fw: Any,
    agent_id: Optional[str] = None,
    raise_on_block: bool = True,
) -> Callable:
    """Decorator to wrap agent execution functions with LLMFirewall runtime protection.

    Usage:
        @firewall.protect
        def run_agent(user_input: str) -> str:
            return llm.invoke(user_input)
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Extract engine
            engine = getattr(engine_or_fw, "protection", engine_or_fw)

            # Extract user input from first arg or kwargs
            input_val = None
            if args:
                if isinstance(args[0], str):
                    input_val = args[0]
                elif hasattr(args[0], "input"):
                    input_val = str(args[0].input)
                elif hasattr(args[0], "prompt"):
                    input_val = str(args[0].prompt)
                elif isinstance(args[0], dict) and ("input" in args[0] or "prompt" in args[0]):
                    input_val = str(args[0].get("input") or args[0].get("prompt"))
            if not input_val and "input" in kwargs:
                input_val = str(kwargs["input"])
            elif not input_val and "prompt" in kwargs:
                input_val = str(kwargs["prompt"])

            # 1. Pre-execution input inspection
            req = RuntimeRequest(
                agent_id=agent_id or getattr(fn, "__name__", "agent"),
                input=input_val,
            )
            dec = engine.inspect(req)

            if dec.is_blocked:
                if raise_on_block:
                    raise SecurityBlockError(dec.reason, decision=dec)
                return f"[BLOCKED BY POLICY] {dec.reason}"

            # Propagate redacted input content downstream to wrapped function
            if dec.is_redacted and dec.redacted_content:
                redacted = dec.redacted_content
                if args:
                    if isinstance(args[0], str):
                        args = (redacted,) + args[1:]
                    elif isinstance(args[0], dict):
                        new_d = dict(args[0])
                        for k in ("input", "prompt", "text", "query", "message"):
                            if k in new_d and isinstance(new_d[k], str):
                                new_d[k] = redacted
                        args = (new_d,) + args[1:]
                if "input" in kwargs and isinstance(kwargs["input"], str):
                    kwargs["input"] = redacted
                elif "prompt" in kwargs and isinstance(kwargs["prompt"], str):
                    kwargs["prompt"] = redacted

            # 2. Execute wrapped agent function
            result = fn(*args, **kwargs)

            # 3. Post-execution output inspection
            if isinstance(result, str):
                out_req = RuntimeRequest(
                    agent_id=agent_id or getattr(fn, "__name__", "agent"),
                    output=result,
                )
                out_dec = engine.inspect(out_req)
                if out_dec.is_blocked:
                    if raise_on_block:
                        raise SecurityBlockError(out_dec.reason, decision=out_dec)
                    return f"[BLOCKED BY POLICY] {out_dec.reason}"
                elif out_dec.is_redacted and out_dec.redacted_content:
                    return out_dec.redacted_content

            return result

        return wrapper

    return decorator


def protect_tool(
    engine_or_fw: Any,
    tool_fn: Optional[Callable] = None,
    tool_name: Optional[str] = None,
    policy_name: Optional[str] = None,
    raise_on_block: bool = True,
    workflow_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> Callable:
    """Wraps a tool function with pre-execution authorization check.

    Supports both single-turn runtime inspection and Phase 3 cross-step workflow enforcement.
    Safely supports both synchronous and asynchronous (coroutine) tool functions.

    Usage:
        # Direct wrap
        guarded = firewall.protect_tool(db_query, tool_name="db")

        # Decorator syntax
        @firewall.protect_tool
        def query(sql: str): ...

        # Decorator with kwargs
        @firewall.protect_tool(tool_name="db", workflow_id="wf-1", tenant_id="t-1")
        async def query(sql: str): ...
    """
    if tool_fn is None:
        return lambda fn: protect_tool(
            engine_or_fw,
            tool_fn=fn,
            tool_name=tool_name,
            policy_name=policy_name,
            raise_on_block=raise_on_block,
            workflow_id=workflow_id,
            tenant_id=tenant_id,
        )

    engine = getattr(engine_or_fw, "protection", engine_or_fw)
    name = tool_name or getattr(tool_fn, "__name__", "tool")

    def _pre_execution_check(args: tuple, kwargs: dict) -> tuple:
        active_wf_id = kwargs.pop("workflow_id", workflow_id)
        active_tenant_id = kwargs.pop("tenant_id", tenant_id)
        active_agent_id = kwargs.pop("agent_id", None)

        # Cross-step workflow security check
        if active_wf_id and hasattr(engine_or_fw, "cross_step_enforcer"):
            from llmfirewall.workflow.models import CrossTenantViolationError
            if not active_tenant_id:
                raise CrossTenantViolationError(
                    f"tenant_id is required for cross-step execution of tool '{name}' in workflow '{active_wf_id}'.",
                    workflow_id=active_wf_id,
                )
            try:
                engine_or_fw.cross_step_enforcer.enforce_tool_call(
                    workflow_id=active_wf_id,
                    tool_name=name,
                    arguments=kwargs,
                    tenant_id=active_tenant_id,
                    agent_id=active_agent_id,
                )
            except Exception as exc:
                if raise_on_block:
                    raise
                reason = getattr(exc, "reason", str(exc))
                return active_wf_id, active_tenant_id, active_agent_id, {"status": "error", "error": f"Tool blocked by policy: {reason}"}

            return active_wf_id, active_tenant_id, active_agent_id, None

        # 1. Runtime policy inspection
        req = RuntimeRequest(
            tool={"name": name, "arguments": kwargs or ({"args": list(args)} if args else {})},
            metadata={"policy": policy_name} if policy_name else {},
        )
        if engine and hasattr(engine, "inspect"):
            dec = engine.inspect(req)
            if dec.is_blocked or dec.decision in (PolicyDecision.BLOCK, PolicyDecision.REVIEW):
                if raise_on_block:
                    raise SecurityBlockError(dec.reason, decision=dec)
                return active_wf_id, active_tenant_id, active_agent_id, {"status": "error", "error": f"Tool blocked by policy: {dec.reason}"}

        # 2. Hardened ToolSecurityEngine inspection (SSRF, path traversal, commands, allowlists)
        if hasattr(engine_or_fw, "check_tool_call"):
            tool_args = dict(kwargs) if kwargs else ({"args": list(args)} if args else {})
            tool_dec = engine_or_fw.check_tool_call(tool_call_or_name=name, arguments=tool_args)
            if getattr(tool_dec, "is_blocked", False) or getattr(tool_dec, "action", None) == Action.BLOCK:
                block_reason = f"Tool '{name}' blocked: {tool_dec.reason}"
                if raise_on_block:
                    raise SecurityBlockError(block_reason, decision=tool_dec)
                return active_wf_id, active_tenant_id, active_agent_id, {"status": "error", "error": block_reason}

        return active_wf_id, active_tenant_id, active_agent_id, None

    def _post_execution_check(
        result: Any,
        active_wf_id: Optional[str],
        active_tenant_id: Optional[str],
        active_agent_id: Optional[str],
    ) -> Optional[dict]:
        if isinstance(result, str) and active_wf_id and hasattr(engine_or_fw, "cross_step_enforcer"):
            try:
                engine_or_fw.cross_step_enforcer.enforce_tool_result(
                    workflow_id=active_wf_id,
                    tool_name=name,
                    output=result,
                    tenant_id=active_tenant_id,
                    agent_id=active_agent_id,
                )
            except Exception as exc:
                if raise_on_block:
                    raise
                reason = getattr(exc, "reason", str(exc))
                return {"status": "error", "error": f"Tool result blocked by policy: {reason}"}
        return None

    if inspect.iscoroutinefunction(tool_fn):
        @functools.wraps(tool_fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            active_wf_id, active_tenant_id, active_agent_id, err = _pre_execution_check(args, kwargs)
            if err is not None:
                return err

            result = await tool_fn(*args, **kwargs)

            post_err = _post_execution_check(result, active_wf_id, active_tenant_id, active_agent_id)
            if post_err is not None:
                return post_err

            return result

        return async_wrapper
    else:
        @functools.wraps(tool_fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            active_wf_id, active_tenant_id, active_agent_id, err = _pre_execution_check(args, kwargs)
            if err is not None:
                return err

            result = tool_fn(*args, **kwargs)

            post_err = _post_execution_check(result, active_wf_id, active_tenant_id, active_agent_id)
            if post_err is not None:
                return post_err

            return result

        return sync_wrapper


class LLMFirewallMiddleware:
    """Universal ASGI/WSGI middleware for web framework integrations (FastAPI, Starlette, Flask, Django).

    Inspects incoming HTTP payloads without making any web framework a required dependency.
    """

    def __init__(self, app: Any, firewall: Any, path_prefix: str = "/api") -> None:
        self.app = app
        self.firewall = firewall
        self.path_prefix = path_prefix

    async def __call__(self, scope: Dict[str, Any], receive: Callable, send: Callable) -> Any:
        """ASGI invocation handler."""
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)

        path = scope.get("path", "")
        if not path.startswith(self.path_prefix):
            return await self.app(scope, receive, send)

        # In ASGI, receive body and inspect
        async def custom_receive() -> Dict[str, Any]:
            message = await receive()
            if message.get("type") == "http.request":
                body = message.get("body", b"")
                if body:
                    try:
                        text = body.decode("utf-8", errors="ignore")
                        req = RuntimeRequest(
                            input=text,
                            metadata={"path": path, "method": scope.get("method")},
                        )
                        engine = getattr(self.firewall, "protection", self.firewall)
                        decision = engine.inspect(req)
                        if decision.is_blocked:
                            # Modify to trigger block response or raise
                            message["_blocked_reason"] = decision.reason
                    except Exception:
                        pass
            return message

        return await self.app(scope, custom_receive, send)
