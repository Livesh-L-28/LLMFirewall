"""SDK decorators, tool wrappers, and middleware for Phase 39: AI Security Runtime Protection."""

from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, Dict, Optional, Union

from llmfirewall.core.exceptions import LLMFirewallError
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
    tool_fn: Callable,
    tool_name: Optional[str] = None,
    policy_name: Optional[str] = None,
    raise_on_block: bool = True,
) -> Callable:
    """Wraps a tool function with pre-execution authorization check.
    
    Usage:
        protected_db = firewall.protect_tool(
            database_query,
            tool_name="database",
            policy_name="database-access"
        )
    """
    engine = getattr(engine_or_fw, "protection", engine_or_fw)
    name = tool_name or getattr(tool_fn, "__name__", "tool")

    @functools.wraps(tool_fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        req = RuntimeRequest(
            tool={"name": name, "arguments": kwargs or ({"args": args} if args else {})},
            metadata={"policy": policy_name} if policy_name else {},
        )
        dec = engine.inspect(req)

        if dec.is_blocked or dec.decision in (PolicyDecision.BLOCK, PolicyDecision.REVIEW):
            if raise_on_block:
                raise SecurityBlockError(dec.reason, decision=dec)
            return {"status": "error", "error": f"Tool blocked by policy: {dec.reason}"}

        return tool_fn(*args, **kwargs)

    return wrapper


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
