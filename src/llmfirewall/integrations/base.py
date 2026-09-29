"""Base abstractions, exceptions, and decorators for LLMFirewall integrations.

Phase 25: Framework & Ecosystem Integrations.
Guarantees:
- Lightweight adapter layer around core Firewall
- Deterministic error mapping
- Safe async/sync wrapping
- Bounded metric labels and correlation ID propagation
"""

from __future__ import annotations

import abc
import asyncio
import functools
import inspect
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union

from llmfirewall.core.exceptions import BlockedOutputError, BlockedPromptError, LLMFirewallError
from llmfirewall.core.models import Action, ScanRequest, ScanResult
from llmfirewall.firewall import Firewall

F = TypeVar("F", bound=Callable[..., Any])


class SecurityViolation(LLMFirewallError):
    """Exception raised when an integration layer detects and blocks a policy violation."""

    def __init__(
        self,
        message: str,
        scan_result: Optional[ScanResult] = None,
        request_id: Optional[str] = None,
        status_code: int = 403,
    ) -> None:
        super().__init__(message)
        self.scan_result = scan_result
        self.request_id = request_id or (scan_result.request_id if scan_result else None)
        self.status_code = status_code

    def to_dict(self) -> Dict[str, Any]:
        """Return safe, non-sensitive JSON payload for API responses."""
        return {
            "error": "security_policy_violation",
            "message": str(self),
            "request_id": self.request_id,
        }


class FirewallIntegration:
    """Base interface for all framework-specific adapters."""

    def __init__(self, firewall: Optional[Firewall] = None) -> None:
        self.firewall = firewall or Firewall()

    def protect(self, *args: Any, **kwargs: Any) -> Any:
        """Apply security protection to target framework component."""
        return self


def protect(
    firewall: Optional[Firewall] = None,
    input_arg_name: Optional[str] = None,
    inspect_output: bool = True,
    user_id_extractor: Optional[Callable[..., Optional[str]]] = None,
    session_id_extractor: Optional[Callable[..., Optional[str]]] = None,
) -> Callable[[F], F]:
    """Decorator to protect sync or async Python functions using LLMFirewall.
    
    Usage:
        @protect()
        def generate(prompt: str) -> str:
            return llm.predict(prompt)
            
        @protect(input_arg_name="query", inspect_output=False)
        async def rag_query(query: str, top_k: int = 5) -> str:
            ...
    """
    fw = firewall or Firewall()

    def decorator(func: F) -> F:
        sig = inspect.signature(func)
        is_async = inspect.iscoroutinefunction(func)

        def _extract_input(args: tuple, kwargs: dict) -> tuple[str, str]:
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            param_name = input_arg_name
            if not param_name:
                # Default to first string parameter
                for name, val in bound.arguments.items():
                    if isinstance(val, str):
                        param_name = name
                        break
            if param_name and param_name in bound.arguments:
                val = bound.arguments[param_name]
                return str(val), param_name
            # Fallback to first argument if present
            if args and isinstance(args[0], str):
                return str(args[0]), ""
            return "", ""

        if is_async:
            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                input_text, p_name = _extract_input(args, kwargs)
                if input_text:
                    u_id = user_id_extractor(*args, **kwargs) if user_id_extractor else None
                    s_id = session_id_extractor(*args, **kwargs) if session_id_extractor else None
                    
                    # Run input scan
                    loop = asyncio.get_running_loop()
                    res = await loop.run_in_executor(
                        None,
                        lambda: fw.check_prompt(input_text, user_id=u_id, session_id=s_id),
                    )
                    if res.decision.action == Action.BLOCK:
                        raise SecurityViolation(
                            f"Input rejected by security policy: {res.decision.reason}",
                            scan_result=res,
                            request_id=res.request_id,
                        )
                    # If redacted, mutate kwargs if possible
                    if res.decision.action == Action.REDACT and p_name:
                        bound = sig.bind(*args, **kwargs)
                        bound.apply_defaults()
                        bound.arguments[p_name] = res.processed_text
                        args = bound.args
                        kwargs = bound.kwargs

                raw_output = await func(*args, **kwargs)

                if inspect_output and isinstance(raw_output, str):
                    loop = asyncio.get_running_loop()
                    out_res = await loop.run_in_executor(
                        None,
                        lambda: fw.check_output(raw_output),
                    )
                    if out_res.decision.action == Action.BLOCK:
                        raise SecurityViolation(
                            f"Output rejected by security policy: {out_res.decision.reason}",
                            scan_result=out_res,
                            request_id=out_res.request_id,
                        )
                    if out_res.decision.action == Action.REDACT:
                        return out_res.processed_text

                return raw_output

            return async_wrapper  # type: ignore

        else:
            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                input_text, p_name = _extract_input(args, kwargs)
                if input_text:
                    u_id = user_id_extractor(*args, **kwargs) if user_id_extractor else None
                    s_id = session_id_extractor(*args, **kwargs) if session_id_extractor else None
                    
                    res = fw.check_prompt(input_text, user_id=u_id, session_id=s_id)
                    if res.decision.action == Action.BLOCK:
                        raise SecurityViolation(
                            f"Input rejected by security policy: {res.decision.reason}",
                            scan_result=res,
                            request_id=res.request_id,
                        )
                    if res.decision.action == Action.REDACT and p_name:
                        bound = sig.bind(*args, **kwargs)
                        bound.apply_defaults()
                        bound.arguments[p_name] = res.processed_text
                        args = bound.args
                        kwargs = bound.kwargs

                raw_output = func(*args, **kwargs)

                if inspect_output and isinstance(raw_output, str):
                    out_res = fw.check_output(raw_output)
                    if out_res.decision.action == Action.BLOCK:
                        raise SecurityViolation(
                            f"Output rejected by security policy: {out_res.decision.reason}",
                            scan_result=out_res,
                            request_id=out_res.request_id,
                        )
                    if out_res.decision.action == Action.REDACT:
                        return out_res.processed_text

                return raw_output

            return sync_wrapper  # type: ignore

    return decorator
