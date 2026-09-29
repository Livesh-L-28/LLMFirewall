"""Flask extension and middleware integration for LLMFirewall.

Provides request/response inspection for Flask applications.
Optional integration: requires Flask to be installed.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Callable, Dict, List, Optional, Set, Union

from llmfirewall.core.models import Action, ScanResult
from llmfirewall.firewall import Firewall
from llmfirewall.integrations.base import FirewallIntegration, SecurityViolation

try:
    import flask
    from flask import Request, Response, current_app, g, jsonify, request
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False


class FirewallExtension(FirewallIntegration):
    """Flask extension providing automatic or route-selective security guardrails.
    
    Usage:
        app = Flask(__name__)
        firewall = Firewall()
        FirewallExtension(app, firewall=firewall, paths=["/chat", "/api/llm"])
    """

    def __init__(
        self,
        app: Optional[Any] = None,
        firewall: Optional[Firewall] = None,
        paths: Optional[List[str]] = None,
        exclude_paths: Optional[List[str]] = None,
        methods: Optional[Set[str]] = None,
        input_fields: Optional[List[str]] = None,
        scan_output: bool = False,
        blocked_status_code: int = 403,
        request_id_header: str = "X-Request-ID",
    ) -> None:
        if not HAS_FLASK:
            raise ImportError(
                "Flask is not installed. To use the Flask integration, install it via: "
                "pip install flask or pip install 'llmfirewall[flask]'"
            )
        super().__init__(firewall=firewall)
        self.paths = paths
        self.exclude_paths = exclude_paths or ["/static", "/health", "/metrics"]
        self.methods = methods or {"POST", "PUT", "PATCH"}
        self.input_fields = input_fields or ["prompt", "message", "text", "query", "content", "input"]
        self.scan_output = scan_output
        self.blocked_status_code = blocked_status_code
        self.request_id_header = request_id_header

        if app is not None:
            self.init_app(app)

    def init_app(self, app: Any) -> None:
        """Register before_request and after_request hooks on Flask app."""
        app.before_request(self._before_request)
        if self.scan_output:
            app.after_request(self._after_request)

    def protect(self, *args: Any, **kwargs: Any) -> Any:
        """Route-level decorator for selective Flask endpoint protection."""
        def decorator(f: Callable[..., Any]) -> Callable[..., Any]:
            import functools

            @functools.wraps(f)
            def wrapper(*a: Any, **kw: Any) -> Any:
                self._inspect_current_request()
                resp = f(*a, **kw)
                if self.scan_output:
                    resp = self._inspect_current_response(resp)
                return resp

            return wrapper

        return decorator

    def _should_inspect(self, path: str, method: str) -> bool:
        if method.upper() not in self.methods:
            return False
        for ex in self.exclude_paths:
            if path.startswith(ex):
                return False
        if self.paths is not None:
            return any(path.startswith(p) for p in self.paths)
        return True

    def _before_request(self) -> Optional[Response]:
        path = flask.request.path
        method = flask.request.method
        if not self._should_inspect(path, method):
            return None
        return self._inspect_current_request()

    def _inspect_current_request(self) -> Optional[Response]:
        req_id = flask.request.headers.get(self.request_id_header) or str(uuid.uuid4())
        flask.g.firewall_request_id = req_id

        # Extract text from json or form
        text_to_scan = ""
        if flask.request.is_json:
            try:
                data = flask.request.get_json(silent=True) or {}
                for field in self.input_fields:
                    if field in data and isinstance(data[field], str):
                        text_to_scan = data[field]
                        break
            except Exception:
                pass
        elif flask.request.form:
            for field in self.input_fields:
                if field in flask.request.form:
                    text_to_scan = flask.request.form[field]
                    break
        elif flask.request.data:
            try:
                text_to_scan = flask.request.data.decode("utf-8", errors="ignore")
            except Exception:
                pass

        if not text_to_scan:
            return None

        # Check firewall
        res: ScanResult = self.firewall.check(
            text_or_request=text_to_scan,
            direction="input",
            user_id=flask.request.headers.get("X-User-ID"),
            session_id=flask.request.headers.get("X-Session-ID"),
            context={"path": flask.request.path, "method": flask.request.method},
        )
        flask.g.firewall_scan_result = res

        if res.decision.action == Action.BLOCK:
            return flask.jsonify({
                "error": "security_policy_violation",
                "message": "Request rejected by security policy.",
                "request_id": req_id,
            }), self.blocked_status_code

        return None

    def _after_request(self, response: Response) -> Response:
        if not self.scan_output or response.status_code >= 400:
            return response

        # Attach telemetry headers if request was scanned
        req_id = getattr(flask.g, "firewall_request_id", None)
        scan_res = getattr(flask.g, "firewall_scan_result", None)
        if req_id:
            response.headers["X-LLMFirewall-Request-ID"] = req_id
        if scan_res:
            response.headers["X-LLMFirewall-Action"] = scan_res.decision.action.value
            response.headers["X-LLMFirewall-Risk-Score"] = str(scan_res.risk_score.score)

        return response

    def _inspect_current_response(self, response: Any) -> Any:
        return response
