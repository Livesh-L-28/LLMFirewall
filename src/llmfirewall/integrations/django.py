"""Django middleware integration for LLMFirewall.

Optional integration: requires Django to be installed.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Callable, Dict, List, Optional, Set

from llmfirewall.core.models import Action, ScanResult
from llmfirewall.firewall import Firewall
from llmfirewall.integrations.base import FirewallIntegration

try:
    import django
    from django.http import HttpRequest, HttpResponse, JsonResponse
    HAS_DJANGO = True
except ImportError:
    HAS_DJANGO = False


class FirewallMiddleware(FirewallIntegration):
    """Django Middleware for protecting view endpoints against prompt injection, leaks, and attacks.
    
    Setup in settings.py:
        MIDDLEWARE = [
            ...
            "llmfirewall.integrations.django.FirewallMiddleware",
        ]
        
        LLMFIREWALL_CONFIG = {
            "paths": ["/api/chat/", "/llm/"],
            "exclude_paths": ["/static/", "/admin/"],
            "input_fields": ["prompt", "message", "query"],
            "blocked_status_code": 403,
        }
    """

    def __init__(
        self,
        get_response: Callable[[Any], Any],
        firewall: Optional[Firewall] = None,
        paths: Optional[List[str]] = None,
        exclude_paths: Optional[List[str]] = None,
        methods: Optional[Set[str]] = None,
        input_fields: Optional[List[str]] = None,
        blocked_status_code: int = 403,
    ) -> None:
        if not HAS_DJANGO:
            raise ImportError(
                "Django is not installed. To use the Django integration, install it via: "
                "pip install django or pip install 'llmfirewall[django]'"
            )
        super().__init__(firewall=firewall)
        self.get_response = get_response
        self.paths = paths
        self.exclude_paths = exclude_paths or ["/static/", "/media/", "/admin/", "/health/"]
        self.methods = methods or {"POST", "PUT", "PATCH"}
        self.input_fields = input_fields or ["prompt", "message", "query", "content", "text"]
        self.blocked_status_code = blocked_status_code

    def __call__(self, request: HttpRequest) -> HttpResponse:
        path = request.path
        method = request.method

        if not self._should_inspect(path, method):
            return self.get_response(request)

        # Generate request ID
        req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.firewall_request_id = req_id  # type: ignore

        # Extract text to scan
        text_to_scan = ""
        if request.content_type == "application/json":
            try:
                data = json.loads(request.body.decode("utf-8"))
                for field in self.input_fields:
                    if field in data and isinstance(data[field], str):
                        text_to_scan = data[field]
                        break
            except Exception:
                pass
        elif request.POST:
            for field in self.input_fields:
                if field in request.POST:
                    text_to_scan = request.POST[field]
                    break

        if not text_to_scan:
            return self.get_response(request)

        # Execute firewall scan
        res: ScanResult = self.firewall.check(
            text_or_request=text_to_scan,
            direction="input",
            user_id=request.headers.get("X-User-ID"),
            session_id=request.headers.get("X-Session-ID"),
            context={"path": path, "method": method},
        )
        request.firewall_scan_result = res  # type: ignore

        if res.decision.action == Action.BLOCK:
            return JsonResponse(
                {
                    "error": "security_policy_violation",
                    "message": "Request rejected by security policy.",
                    "request_id": req_id,
                },
                status=self.blocked_status_code,
            )

        response = self.get_response(request)
        response["X-LLMFirewall-Request-ID"] = req_id
        response["X-LLMFirewall-Action"] = res.decision.action.value
        response["X-LLMFirewall-Risk-Score"] = str(res.risk_score.score)
        return response

    def _should_inspect(self, path: str, method: str) -> bool:
        if method.upper() not in self.methods:
            return False
        for ex in self.exclude_paths:
            if path.startswith(ex):
                return False
        if self.paths is not None:
            return any(path.startswith(p) for p in self.paths)
        return True

    def protect(self, *args: Any, **kwargs: Any) -> Any:
        return self
