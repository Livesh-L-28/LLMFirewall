# Django Integration Recipe

Secure Django REST Framework and web views with automated request scanning and PII sanitization.

---

## 1. Overview & Capabilities

The `llmfirewall.integrations.django.FirewallMiddleware` provides:
- Automatic inspection of incoming prompt fields (e.g. `prompt`, `message`, `query`).
- Pre-view termination with HTTP 403 when prompt injection attacks are detected.
- Request-context attachment (`request.firewall_scan_result`) containing sanitized text (`processed_text`).
- Path-based exclusions (e.g. static assets, admin, health checks).

---

## 2. Installation

```bash
# Install core package with Django optional extra
python -m pip install "llmfirewall-core[django]"
```

---

## 3. Configuration in `settings.py`

Add `FirewallMiddleware` to your `MIDDLEWARE` list and configure endpoint paths:

```python
# settings.py

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    # ... standard Django middlewares ...
    "llmfirewall.integrations.django.FirewallMiddleware",
]

LLMFIREWALL_CONFIG = {
    # Endpoints to inspect:
    "paths": ["/api/chat/", "/api/generate/"],

    # Paths bypassed by the firewall:
    "exclude_paths": ["/admin/", "/static/", "/health/"],

    # JSON or POST field names to inspect for prompts:
    "input_fields": ["prompt", "message", "query"],

    # HTTP status code returned on policy block:
    "blocked_status_code": 403,
}
```

---

## 4. View Integration (`views.py`)

Retrieve the sanitized scan result from `request.firewall_scan_result`:

```python
# views.py
from django.http import JsonResponse

def chat_view(request):
    # Retrieve scan result attached by FirewallMiddleware
    scan_res = getattr(request, "firewall_scan_result", None)

    # CRITICAL INVARIANT: Always consume processed_text if PII was redacted!
    safe_prompt = scan_res.processed_text if scan_res else request.POST.get("prompt", "")

    # Invoke downstream model with safe_prompt
    return JsonResponse({
        "reply": f"Model completion for: {safe_prompt}",
        "action": scan_res.action.value if scan_res else "allow",
    })
```

---

## 5. Offline Testing

See [`tests/test_optional_extra_error_messages.py`](https://github.com/Livesh-L-28/LLMFirewall/blob/main/tests/test_optional_extra_error_messages.py) and [`tests/test_framework_integrations.py`](https://github.com/Livesh-L-28/LLMFirewall/blob/main/tests/test_framework_integrations.py).
