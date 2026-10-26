# Pure ASGI 3.0 Secure Gateway Sample

This sample application demonstrates integrating `llmfirewall-core` using `LLMFirewallASGIMiddleware` with zero external dependencies.

## Structure
- `app.py`: Pure ASGI 3.0 handler wrapped with `LLMFirewallASGIMiddleware`.
- `test_app.py`: Verification tests asserting allow, block, and redact across raw ASGI channels.

## Running Tests
```bash
pytest examples/sample_apps/asgi_secure_gateway/test_app.py -v
```
