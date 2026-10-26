# Isolated FastAPI Secure Service Sample

This sample application demonstrates integrating `llmfirewall-core` into a **FastAPI** web service.

## Structure
- `app.py`: FastAPI endpoint protected with `FirewallMiddleware` and backed by a deterministic `LocalModelStub`.
- `test_app.py`: Verification tests asserting that allowed input reaches the model, blocked input never reaches it, and redacted input arrives only in sanitized form.

## Running Tests
```bash
pytest examples/sample_apps/fastapi_secure_service/test_app.py -v
```
