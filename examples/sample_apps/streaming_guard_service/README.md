# Streaming Text Guard Secure Service Sample

This sample application demonstrates real-time streaming LLM output protection using `StreamingTextGuard`.

## Structure
- `app.py`: Streaming generator protected by `StreamingTextGuard` sliding window.
- `test_app.py`: Verification tests checking split-token credential blocking and in-flight PII masking.

## Running Tests
```bash
pytest examples/sample_apps/streaming_guard_service/test_app.py -v
```
