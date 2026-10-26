# Agent Tool Calling Security Sample

This sample application demonstrates sandboxing AI agent tools and functions using `fw.check_tool_call()` and `@fw.protect_tool`.

## Structure
- `app.py`: Functions with SSRF interception, SQL permission checks, and `@fw.protect`.
- `test_app.py`: Verification tests checking pre-execution blocking.

## Running Tests
```bash
pytest examples/sample_apps/agent_tool_sandbox/test_app.py -v
```
