# LLMFirewall Runtime Protection Example

Demonstrates end-to-end multi-boundary runtime protection across the lifecycle of an AI agent.

## Execution Flow

```text
User Input
    ↓ (Boundary 1: Input Guard)
Prompt Construction
    ↓ (Boundary 2: Prompt Guard with Trust Levels)
Pre-LLM Request
    ↓ (Boundary 3: LLM Request Guard)
Mock LLM selects Tool
    ↓ (Boundary 4: Tool Call Guard)
Tool Execution
    ↓ (Boundary 5: Tool Result Guard)
Agent Loop Check
    ↓ (Boundary 6: Loop Guard for Iterations & Limits)
Final Response
    ↓ (Boundary 7: Final Output Guard)
Result
```

## Running the Example

```bash
python examples/runtime/mock_agent.py
```

No external API keys or network dependencies are required. All checks run locally with deterministic security guarantees.
