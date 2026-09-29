# Phase 37 — AI Security Risk & Prioritization Engine Example

This example demonstrates how LLMFirewall computes **evidence-driven risk prioritization** across AI assets, knowledge graphs, and attack surfaces.

## Key Invariants Demonstrated

1. **Explainable Prioritization**: Issues are prioritized with concrete factual rationale (e.g. externally reachable agent + access to sensitive database) rather than opaque arbitrary scores.
2. **Risk Inheritance**: Downstream database criticality propagates up to reachable agents.
3. **Epistemic Uncertainty**: Missing telemetry is treated as unobserved/partially supported, never assumed safe.

## Running the Example

```bash
python examples/risk/application.py
```

## CLI Usage

```bash
# Prioritize risk across all assets
llmfirewall risk

# Prioritize specific asset
llmfirewall risk agent:support_copilot

# JSON format
llmfirewall risk --format json
```
