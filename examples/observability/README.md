# Observability & Security Intelligence Examples

This directory demonstrates Phase 24 capabilities of **LLMFirewall**:

1. `basic.py`:
   - Inspects text prompts and displays security decisions.
   - Generates deterministic non-LLM `DecisionTrace` explanations.
   - Queries `firewall.observe.summary()` for high-level metrics.
   - Exports metrics in standard Prometheus text format.

2. `production_like.py`:
   - Simulates 100 requests through a production SQLite event store backend.
   - Validates agent tool security calls.
   - Computes period-over-period trend deltas.
   - Generates conservative statistical anomaly signals.

### Running the examples

```bash
python examples/observability/basic.py
python examples/observability/production_like.py
```
