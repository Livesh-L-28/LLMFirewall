# AI Security Posture Management (AI-SPM) Example

This example demonstrates the complete defensive security lifecycle for a production-grade compound AI application:

```text
Customer Support AI
        │
        ├── Agent (Customer Support Agent)
        │    ├── Model (GPT-4o)
        │    ├── Database Tool (Customer DB)
        │    ├── Search Tool (Web Search)
        │    └── Memory (Session Memory Store)
        │
        └── RAG (Knowledge Base Documents)
```

---

## What It Demonstrates

1. **Asset Discovery & Graph Synchronization**:
   Registers the application, agent, model, tools, memory store, and RAG retrieval sources into the inventory and Knowledge Graph.
2. **Initial Posture Evaluation**:
   Evaluates initial security posture, identifying:
   - Untested tool authorization.
   - Missing input/output validation for high-sensitivity database tools.
   - Unverified RAG document tenant access controls.
   - Unverified memory poisoning defenses.
3. **Canonical Baseline Snapshotting**:
   Captures an immutable, tamper-evident posture baseline snapshot with cryptographic SHA-256 fingerprinting.
4. **Targeted Remediation Engineering**:
   Configures defensive security controls (`RBAC Tool Authorizer` and `Database Query Validator`) and ingests verified passing security test results (Phase 30).
5. **Posture Diff & Regression Verification**:
   Compares the current posture against the baseline snapshot using `PostureEngine.diff(...)`, verifying:
   - New defensive controls detected (`controls_added`).
   - Resolution of previously open security gaps (`gaps_resolved`).
   - Test freshness and control validation status.

---

## Running the Example

Run the Python demonstration script:

```bash
python3 examples/ai_spm/application.py
```

Or evaluate via the command line interface:

```bash
# Discover assets in environment
llmfirewall inventory discover

# Review aggregated security posture
llmfirewall posture summary

# View specific agent posture
llmfirewall posture agent:support_agent

# Create a baseline snapshot
llmfirewall posture snapshot --output baseline.json

# Diff against baseline
llmfirewall posture diff --before baseline.json --after current.json

# Export actionable gaps in OASIS SARIF format
llmfirewall posture export --format sarif --output gaps.sarif
```
