# Example: AI Security Compliance & Control Mapping (Phase 36)

This example demonstrates the **Phase 36** evidence-driven compliance and control-mapping engine on a **Customer Support AI** application.

---

## 1. What This Example Demonstrates

1. **Asset Topology Integration**: Evaluates an AI system composed of an Autonomous Agent, Tools, Model, and RAG knowledge store.
2. **Initial Assessment**: Evaluates applicable controls from the `ai-security-baseline` v1.0.0 framework and generates initial gaps.
3. **Traceable Evidence Chain**:
   ```text
   Asset -> Security Control -> Posture -> Evidence -> Compliance Control -> Assessment -> Gap
   ```
4. **Remediation & Re-Assessment**: Ingests policy configurations, empirical security test results, and runtime verifications, transitioning controls from `PARTIALLY_EVIDENCED` to `EVIDENCED`.
5. **Exception Management**: Formally registers a time-bounded exception waiver approved by security leadership.
6. **SARIF 2.1.0 Export**: Generates standardized SARIF output for developer remediation workflows.

---

## 2. Running the Example

```bash
python3 examples/compliance/application.py
```
