# Agent Capability Security Example

This example demonstrates how **LLMFirewall** enforces capability-based security, action budgets, delegation controls, and approval gates for autonomous and tool-using AI agents.

## Core Concepts

1. **Least-Privilege Authorization**: Agents only receive explicitly granted capabilities (`filesystem.read`, `network.request`).
2. **Resource Scoping**: Permissions are restricted to specific glob patterns (e.g. `./docs/*`).
3. **Action Budgets**: Bounded session actions prevent runaway loops and runaway token costs.
4. **Delegation Controls**: A parent agent can only delegate capabilities it actually possesses (`child_agent ⊆ parent_agent`).
5. **Approval Gates**: Sensitive operations (e.g. `database.delete`, `email.send`, `shell.execute`) require verified, non-reusable administrative approval.

## Running the Example

```bash
python3 -m examples.agent_security.agent
```
