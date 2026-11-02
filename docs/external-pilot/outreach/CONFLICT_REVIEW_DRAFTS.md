# LLMFirewall-Core: Conflict-Review Track Evaluation Notes & Conditional Drafts

> [!CAUTION] Strict Maintainer Authorization Required
> **THESE MATERIALS ARE STRICTLY FOR INTERNAL MAINTAINER REVIEW.**
> **DO NOT SEND, DISTRIBUTE, OR TRANSMIT ANY INVITATION FROM THIS TRACK WITHOUT EXPLICIT WRITTEN MAINTAINER AUTHORIZATION.**
> Candidates on this track possess organizational affiliations or maintain peer products in the LLM security domain.

---

## 1. Principles of the Conflict-Review Track

External security evaluations frequently benefit most from the scrutiny of peer researchers and domain specialists who actively design vulnerability probes and guardrail systems. However, engaging developers affiliated with commercial AI platforms or competing open-source security SDKs introduces distinct governance and competitive sensitivities.

To safeguard both the evaluator and LLMFirewall-Core, the following non-negotiable principles apply to this track:

1. **Strictly Individual Capacity**: Evaluators are invited purely in their personal capacity as open-source security researchers and software engineers—never as corporate representatives or commercial proxies for their employers.
2. **Zero Competitive Intelligence Solicitation**: The maintainer and project must **never** request, solicit, or accept proprietary internal threat models, closed-source rulesets, private customer exploit corpora, or unreleased commercial roadmaps.
3. **Public Synthetic Benchmarks Only**: All evaluation tasks must run exclusively on public, synthetic, open-source test datasets (e.g., standard regex test cases, synthetic injection phrases, public mock transports).
4. **Transparent Peer Engagement**: The project transparently acknowledges the candidate's existing contributions to the security ecosystem, approaching the interaction as open-source peer review rather than sales discovery or commercial recruitment.
5. **Right of Exclusion**: If the maintainer determines that competitive sensitivity outweighs the value of technical feedback, candidates on this track may be excluded without prejudice.

---

## 2. Detailed Conflict Assessments & Handling Guidance

---

### Candidate 1: Leon Derczynski (`@leondz`) — Slot PILOT-009

- **Assigned Persona**: Application Security Engineer
- **Public Profile**: `https://github.com/leondz`
- **Key Project**: Original author and creator of `garak` ([`NVIDIA/garak`](https://github.com/NVIDIA/garak)), [`leondz/autoredteam`](https://github.com/leondz/autoredteam)
- **Organizational Affiliation**: Principal Research Scientist in LLM Security at NVIDIA; Associate Professor / PI at ITU Copenhagen.

#### Conflict Analysis
- **Nature of Affiliation**: Leon leads `garak` under NVIDIA. NVIDIA also develops and maintains `NeMo Guardrails` (`NVIDIA-NeMo/Guardrails`), a major open-source conversational safety framework.
- **Sensitivity Risk**: While `garak` is an evaluation/scanning tool (which probes LLMs for vulnerabilities) rather than an in-process runtime firewall like LLMFirewall, NVIDIA has active commercial and strategic interests across the entire LLM safety stack.
- **Adversarial Evaluation Value**: Outstanding. As the pioneer of automated LLM vulnerability scanning, Leon’s feedback on deterministic rule precedence (`BLOCK > REDACT > WARN > ALLOW`), zero-retention safe audit logging (`safe_dict`), and static vs. semantic evasion boundaries would be of the highest technical quality.

#### Recommended Maintainer Action
- **Recommendation**: **Invite conditionally in personal research capacity**.
- **Scope Restriction**: Confine evaluation strictly to Task B (scan accuracy on synthetic injections), Task E (safe logging scrubbing), and Task F (error ergonomics). Do not request comparative benchmarks against NeMo Guardrails. Do not seek corporate NVIDIA authorization.

---

### Candidate 2: Oleksandr Yaremchuk (`@asofter`) — Slot PILOT-010

- **Assigned Persona**: Application Security Engineer
- **Public Profile**: `https://github.com/asofter`
- **Key Project**: Co-founder of Laiyer AI; original creator and primary author of `llm-guard` ([`protectai/llm-guard`](https://github.com/protectai/llm-guard))
- **Organizational Affiliation**: Protect AI (via Laiyer AI acquisition).

#### Conflict Analysis
- **Nature of Affiliation**: Protect AI's `llm-guard` is a direct open-source and commercial peer to `llmfirewall-core`. Both projects focus on in-process prompt injection detection, PII anonymization, and secret scrubbing.
- **Sensitivity Risk**: High competitive sensitivity. Reaching out to a direct competitor's creator could be misconstrued as commercial posturing, competitive intelligence gathering, or marketing intrusion.
- **Adversarial Evaluation Value**: Exceptionally high. Oleksandr pioneered production guardrail ergonomics in Python. His critique of LLMFirewall’s Redaction Invariant (`result.processed_text`), caching TTL, and policy execution order would provide world-class technical scrutiny.

#### Recommended Maintainer Action
- **Maintainer Decision Options**:
  - *Option A (Peer-to-Peer Academic / OSS Scrutiny)*: Maintainer explicitly approves outreach using a tailored, collegial invitation that explicitly acknowledges `llm-guard`, emphasizes open-source technical comparison on public synthetic datasets, and disclaims any commercial competition.
  - *Option B (Risk Avoidance)*: Maintainer chooses to exclude Slot `PILOT-010` from external pilot recruitment and replace it with an unconflicted reserve candidate (e.g. `RES-001` or an independent security engineer).
- **Scope Restriction**: If invited, testing must be restricted to open-source developer ergonomics and published PyPI mechanics (`llmfirewall-core==1.4.0`). Never request Protect AI internal metrics.

---

### Candidate 3: Erick Galinkin (`@erickgalinkin`) — Slot RES-002

- **Assigned Persona**: Application Security Engineer (Reserve)
- **Public Profile**: `https://github.com/erickgalinkin`
- **Key Project**: Core contributor to [`NVIDIA/garak`](https://github.com/NVIDIA/garak); contributor to [`NVIDIA-NeMo/Guardrails`](https://github.com/NVIDIA-NeMo/Guardrails)
- **Organizational Affiliation**: Principal AI Security Researcher at NVIDIA.

#### Conflict Analysis
- **Nature of Affiliation**: In addition to `garak`, Erick has directly contributed code to `NVIDIA-NeMo/Guardrails`.
- **Sensitivity Risk**: Direct contributor to a conversational guardrails framework.
- **Adversarial Evaluation Value**: High expertise in adversarial threat modeling and guardrail policy evaluation.

#### Recommended Maintainer Action
- **Recommendation**: **Hold in Reserve**. Only engage if primary AppSec candidate `PILOT-009` declines or is unavailable, and follow the same conditional peer-review protocols.

---

### Candidate 4: Willem Pienaar (`@woop`) — Slot RES-003

- **Assigned Persona**: AI Agents / Security (Reserve)
- **Public Profile**: `https://github.com/woop`
- **Key Project**: Creator of [`feast-dev/feast`](https://github.com/feast-dev/feast); original creator of `Rebuff.ai` ([`protectai/rebuff`](https://github.com/protectai/rebuff))
- **Organizational Affiliation**: Co-founder & CTO at Cleric; historical association with Rebuff / Protect AI.

#### Conflict Analysis
- **Nature of Affiliation**: Willem created Rebuff (the pioneer in self-hardening prompt injection detection with canary tokens). Rebuff was acquired by Protect AI. Willem is currently CTO of Cleric (building autonomous AI agents).
- **Sensitivity Risk**: Low to Moderate. Willem is no longer actively maintaining Rebuff and is operating as CTO of an AI agent company.
- **Adversarial Evaluation Value**: Exceptional dual perspective—deep historical expertise in prompt injection defense heuristics combined with current leadership in agentic tool-use systems.

#### Recommended Maintainer Action
- **Recommendation**: **Qualified Reserve for AI Agents (`PILOT-007`/`PILOT-008`) or AppSec**. Can be activated as a standard participant with standard synthetic safeguards.

---

## 3. Conditional Invitation Drafts (Subject to Maintainer Approval)

---

### Draft 1: Leon Derczynski (`@leondz`) — Slot PILOT-009

```text
Subject: Open-source peer review: Evaluating in-process prompt & secret guardrails

Hi Leon,

I’m reaching out from the open-source LLMFirewall-Core project (https://github.com/Livesh-L-28/LLMFirewall). We are developing an in-process, deterministic security library for Python applications interacting with LLMs.

I follow your pioneering research in LLM vulnerability assessment and your work leading `garak`. In building LLMFirewall, we have prioritized deterministic in-process enforcement, sub-millisecond scan latency, and zero-retention safe audit logging (`result.safe_dict()`). Because you have established the standard methodology for adversarial vulnerability scanning, your critical feedback on our pre-execution detection semantics and threat model boundaries would be invaluable to the open-source community.

We are organizing an external developer pilot (7–14 days, ~30–45 minutes total) focusing on our published stable release:
`pip install llmfirewall-core==1.4.0`

Scope of technical evaluation:
- Inbound prompt injection inspection heuristics and static boundary limitations (see docs/external-pilot/KNOWN_LIMITATIONS.md).
- Outbound secret and credential leak interception.
- Local audit log sanitization (`result.safe_dict()`).
- Error handling ergonomics and diagnostic traces (`DecisionTrace`).

Evaluation guardrails:
- We invite you strictly in your personal capacity as an open-source researcher and engineer.
- We do not seek or request any corporate affiliation, endorsement, or proprietary intelligence from NVIDIA.
- All testing runs locally using public synthetic prompts. No confidential data or proprietary exploits are requested.
- Participation is 100% voluntary, unpaid, and open-source. You may decline or withdraw at any time.

If you are open to taking a look at our evaluation guide, please let me know and I will share the walkthrough (docs/external-pilot/DEVELOPER_EVALUATION_GUIDE.md).

Best regards,
[Maintainer Name / LLMFirewall Team]
https://github.com/Livesh-L-28/LLMFirewall
```

---

### Draft 2: Oleksandr Yaremchuk (`@asofter`) — Slot PILOT-010

```text
Subject: Open-source peer review: Technical evaluation of LLMFirewall-Core v1.4.0

Hi Oleksandr,

I’m reaching out from the open-source LLMFirewall-Core project (https://github.com/Livesh-L-28/LLMFirewall). We are developing a zero-dependency, in-process security guardrail library for Python LLM applications.

I have followed your work as the original creator of `llm-guard`. You established foundational patterns for guardrail ergonomics, PII anonymization, and prompt injection mitigation in the Python ecosystem. While our projects share a common focus on LLM application safety, we approach this through a zero-external-dependency, deterministic in-process architecture designed for sub-millisecond ASGI and client middleware.

Because of your deep domain experience with guardrail edge cases, we would welcome your critical, unfiltered feedback as a peer open-source maintainer on our published PyPI release:
`pip install llmfirewall-core==1.4.0`

What you would evaluate:
- Pre-execution input scanning and prompt injection detection heuristics.
- The Redaction Invariant (`result.processed_text`) and secret scrubbing behavior (`result.safe_dict()`).
- In-process execution overhead and ASGI middleware integration (`LLMFirewallASGIMiddleware`).
- Developer experience, error clarity, and known detection limitations (docs/external-pilot/KNOWN_LIMITATIONS.md).

Clear peer boundaries:
- We invite you strictly in your personal capacity as an open-source engineer.
- We do not ask for or collect any proprietary intelligence, closed-source rulesets, or internal Protect AI metrics.
- All exercises run locally on synthetic mock inputs.
- Participation is 100% voluntary, unpaid, and implies zero partnership or endorsement. You are completely free to decline without explanation.

If you are interested in reviewing the evaluation walkthrough, let me know and I will provide the guide (docs/external-pilot/DEVELOPER_EVALUATION_GUIDE.md).

Best regards,
[Maintainer Name / LLMFirewall Team]
https://github.com/Livesh-L-28/LLMFirewall
```
