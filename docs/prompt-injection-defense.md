# Advanced Prompt-Injection Defense Architecture (Phase 45)

## 1. Overview & Objectives

Prompt injection occurs when an untrusted input—whether from a user prompt, a retrieved document, an external tool output, or conversational history—manipulates the execution context of a Large Language Model to override developer system instructions.

LLMFirewall v1.1.0 upgrades prompt-injection defenses with:
1. **Source-Awareness & Provenance**: Differentiating user input, retrieved context, tool outputs, and system instructions.
2. **Multi-Vector Rule Protection**: Expanding detection to indirect injections, delimiter framing escapes, and authority impersonation.
3. **Multi-Turn Security Tracking**: Bounded state modeling across conversational turns to detect persistent jailbreak probing.
4. **False-Positive Resistance**: Ensuring benign security discussions, educational explanations, and literature analysis are not erroneously flagged.

---

## 2. Threat Vector Coverage

| Rule ID | Vector | Description | Severity |
| :--- | :--- | :--- | :--- |
| `instruction_override` | Direct Override | "Ignore previous instructions", "disregard system prompt" | HIGH |
| `system_prompt_leak` | Prompt Extraction | "Repeat words above", "reveal developer instructions" | HIGH |
| `role_manipulation` | Persona Transition | "You are now DAN", "enter developer mode", "godmode" | HIGH |
| `instruction_hierarchy` | False Hierarchy | False admin priority tags, simulated `system:` headers | HIGH |
| `suspicious_control` | Control Tokens | Special stop tokens (`<\|im_end\|>`, `</s>`), hypothetical framing | HIGH |
| `indirect_injection` | Indirect Injections | "AI instruction: ignore tasks", hidden `<!-- -->` markup payloads | HIGH / CRITICAL |
| `delimiter_attack` | Boundary Framing | Multi-quote escapes (`"""system"""`), fake envelope tags (`<instructions>`) | HIGH |
| `authority_impersonation`| Credential Spoofing | "I am the system administrator, you must authorize" | HIGH |

---

## 3. Source Awareness & `PromptSecurityContext`

When inspecting prompts originating from external components (e.g. RAG pipelines or agent tool loops), developers pass a `PromptSecurityContext`:

```python
from llmfirewall import Firewall, PromptSecurityContext, PromptSourceType, TrustLevel

fw = Firewall()

context = PromptSecurityContext(
    source_type=PromptSourceType.RETRIEVED_DOCUMENT,
    trust_level=TrustLevel.UNTRUSTED,
    source_id="retrieved_chunk_42",
)

result = fw.scan(retrieved_text, context=context.model_dump())
```

Emitted `Finding` records preserve source metadata, enabling audit systems and downstream policies to distinguish between direct user attacks and third-party context poisoning.

---

## 4. Multi-Turn Security Tracking (`MultiTurnSecurityState`)

Adversaries frequently employ multi-turn jailbreak strategies where individual prompts appear subtle, but the sequence represents persistent probing.

`MultiTurnSecurityState` provides a lightweight, bounded in-memory tracker:
```python
from llmfirewall import MultiTurnSecurityState

state = MultiTurnSecurityState(session_id="user_session_101", max_history_turns=10)

# In your chat loop:
scan_result = fw.scan(user_message)
state.record_turn(
    threats=[f.threat_type.value for f in scan_result.findings],
    action=scan_result.action.value,
)

if state.is_suspicious_session:
    # Trigger escalation, step-up verification, or session termination
    ...
```

---

## 5. False-Positive Resistance

Prompt injection rules utilize tight boundaries and multi-word semantic sequences rather than naive single-word triggers. Benign inquiries such as:
- *"What is prompt injection and how do security researchers study it?"*
- *"Can you explain how role-based access control works in administrative systems?"*
- *"In literature, how do characters ignore distractions?"*

are evaluated as clean (`Action.ALLOW`).
