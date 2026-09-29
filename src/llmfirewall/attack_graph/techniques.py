"""AI Attack Technique definitions and metadata registry (Phase 33)."""

from typing import Dict, List, Optional
from llmfirewall.attack_graph.models import AttackTechnique


STANDARD_TECHNIQUES: Dict[str, AttackTechnique] = {
    "T-PI-01": AttackTechnique(
        id="T-PI-01",
        name="Direct Prompt Injection",
        description="Adversary crafts prompts containing instructions designed to override system instructions and hijack model behavior.",
        prerequisites=["untrusted_input_channel", "llm_processing"],
        affected_assets=["agent", "model", "prompt"],
        detection_methods=["prompt_injection_detector", "instruction_hierarchy_rule", "role_manipulation_rule"],
        mitigations=["control:prompt_injection_detector", "policy:strict_guardrails", "control:input_sanitizer"],
    ),
    "T-IPI-02": AttackTechnique(
        id="T-IPI-02",
        name="Indirect Prompt Injection",
        description="Adversary embeds malicious control directives into external data, web pages, or documents ingested by an agent or RAG pipeline.",
        prerequisites=["external_data_ingestion", "agent_reading_external_content"],
        affected_assets=["agent", "rag_source", "document", "tool"],
        detection_methods=["rag_scanner", "context_trust_boundary", "indirect_injection_detector"],
        mitigations=["control:rag_scanner", "control:document_trust_boundary", "control:context_isolation"],
    ),
    "T-IO-03": AttackTechnique(
        id="T-IO-03",
        name="Instruction Override",
        description="Adversary causes the model to ignore developer-provided system prompts or boundary rules through adversarial framing.",
        prerequisites=["direct_or_indirect_prompt_injection"],
        affected_assets=["agent", "prompt"],
        detection_methods=["instruction_override_rule", "system_prompt_leak_rule"],
        mitigations=["control:prompt_injection_detector", "control:output_verifier"],
    ),
    "T-TA-04": AttackTechnique(
        id="T-TA-04",
        name="Tool Abuse & Parameter Tampering",
        description="Adversary manipulates an agent into executing tools with unauthorized or malicious arguments (e.g. SQLi, SSRF, command injection).",
        prerequisites=["agent_tool_access", "unvalidated_tool_arguments"],
        affected_assets=["tool", "capability", "application"],
        detection_methods=["tool_security_engine", "ssrf_detector", "path_security_detector", "command_injection_rule"],
        mitigations=["control:tool_validator", "control:ssrf_protection", "control:tool_authorization"],
    ),
    "T-PE-05": AttackTechnique(
        id="T-PE-05",
        name="Privilege Escalation",
        description="Adversary tricks an agent into exercising actions or capabilities exceeding its designated authorization boundaries.",
        prerequisites=["agent_capability_access", "missing_or_bypassed_capability_guard"],
        affected_assets=["agent", "capability", "application"],
        detection_methods=["capability_engine", "action_authorization_verifier", "approval_gate"],
        mitigations=["control:capability_authorizer", "control:approval_gate", "control:action_budget"],
    ),
    "T-DE-06": AttackTechnique(
        id="T-DE-06",
        name="Sensitive Data Exfiltration",
        description="Adversary forces the model or tool to transmit confidential internal data, secrets, or PII to an external location.",
        prerequisites=["access_to_sensitive_data", "network_egress_or_untrusted_output"],
        affected_assets=["agent", "tool", "document", "application"],
        detection_methods=["pii_detector", "secret_detector", "egress_monitor"],
        mitigations=["control:secret_detector", "control:pii_detector", "control:redaction_engine", "control:egress_filter"],
    ),
    "T-CP-07": AttackTechnique(
        id="T-CP-07",
        name="Context Poisoning",
        description="Adversary injects misleading, contradictory, or malicious information into the shared conversation context or session memory.",
        prerequisites=["shared_session_or_multi_turn_history"],
        affected_assets=["agent", "memory", "runtime"],
        detection_methods=["context_security_verifier", "runtime_session_monitor"],
        mitigations=["control:context_integrity_guard", "control:session_isolation"],
    ),
    "T-MP-08": AttackTechnique(
        id="T-MP-08",
        name="Memory Poisoning",
        description="Adversary stores crafted payloads into long-term persistent agent memory to affect subsequent agent invocations across sessions.",
        prerequisites=["agent_persistent_memory_write"],
        affected_assets=["agent", "memory"],
        detection_methods=["memory_security_engine", "persistent_memory_verifier"],
        mitigations=["control:memory_guard", "control:memory_authorization"],
    ),
    "T-RP-09": AttackTechnique(
        id="T-RP-09",
        name="RAG Knowledge Base Poisoning",
        description="Adversary manipulates documents or embeddings within the RAG corpus to induce biased, unsafe, or deceptive agent responses.",
        prerequisites=["unverified_document_ingestion", "vector_search"],
        affected_assets=["rag_source", "document", "agent"],
        detection_methods=["document_hash_verifier", "rag_scanner", "context_provenance_tracker"],
        mitigations=["control:rag_provenance_verifier", "control:document_integrity_checker"],
    ),
    "T-MM-10": AttackTechnique(
        id="T-MM-10",
        name="Model Artifact & Weight Manipulation",
        description="Adversary tampers with model weights, fine-tuning checkpoints, or adapter artifacts in the supply chain.",
        prerequisites=["unverified_model_checkpoint", "supply_chain_access"],
        affected_assets=["model", "application"],
        detection_methods=["model_integrity_verifier", "sha256_verification"],
        mitigations=["control:model_hash_verifier", "control:artifact_integrity_gate"],
    ),
    "T-CE-11": AttackTechnique(
        id="T-CE-11",
        name="Credential & Secret Exposure",
        description="Adversary extracts API keys, credentials, or authentication tokens hardcoded in configuration or exposed via prompt leaks.",
        prerequisites=["credentials_in_context_or_properties"],
        affected_assets=["agent", "configuration", "prompt", "model"],
        detection_methods=["secret_detector", "system_prompt_leak_rule"],
        mitigations=["control:secret_detector", "control:secret_sanitizer"],
    ),
    "T-SC-12": AttackTechnique(
        id="T-SC-12",
        name="Supply-Chain Package Compromise",
        description="Vulnerable or compromised third-party software dependencies (e.g. PyPI packages) introduce backdoor execution into the AI pipeline.",
        prerequisites=["vulnerable_dependency", "unpinned_manifest"],
        affected_assets=["dependency", "application", "agent"],
        detection_methods=["dependency_scanner", "sbom_verifier", "supply_chain_engine"],
        mitigations=["control:dependency_scanner", "control:sbom_verifier", "control:supply_chain_gate"],
    ),
}


class AttackTechniqueRegistry:
    """Registry managing known AI attack techniques with runtime extensibility."""

    def __init__(self) -> None:
        self._techniques: Dict[str, AttackTechnique] = dict(STANDARD_TECHNIQUES)

    def get(self, technique_id: str) -> Optional[AttackTechnique]:
        return self._techniques.get(technique_id.strip().upper())

    def list_techniques(self) -> List[AttackTechnique]:
        return list(self._techniques.values())

    def register(self, technique: AttackTechnique) -> None:
        clean_id = technique.id.strip().upper()
        self._techniques[clean_id] = technique

    def unregister(self, technique_id: str) -> bool:
        clean_id = technique_id.strip().upper()
        return self._techniques.pop(clean_id, None) is not None

    def exists(self, technique_id: str) -> bool:
        return technique_id.strip().upper() in self._techniques


# Default shared singleton instance
default_technique_registry = AttackTechniqueRegistry()
