"""Rule Engine and declarative attack rules registry for Phase 33."""

from enum import Enum
import json
import logging
from typing import Any, Callable, Dict, List, Optional, Set, Union
from pydantic import BaseModel, ConfigDict, Field, field_validator

from llmfirewall.attack_graph.models import (
    AttackEvidence,
    AttackStep,
    ConfidenceLevel,
    ControlEffectiveness,
    EvidenceType,
    MitigationStatus,
)
from llmfirewall.attack_graph.techniques import default_technique_registry
from llmfirewall.graph.engine import KnowledgeGraph
from llmfirewall.graph.models import Node, NodeType, RelationshipType

logger = logging.getLogger("llmfirewall.attack_graph")


class AttackRule(BaseModel):
    """Declarative or programmatic rule inferring potential attack steps across graph entities."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    rule_id: str = Field(..., description="Unique rule identifier (e.g. R-AGENT-TO-TOOL).")
    name: str = Field(..., description="Descriptive rule name.")
    description: str = Field(..., description="Explanation of the causal attack pattern.")
    source_type: str = Field(..., description="Expected entity type of source node.")
    target_type: str = Field(..., description="Expected entity type of target node.")
    technique: str = Field(..., description="Technique ID exercised by this rule (e.g. T-TA-04).")
    requires: List[str] = Field(default_factory=list, description="Preconditions that must hold for rule to fire.")
    postconditions: List[str] = Field(default_factory=list, description="States or privileges gained if fired.")
    mitigations: List[str] = Field(default_factory=list, description="Control categories/types that neutralize this rule.")
    assumptions: List[str] = Field(default_factory=list, description="Explicit architectural assumptions.")
    confidence: ConfidenceLevel = Field(default=ConfidenceLevel.LOW, description="Feasibility confidence level.")

    @field_validator("rule_id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        clean = v.strip().upper()
        if not clean:
            raise ValueError("Rule ID cannot be blank.")
        return clean


class PreconditionEvaluator:
    """Evaluates whether specific precondition tokens hold true against the KnowledgeGraph."""

    @staticmethod
    def evaluate_condition(
        condition: str,
        kg: KnowledgeGraph,
        source: Node,
        target: Node,
    ) -> bool:
        cond = condition.strip().lower()

        if cond == "untrusted_input":
            # True if source is an entry point, user, or untrusted prompt
            return source.type in (NodeType.APPLICATION.value, NodeType.PROMPT.value, "entry_point", "user")

        if cond == "agent_tool_access":
            # True if source agent has CAN_CALL relationship to target tool
            rel = kg.get_relationship(source.id, RelationshipType.CAN_CALL.value, target.id)
            if rel:
                return True
            # Also check if connected via CAPABILITY
            for edge in kg.store.get_out_edges(source.id, rel_type=RelationshipType.CAN_ACCESS.value):
                if kg.get_relationship(edge.target, RelationshipType.CAN_CALL.value, target.id):
                    return True
            return False

        if cond == "missing_authorization":
            # Check if target tool or action lacks effective passing authorization control
            # 1. Check if tool is protected by authorization/sanitizer control
            protecting_edges = [
                e for e in kg.store.get_in_edges(target.id)
                if e.type in (RelationshipType.PROTECTS.value, "PROTECTED_BY")
            ] + [
                e for e in kg.store.get_out_edges(target.id)
                if e.type in (RelationshipType.PROTECTED_BY.value, "PROTECTED_BY")
            ]
            for edge in protecting_edges:
                ctrl_id = edge.source if edge.target == target.id else edge.target
                ctrl_node = kg.get_node(ctrl_id)
                if ctrl_node:
                    props = ctrl_node.properties or {}
                    mode = str(props.get("mode", "")).lower()
                    auth = props.get("authorization", False)
                    # If control is RBAC or explicit authorization and has passing tests, authorization exists!
                    if mode in ("rbac", "strict", "authorization") or auth is True:
                        # Check if failing
                        test_edges = kg.store.get_in_edges(ctrl_id, rel_type=RelationshipType.TESTS.value)
                        is_failing = any(
                            kg.get_node(te.source) and kg.get_node(te.source).properties.get("passed") is False
                            for te in test_edges
                        )
                        if not is_failing:
                            return False  # Strong passing authorization is PRESENT, so missing_authorization is FALSE!
            return True  # Authorization control is missing or unverified

        if cond == "access_to_sensitive_data":
            # True if target is database, storage, or document
            if target.type in (NodeType.DOCUMENT.value, NodeType.RAG_SOURCE.value):
                return True
            cat = str(target.properties.get("category", "")).lower()
            return "database" in cat or "storage" in cat or "sql" in cat

        if cond == "agent_capability_access":
            # True if agent CAN_ACCESS capability
            return bool(kg.get_relationship(source.id, RelationshipType.CAN_ACCESS.value, target.id))

        if cond == "missing_approval_gate":
            # True if target capability has high risk and no approval gate
            risk = str(target.properties.get("risk", "")).lower()
            requires_app = target.properties.get("require_approval", False)
            return (risk in ("high", "critical") and not requires_app)

        if cond == "unverified_document_ingestion":
            # True if document or RAG source has no verified hash
            return not bool(target.properties.get("sha256"))

        if cond == "has_security_finding":
            # True if target or source has active finding
            in_f = kg.store.get_in_edges(target.id, rel_type=RelationshipType.HAS_FINDING.value)
            out_f = kg.store.get_out_edges(target.id, rel_type=RelationshipType.AFFECTS.value)
            return bool(in_f or out_f)

        if cond == "vulnerable_dependency":
            # True if dependency node (source) has an active security finding attached
            for e in kg.store.get_in_edges(source.id):
                if e.type in (RelationshipType.AFFECTS.value, RelationshipType.HAS_FINDING.value):
                    return True
            for e in kg.store.get_out_edges(source.id):
                if e.type in (RelationshipType.AFFECTS.value, RelationshipType.HAS_FINDING.value):
                    return True
            return False

        # Default fallback: unknown condition treated as true with logged notice
        return True


STANDARD_RULES: List[AttackRule] = [
    AttackRule(
        rule_id="R-PROMPT-TO-AGENT",
        name="Ingress Prompt Injection to Agent",
        description="External user input or prompt payload attempts to hijack agent control logic.",
        source_type="application",
        target_type="agent",
        technique="T-PI-01",
        requires=["untrusted_input"],
        postconditions=["agent_instruction_override"],
        mitigations=["control:prompt_injection_detector", "control:input_sanitizer"],
        assumptions=["Agent directly processes user-controlled prompt without rigid input firewalling."],
        confidence=ConfidenceLevel.MEDIUM,
    ),
    AttackRule(
        rule_id="R-DOC-TO-AGENT",
        name="Indirect Document / RAG Context Injection",
        description="Untrusted document or retrieved context delivers indirect injection payload to agent.",
        source_type="rag_source",
        target_type="agent",
        technique="T-IPI-02",
        requires=["unverified_document_ingestion"],
        postconditions=["agent_context_poisoned"],
        mitigations=["control:rag_scanner", "control:document_trust_boundary"],
        assumptions=["Retrieved context is inserted verbatim into LLM prompt template without sanitization."],
        confidence=ConfidenceLevel.MEDIUM,
    ),
    AttackRule(
        rule_id="R-AGENT-TO-TOOL",
        name="Agent Unauthorized Tool Execution",
        description="Compromised agent invokes tools with unauthorized, malicious, or dangerous parameters.",
        source_type="agent",
        target_type="tool",
        technique="T-TA-04",
        requires=["agent_tool_access", "missing_authorization"],
        postconditions=["tool_execution_compromise"],
        mitigations=["control:tool_validator", "control:tool_authorization", "control:approval_gate"],
        assumptions=["Tool accepts agent-generated arguments without independent server-side validation."],
        confidence=ConfidenceLevel.HIGH,
    ),
    AttackRule(
        rule_id="R-TOOL-TO-DATA",
        name="Tool Sensitive Database / Storage Access",
        description="Tool executes commands or queries against sensitive data storage.",
        source_type="tool",
        target_type="tool",
        technique="T-DE-06",
        requires=["access_to_sensitive_data"],
        postconditions=["sensitive_data_exposure"],
        mitigations=["control:secret_detector", "control:pii_detector", "control:sql_sanitizer"],
        assumptions=["Underlying datastore permits broad query or retrieval privileges."],
        confidence=ConfidenceLevel.HIGH,
    ),
    AttackRule(
        rule_id="R-AGENT-TO-CAPABILITY",
        name="Agent Capability Privilege Expansion",
        description="Agent executes actions exercising elevated capabilities exceeding normal bounds.",
        source_type="agent",
        target_type="capability",
        technique="T-PE-05",
        requires=["agent_capability_access", "missing_approval_gate"],
        postconditions=["elevated_privilege_granted"],
        mitigations=["control:capability_authorizer", "control:approval_gate"],
        assumptions=["Capability invocation does not enforce human-in-the-loop approval."],
        confidence=ConfidenceLevel.MEDIUM,
    ),
    AttackRule(
        rule_id="R-AGENT-TO-AGENT",
        name="Multi-Agent Message Poisoning",
        description="Primary agent passes hijacked or manipulated task payload to downstream worker agent.",
        source_type="agent",
        target_type="agent",
        technique="T-IO-03",
        requires=["untrusted_input"],
        postconditions=["downstream_agent_hijack"],
        mitigations=["control:runtime_guard", "control:context_isolation"],
        assumptions=["Inter-agent communication lacks bilateral trust verification."],
        confidence=ConfidenceLevel.MEDIUM,
    ),
    AttackRule(
        rule_id="R-DEP-TO-APP",
        name="Vulnerable Supply-Chain Dependency Exploitation",
        description="Known vulnerability in software package impacts application or agent security boundary.",
        source_type="dependency",
        target_type="application",
        technique="T-SC-12",
        requires=["vulnerable_dependency"],
        postconditions=["application_subversion"],
        mitigations=["control:dependency_scanner", "control:sbom_verifier"],
        assumptions=["Vulnerable code paths in dependency are reachable during runtime."],
        confidence=ConfidenceLevel.MEDIUM,
    ),
]


class AttackRuleRegistry:
    """Registry maintaining active attack inference rules with strict validation."""

    def __init__(self, rules_version: str = "1.0") -> None:
        self.rules_version = rules_version
        self._rules: Dict[str, AttackRule] = {}
        for r in STANDARD_RULES:
            self.register(r)

    def register(self, rule: AttackRule) -> None:
        """Register and validate a new attack rule."""
        self.validate_rule(rule)
        self._rules[rule.rule_id] = rule

    def unregister(self, rule_id: str) -> bool:
        """Unregister an attack rule by ID."""
        clean_id = rule_id.strip().upper()
        return self._rules.pop(clean_id, None) is not None

    def get(self, rule_id: str) -> Optional[AttackRule]:
        """Fetch rule by ID."""
        return self._rules.get(rule_id.strip().upper())

    def list_rules(self) -> List[AttackRule]:
        """List all active rules."""
        return list(self._rules.values())

    def validate_rule(self, rule: AttackRule) -> None:
        """Reject invalid techniques, node types, cyclic dependencies, or malformed configs."""
        if not rule.rule_id:
            raise ValueError("Rule ID cannot be blank.")

        # 1. Validate Technique exists
        if not default_technique_registry.exists(rule.technique):
            raise ValueError(
                f"Attack rule '{rule.rule_id}' references unknown technique '{rule.technique}'. "
                f"Valid techniques: {[t.id for t in default_technique_registry.list_techniques()]}"
            )

        # 2. Validate Node Types
        valid_types = {t.value for t in NodeType}.union({"user", "entry_point"})
        if rule.source_type not in valid_types:
            raise ValueError(f"Attack rule '{rule.rule_id}' has invalid source_type '{rule.source_type}'.")
        if rule.target_type not in valid_types:
            raise ValueError(f"Attack rule '{rule.rule_id}' has invalid target_type '{rule.target_type}'.")

        # 3. Reject cyclic self-loop rules with identical preconditions and postconditions
        if (
            rule.source_type == rule.target_type
            and rule.requires
            and rule.postconditions
            and set(rule.requires) == set(rule.postconditions)
        ):
            raise ValueError(f"Attack rule '{rule.rule_id}' defines an ungrounded cyclic loop dependency.")

    def find_rules_for(self, source_type: str, target_type: str) -> List[AttackRule]:
        """Find matching rules connecting source_type to target_type."""
        s_clean = source_type.strip().lower()
        t_clean = target_type.strip().lower()
        return [
            r for r in self._rules.values()
            if r.source_type == s_clean and r.target_type == t_clean
        ]

    def evaluate_hop(
        self,
        kg: KnowledgeGraph,
        source: Node,
        target: Node,
    ) -> List[AttackStep]:
        """Evaluate applicable rules connecting source to target entity."""
        matching_rules = self.find_rules_for(source.type, target.type)
        candidate_steps: List[AttackStep] = []

        for rule in matching_rules:
            # Check all required preconditions
            preconditions_met = True
            for req in rule.requires:
                if not PreconditionEvaluator.evaluate_condition(req, kg, source, target):
                    preconditions_met = False
                    break

            if not preconditions_met:
                continue

            tech = default_technique_registry.get(rule.technique)
            t_name = tech.name if tech else rule.technique

            # Determine mitigating controls protecting the target
            protecting_controls: List[str] = []
            for edge in kg.store.get_in_edges(target.id):
                if edge.type in (RelationshipType.PROTECTS.value, "PROTECTED_BY"):
                    protecting_controls.append(edge.source)
            for edge in kg.store.get_out_edges(target.id):
                if edge.type in (RelationshipType.PROTECTED_BY.value, "PROTECTED_BY"):
                    protecting_controls.append(edge.target)

            # Deduplicate control IDs
            protecting_controls = sorted(list(set(protecting_controls)))

            step = AttackStep(
                technique=rule.technique,
                technique_name=t_name,
                source=source.id,
                target=target.id,
                preconditions=rule.requires,
                postconditions=rule.postconditions,
                evidence=[
                    AttackEvidence(
                        evidence_type=EvidenceType.GRAPH,
                        source_id=f"{source.id}->{target.id}",
                        description=f"Rule {rule.rule_id} triggered across {source.type} '{source.id}' and {target.type} '{target.id}'.",
                        verified=True,
                    )
                ],
                confidence=rule.confidence,
                mitigations=protecting_controls or rule.mitigations,
                mitigation_status=MitigationStatus.MITIGATED if protecting_controls else MitigationStatus.UNMITIGATED,
                assumptions=rule.assumptions,
            )
            candidate_steps.append(step)

        return candidate_steps

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AttackRuleRegistry":
        """Instantiate registry from serialized configuration dictionary."""
        version = data.get("rules_version", "1.0")
        registry = cls(rules_version=version)
        raw_rules = data.get("attack_rules", [])
        for r_raw in raw_rules:
            rule = AttackRule(**r_raw)
            registry.register(rule)
        return registry

    @classmethod
    def from_json(cls, json_content: str) -> "AttackRuleRegistry":
        """Parse registry from JSON string."""
        data = json.loads(json_content)
        if not isinstance(data, dict):
            raise ValueError("JSON attack rules root must be a dictionary.")
        return cls.from_dict(data)

    @classmethod
    def from_yaml(cls, yaml_content: str) -> "AttackRuleRegistry":
        """Parse registry from YAML or JSON-compatible content."""
        try:
            import yaml
            parsed = yaml.safe_load(yaml_content)
        except ImportError:
            try:
                parsed = json.loads(yaml_content)
            except Exception:
                raise ValueError("YAML parsing requires 'PyYAML'. Install with `pip install PyYAML` or use JSON format.")
        if not isinstance(parsed, dict):
            raise ValueError("YAML attack rules root must be a dictionary.")
        return cls.from_dict(parsed)
