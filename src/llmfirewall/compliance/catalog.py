"""Control catalog, framework pack definitions, safe parsers, and cross-framework mappings for Phase 36."""

import hashlib
import json
import logging
import os
from pathlib import Path
import threading
from typing import Any, Dict, List, Optional, Set, Union
import yaml

from llmfirewall.compliance.models import (
    ApplicabilityStatus,
    ComplianceControl,
    ComplianceFramework,
    CrossFrameworkMapping,
    MappingType,
    sanitize_compliance_metadata,
)

logger = logging.getLogger("llmfirewall.compliance.catalog")

# Maximum permitted control pack file size (5MB)
MAX_PACK_FILE_SIZE = 5 * 1024 * 1024


# -----------------------------------------------------------------------------
# Standard Built-In AI Security Baseline Framework (v1.0.0)
# -----------------------------------------------------------------------------

AI_SECURITY_BASELINE_CONTROLS = [
    ComplianceControl(
        id="ai-baseline:AM-01",
        framework_id="ai-security-baseline",
        control_id="AM-01",
        title="AI Asset Inventory & Continuous Discovery",
        category="asset_management",
        domain="AI Asset Management",
        description="Organizations must continuously discover, catalog, and maintain an authoritative inventory of AI models, autonomous agents, tools, memory buffers, and RAG sources.",
        requirements=[
            "All AI assets across configuration, dependencies, and runtime must be registered with stable identifiers.",
            "Asset provenance and environment classifications must be tracked.",
        ],
        evidence_requirements=["asset_inventory", "configuration"],
        applicability={"asset_types": ["application", "agent", "model", "tool", "rag_source", "memory_store"]},
    ),
    ComplianceControl(
        id="ai-baseline:MD-01",
        framework_id="ai-security-baseline",
        control_id="MD-01",
        title="Model Provenance & Change Detection",
        category="model_security",
        domain="Model Security",
        description="Foundation and fine-tuned models must track provider provenance, version immutability, and trigger re-evaluation upon version changes.",
        requirements=[
            "Model provider, version, and deployment endpoint must be recorded.",
            "Model version modifications must generate audit events and require re-evaluation.",
        ],
        evidence_requirements=["model_provenance", "security_test"],
        applicability={"asset_types": ["model"]},
    ),
    ComplianceControl(
        id="ai-baseline:AG-01",
        framework_id="ai-security-baseline",
        control_id="AG-01",
        title="Autonomous Agent Capability & Instruction Boundaries",
        category="agent_security",
        domain="Agent Security",
        description="Autonomous agents must operate within explicit operational capability budgets, instruction guardrails, and role boundaries.",
        requirements=[
            "System prompts and operational instructions must be versioned and protected.",
            "Agent capabilities and max step budgets must be enforced.",
        ],
        evidence_requirements=["policy", "configuration", "security_test"],
        applicability={"asset_types": ["agent"]},
    ),
    ComplianceControl(
        id="ai-baseline:PS-01",
        framework_id="ai-security-baseline",
        control_id="PS-01",
        title="Prompt Injection & Jailbreak Defense",
        category="prompt_security",
        domain="Prompt Security",
        description="AI entry points must inspect incoming prompts and system contexts for direct and indirect prompt injection attacks.",
        requirements=[
            "Prompt injection detection must inspect inputs before LLM inference.",
            "Empirical security tests must verify detector resilience against injection payloads.",
        ],
        evidence_requirements=["security_control", "security_test", "configuration"],
        applicability={"asset_types": ["application", "agent"]},
    ),
    ComplianceControl(
        id="ai-baseline:TS-01",
        framework_id="ai-security-baseline",
        control_id="TS-01",
        title="Tool Execution Validation & Sandboxing",
        category="tool_security",
        domain="Tool Security",
        description="Agent tool executions must validate input arguments, enforce parameter schemas, and isolate execution environments.",
        requirements=[
            "Tool call parameters must be strictly validated against registered schemas.",
            "High-risk tools (e.g. database, code execution) must enforce sandboxed execution.",
        ],
        evidence_requirements=["security_control", "security_test", "configuration"],
        applicability={"asset_types": ["tool"]},
    ),
    ComplianceControl(
        id="ai-baseline:AC-01",
        framework_id="ai-security-baseline",
        control_id="AC-01",
        title="Agent Tool Authorization & Least Privilege",
        category="access_control",
        domain="Access Control",
        description="Agent access to tools, APIs, and data sources must be governed by explicit authorization policies and RBAC guardrails.",
        requirements=[
            "Tool call authorization policy must be configured and enforced.",
            "Unauthorized tool invocation attempts must be blocked and audited.",
            "Empirical tests must verify authorization enforcement.",
        ],
        evidence_requirements=["authorization_policy", "authorization_test", "production_configuration"],
        applicability={"asset_types": ["agent", "tool"]},
    ),
    ComplianceControl(
        id="ai-baseline:DS-01",
        framework_id="ai-security-baseline",
        control_id="DS-01",
        title="Sensitive Data & Exfiltration Protection",
        category="data_security",
        domain="Data Security",
        description="AI inputs, outputs, and tool responses must be guarded against data leakage, secret exposure, and unauthorized exfiltration.",
        requirements=[
            "Secrets, private keys, and credentials must be detected and blocked.",
            "Data flow transitions between tools and external endpoints must enforce egress filters.",
        ],
        evidence_requirements=["security_control", "security_test"],
        applicability={"asset_types": ["application", "agent", "tool"]},
    ),
    ComplianceControl(
        id="ai-baseline:RS-01",
        framework_id="ai-security-baseline",
        control_id="RS-01",
        title="RAG Ingestion Access Control & Poisoning Defense",
        category="rag_security",
        domain="RAG Security",
        description="Retrieval-Augmented Generation sources must enforce document tenant isolation, access controls, and poisoning defenses.",
        requirements=[
            "Retrieved documents must enforce user or tenant access boundaries.",
            "RAG ingestion pipelines must validate document sources against poisoning.",
        ],
        evidence_requirements=["security_control", "security_test", "policy"],
        applicability={"asset_types": ["rag_source", "agent"]},
    ),
    ComplianceControl(
        id="ai-baseline:MS-01",
        framework_id="ai-security-baseline",
        control_id="MS-01",
        title="Persistent Memory Isolation & Poisoning Protection",
        category="memory_security",
        domain="Memory Security",
        description="Conversational memory buffers and semantic stores must enforce session isolation, retention limits, and poisoning defenses.",
        requirements=[
            "Persistent memory buffers must isolate tenant contexts.",
            "Memory stores must be tested against memory poisoning and indirect prompt injection.",
        ],
        evidence_requirements=["security_control", "security_test"],
        applicability={"asset_types": ["memory_store", "agent"]},
    ),
    ComplianceControl(
        id="ai-baseline:SC-01",
        framework_id="ai-security-baseline",
        control_id="SC-01",
        title="AI Dependency & Supply Chain Verification",
        category="supply_chain",
        domain="Supply Chain Security",
        description="AI software packages, libraries, and model artifacts must maintain cryptographic integrity and be scanned for known vulnerabilities.",
        requirements=[
            "Dependency packages must have verified versions and integrity metadata.",
            "High-severity dependency vulnerabilities must be identified and resolved.",
        ],
        evidence_requirements=["asset_inventory", "configuration"],
        applicability={"asset_types": ["package", "model"]},
    ),
    ComplianceControl(
        id="ai-baseline:MO-01",
        framework_id="ai-security-baseline",
        control_id="MO-01",
        title="Audit Logging & Security Telemetry",
        category="monitoring",
        domain="Monitoring",
        description="Security-relevant AI events, policy decisions, tool calls, and posture evaluations must be immutably recorded.",
        requirements=[
            "Firewall scan decisions and policy violations must emit structured audit events.",
            "Security telemetry must track metrics with bounded cardinality.",
        ],
        evidence_requirements=["audit_event", "configuration"],
        applicability={"asset_types": ["application", "agent"]},
    ),
    ComplianceControl(
        id="ai-baseline:IR-01",
        framework_id="ai-security-baseline",
        control_id="IR-01",
        title="Security Incident Detection & Blast Radius Analysis",
        category="incident_response",
        domain="Incident Response",
        description="Security incidents must be traceable through knowledge and attack graphs to quantify exposure and blast radius.",
        requirements=[
            "Multi-step attack paths reaching critical assets must be mapped and quantified.",
            "Incident blast radius across tools and models must be calculable.",
        ],
        evidence_requirements=["attack_graph", "posture"],
        applicability={"asset_types": ["application", "agent", "tool"]},
    ),
    ComplianceControl(
        id="ai-baseline:ST-01",
        framework_id="ai-security-baseline",
        control_id="ST-01",
        title="Continuous Empirical Security Testing",
        category="testing",
        domain="Testing",
        description="AI systems and defensive guardrails must be continuously evaluated using automated security testing suites.",
        requirements=[
            "Security tests must target prompt injection, tool authorization, and PII protection.",
            "Test results must be evaluated for freshness when underlying assets change.",
        ],
        evidence_requirements=["security_test"],
        applicability={"asset_types": ["application", "agent", "tool", "model"]},
    ),
    ComplianceControl(
        id="ai-baseline:GV-01",
        framework_id="ai-security-baseline",
        control_id="GV-01",
        title="Policy-as-Code & Version Governance",
        category="governance",
        domain="Governance",
        description="Security policies must be declared as version-controlled code, assigned to assets, and checked for contradictory rules.",
        requirements=[
            "Policy documents must be versioned, validated, and active.",
            "Policy conflicts must be detected and reported without silent resolution.",
        ],
        evidence_requirements=["policy", "configuration"],
        applicability={"asset_types": ["application", "agent", "tool"]},
    ),
    ComplianceControl(
        id="ai-baseline:PV-01",
        framework_id="ai-security-baseline",
        control_id="PV-01",
        title="PII Redaction & Privacy Guardrails",
        category="privacy",
        domain="Privacy",
        description="Personally Identifiable Information (PII) must be detected and redacted from user prompts, LLM generations, and tool logs.",
        requirements=[
            "PII detectors must identify emails, phone numbers, IP addresses, and credit cards.",
            "PII redaction policies must be enforced at entry and exit points.",
        ],
        evidence_requirements=["security_control", "security_test", "configuration"],
        applicability={"asset_types": ["application", "agent"]},
    ),
]


def create_ai_security_baseline_framework() -> ComplianceFramework:
    """Instantiate the standard, built-in AI Security Baseline Framework (v1.0.0)."""
    ctrl_dict = {c.id: c for c in AI_SECURITY_BASELINE_CONTROLS}
    domains = sorted(list(set(c.domain for c in AI_SECURITY_BASELINE_CONTROLS)))
    return ComplianceFramework(
        id="ai-security-baseline",
        name="AI Security Baseline",
        version="1.0.0",
        description="Comprehensive, evidence-based security control framework for AI applications, autonomous agents, and RAG pipelines.",
        source="LLMFirewall Security Standards",
        publisher="LLMFirewall Project",
        domains=domains,
        controls=ctrl_dict,
        metadata={"maturity": "production", "domains_count": len(domains)},
    )


# -----------------------------------------------------------------------------
# Control Catalog
# -----------------------------------------------------------------------------

class ControlCatalog:
    """Thread-safe catalog managing compliance frameworks, controls, and cross-framework mappings."""

    def __init__(self, catalog_version: str = "1.0.0", load_defaults: bool = True) -> None:
        self.catalog_version = catalog_version
        self._lock = threading.RLock()
        # Storage: framework_id -> version -> ComplianceFramework
        self._frameworks: Dict[str, Dict[str, ComplianceFramework]] = {}
        self._cross_mappings: List[CrossFrameworkMapping] = []

        if load_defaults:
            base_fw = create_ai_security_baseline_framework()
            self.register_framework(base_fw)

    # -------------------------------------------------------------------------
    # Framework Management
    # -------------------------------------------------------------------------

    def register_framework(self, framework: ComplianceFramework) -> None:
        """Register a versioned compliance framework into the catalog."""
        with self._lock:
            fid = framework.id.strip().lower()
            ver = framework.version.strip()
            if fid not in self._frameworks:
                self._frameworks[fid] = {}
            self._frameworks[fid][ver] = framework

    def get_framework(self, framework_id: str, version: Optional[str] = None) -> Optional[ComplianceFramework]:
        """Retrieve framework by ID and optional version (defaults to highest or latest version)."""
        with self._lock:
            fid = framework_id.strip().lower()
            ver_map = self._frameworks.get(fid)
            if not ver_map:
                return None
            if version:
                return ver_map.get(version.strip())
            # Return latest registered version
            latest_ver = sorted(ver_map.keys())[-1]
            return ver_map[latest_ver]

    def list_frameworks(self) -> List[ComplianceFramework]:
        """List all registered framework versions."""
        with self._lock:
            return [fw for ver_map in self._frameworks.values() for fw in ver_map.values()]

    def list_framework_ids(self) -> List[str]:
        with self._lock:
            return sorted(list(self._frameworks.keys()))

    # -------------------------------------------------------------------------
    # Control Management
    # -------------------------------------------------------------------------

    def get_control(self, control_id: str, framework_id: Optional[str] = None) -> Optional[ComplianceControl]:
        """Retrieve control by full ID ('ai-baseline:AC-01') or (framework_id, control_id)."""
        with self._lock:
            clean_id = control_id.strip()
            # If full ID given with ':'
            if ":" in clean_id:
                parts = clean_id.split(":", 1)
                fid, cid = parts[0].strip().lower(), parts[1].strip()
                fw = self.get_framework(fid)
                if fw:
                    ctrl = fw.controls.get(clean_id) or fw.controls.get(f"{fw.id}:{cid}")
                    if ctrl:
                        return ctrl
            # If framework_id explicitly provided
            if framework_id:
                fw = self.get_framework(framework_id)
                if fw:
                    for c in fw.controls.values():
                        if c.control_id.lower() == clean_id.lower() or c.id.lower() == clean_id.lower():
                            return c

            # Search across all frameworks
            for fw in self.list_frameworks():
                for c in fw.controls.values():
                    if c.id.lower() == clean_id.lower() or c.control_id.lower() == clean_id.lower():
                        return c
            return None

    def search_controls(
        self,
        query: str = "",
        domain: Optional[str] = None,
        category: Optional[str] = None,
        framework_id: Optional[str] = None,
    ) -> List[ComplianceControl]:
        """Search controls across frameworks by text query, domain, or category."""
        q_lower = query.strip().lower()
        results: List[ComplianceControl] = []

        with self._lock:
            target_frameworks = [self.get_framework(framework_id)] if framework_id else self.list_frameworks()
            for fw in target_frameworks:
                if not fw:
                    continue
                for c in fw.controls.values():
                    if domain and c.domain.lower() != domain.strip().lower():
                        continue
                    if category and c.category.lower() != category.strip().lower():
                        continue
                    if q_lower:
                        matches = (
                            q_lower in c.id.lower()
                            or q_lower in c.title.lower()
                            or q_lower in c.description.lower()
                            or any(q_lower in r.lower() for r in c.requirements)
                        )
                        if not matches:
                            continue
                    results.append(c)

        return sorted(results, key=lambda c: c.id)

    # -------------------------------------------------------------------------
    # Cross-Framework Mapping
    # -------------------------------------------------------------------------

    def register_cross_mapping(self, mapping: CrossFrameworkMapping) -> None:
        """Register cross-framework control mapping."""
        with self._lock:
            self._cross_mappings.append(mapping)

    def add_cross_mapping(
        self,
        source_control_id: str,
        target_control_id: str,
        mapping_type: MappingType = MappingType.RELATED,
        confidence: float = 1.0,
        rationale: str = "",
        source: str = "LLMFirewall",
    ) -> CrossFrameworkMapping:
        """Create and register a cross-framework mapping."""
        m = CrossFrameworkMapping(
            source_control_id=source_control_id,
            target_control_id=target_control_id,
            mapping_type=mapping_type,
            confidence=confidence,
            rationale=rationale,
            source=source,
        )
        self.register_cross_mapping(m)
        return m

    def get_cross_mappings(self, control_id: str) -> List[CrossFrameworkMapping]:
        """Retrieve all mappings where control is source or target."""
        clean_id = control_id.strip().lower()
        with self._lock:
            return [
                m for m in self._cross_mappings
                if m.source_control_id.lower() == clean_id or m.target_control_id.lower() == clean_id
            ]

    # -------------------------------------------------------------------------
    # Safe Control Pack Loading & Export
    # -------------------------------------------------------------------------

    def load_pack_from_dict(self, data: Dict[str, Any]) -> ComplianceFramework:
        """Parse, validate, and register a declarative control pack dictionary."""
        if not isinstance(data, dict):
            raise ValueError("Control pack must be a valid dictionary/object.")

        fw_data = data.get("framework") or data
        fid = str(fw_data.get("id") or "").strip().lower()
        if not fid:
            raise ValueError("Control pack missing required 'id' (or 'framework.id').")
        name = str(fw_data.get("name") or fid).strip()
        version = str(fw_data.get("version") or "1.0.0").strip()
        description = str(fw_data.get("description") or "").strip()
        source = str(fw_data.get("source") or "Custom Organization").strip()
        publisher = fw_data.get("publisher")

        raw_controls = data.get("controls") or []
        if not isinstance(raw_controls, list):
            raise ValueError("'controls' must be a list of control specifications.")

        controls_dict: Dict[str, ComplianceControl] = {}
        seen_control_ids: Set[str] = set()

        for c_entry in raw_controls:
            if not isinstance(c_entry, dict):
                raise ValueError("Each control in pack must be a dictionary.")

            short_cid = str(c_entry.get("id") or c_entry.get("control_id") or "").strip()
            if not short_cid:
                raise ValueError("Control in pack missing required 'id'.")

            # Check for duplicate control IDs within the framework (Section 68)
            norm_cid = short_cid.lower()
            if norm_cid in seen_control_ids:
                raise ValueError(f"Duplicate control ID '{short_cid}' detected in framework '{fid}'. Control IDs must be unique.")
            seen_control_ids.add(norm_cid)

            full_id = f"{fid}:{short_cid}" if ":" not in short_cid else short_cid
            title = str(c_entry.get("title") or short_cid).strip()
            desc = str(c_entry.get("description") or "").strip()
            cat = str(c_entry.get("category") or "general").strip()
            dom = str(c_entry.get("domain") or "General").strip()
            reqs = [str(r).strip() for r in (c_entry.get("requirements") or [])]
            evid_reqs = [str(e).strip() for e in (c_entry.get("evidence_requirements") or c_entry.get("evidence") or [])]
            app = c_entry.get("applicability") or {}

            ctrl = ComplianceControl(
                id=full_id,
                framework_id=fid,
                control_id=short_cid,
                title=title,
                description=desc,
                category=cat,
                domain=dom,
                requirements=reqs,
                evidence_requirements=evid_reqs,
                applicability=app,
            )
            controls_dict[full_id] = ctrl

        domains = sorted(list(set(c.domain for c in controls_dict.values())))

        fw = ComplianceFramework(
            id=fid,
            name=name,
            version=version,
            description=description,
            source=source,
            publisher=publisher,
            domains=domains,
            controls=controls_dict,
            metadata=sanitize_compliance_metadata(data.get("metadata") or {}),
        )

        self.register_framework(fw)
        return fw

    def load_pack_from_file(self, file_path: str, format_type: Optional[str] = None) -> ComplianceFramework:
        """Safely load and validate a control pack from a YAML or JSON file."""
        p = Path(file_path).resolve()
        if not p.exists() or not p.is_file():
            raise FileNotFoundError(f"Control pack file not found: {file_path}")

        file_size = p.stat().st_size
        if file_size > MAX_PACK_FILE_SIZE:
            raise ValueError(f"Control pack file size ({file_size} bytes) exceeds maximum limit of {MAX_PACK_FILE_SIZE} bytes.")

        text_content = p.read_text(encoding="utf-8")

        # Determine format
        fmt = (format_type or p.suffix.lstrip(".").lower())
        if fmt in ("yaml", "yml"):
            try:
                parsed = yaml.safe_load(text_content)
            except Exception as exc:
                raise ValueError(f"Failed to parse YAML control pack: {exc}")
        else:
            try:
                parsed = json.loads(text_content)
            except Exception as exc:
                raise ValueError(f"Failed to parse JSON control pack: {exc}")

        return self.load_pack_from_dict(parsed)

    def export_pack_to_file(
        self,
        framework_id: str,
        file_path: str,
        version: Optional[str] = None,
        format_type: str = "json",
    ) -> None:
        """Export framework controls to a JSON or YAML control pack."""
        fw = self.get_framework(framework_id, version=version)
        if not fw:
            raise KeyError(f"Framework '{framework_id}' not found in catalog.")

        p = Path(file_path).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "framework": {
                "id": fw.id,
                "name": fw.name,
                "version": fw.version,
                "description": fw.description,
                "source": fw.source,
                "publisher": fw.publisher,
                "domains": fw.domains,
                "checksum": fw.checksum,
            },
            "controls": [
                {
                    "id": c.control_id,
                    "title": c.title,
                    "category": c.category,
                    "domain": c.domain,
                    "description": c.description,
                    "requirements": c.requirements,
                    "evidence_requirements": c.evidence_requirements,
                    "applicability": c.applicability,
                }
                for c in sorted(fw.controls.values(), key=lambda c: c.id)
            ],
            "metadata": fw.metadata,
        }

        if format_type.lower() in ("yaml", "yml"):
            p.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
        else:
            p.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
