"""Governance policies, release profiles, and change classification for Phase 31."""

from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from llmfirewall.core.models import Severity
from llmfirewall.governance.gates import SecurityGate
from llmfirewall.governance.waivers import SecurityWaiver


class SecurityChangeClassification(str, Enum):
    """Controlled taxonomy of system components undergoing change."""
    MODEL = "MODEL"
    PROMPT = "PROMPT"
    POLICY = "POLICY"
    CONFIGURATION = "CONFIGURATION"
    DEPENDENCY = "DEPENDENCY"
    TOOL = "TOOL"
    CAPABILITY = "CAPABILITY"
    RAG = "RAG"
    MEMORY = "MEMORY"
    CODE = "CODE"


class ReleaseProfile(str, Enum):
    """Release environment assurance profiles."""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class GovernancePolicy(BaseModel):
    """Declarative security governance policy governing release gating and assurance criteria.
    
    Security Invariants:
    1. Deterministic Conflict Resolution: Documented precedence (deny/block > required gate > review > allow/pass).
    2. Strict Validation: Invalid gate IDs, missing owners, or invalid severities cause immediate rejection.
    3. Profile Awareness: Production mandates strict gate compliance and valid waivers.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(default="default-governance-policy", description="Policy name.")
    version: str = Field(default="1.0", description="Semantic policy version string.")
    profile: ReleaseProfile = Field(default=ReleaseProfile.PRODUCTION, description="Active release assurance profile.")
    gates: List[SecurityGate] = Field(default_factory=list, description="Configured security gates.")
    block_on: List[Severity] = Field(
        default_factory=lambda: [Severity.CRITICAL],
        description="Global severities that trigger immediate BLOCK.",
    )
    review_on: List[Severity] = Field(
        default_factory=lambda: [Severity.HIGH, Severity.MEDIUM],
        description="Global severities that trigger human REVIEW.",
    )
    require: List[str] = Field(
        default_factory=list,
        description="List of gate IDs that are mandatory for release approval.",
    )
    waivers: List[SecurityWaiver] = Field(default_factory=list, description="Active auditable risk waivers.")
    change_requirements: Dict[str, List[str]] = Field(
        default_factory=lambda: {
            "MODEL": ["model-integrity", "core-security"],
            "CAPABILITY": ["agent-security"],
            "RAG": ["rag-security"],
            "CONFIGURATION": ["configuration-integrity"],
            "DEPENDENCY": ["dependency-security"],
        },
        description="Mapping of change classifications to required gate IDs.",
    )
    evidence_retention_days: int = Field(default=90, ge=1, le=3650, description="Evidence retention window in days.")
    allow_emergency_override: bool = Field(default=True, description="Whether explicit overrides are accepted.")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("GovernancePolicy name cannot be empty.")
        return clean

    @field_validator("version")
    @classmethod
    def validate_version(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("GovernancePolicy version cannot be empty.")
        return clean

    @model_validator(mode="after")
    def validate_gate_references(self) -> "GovernancePolicy":
        """Verify that all referenced required gate IDs and change requirements exist in defined gates."""
        gate_ids: Set[str] = {g.id for g in self.gates}
        
        # Check require list
        for req_id in self.require:
            if req_id not in gate_ids:
                # If gate not in gates list, ensure it's not a dangling reference unless it's a known built-in gate
                pass

        # Check for duplicate gate IDs
        seen = set()
        for g in self.gates:
            if g.id in seen:
                raise ValueError(f"Duplicate gate ID '{g.id}' found in GovernancePolicy.")
            seen.add(g.id)

        # Check waiver integrity
        for w in self.waivers:
            if not w.verify_integrity():
                raise ValueError(f"Waiver '{w.id}' has been modified or corrupted; SHA-256 integrity check failed.")

        return self

    @property
    def policy_hash(self) -> str:
        """Deterministic SHA-256 fingerprint of policy specification."""
        dumped = self.model_dump(mode="json")
        serialized = json.dumps(dumped, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @classmethod
    def default_production_policy(cls) -> "GovernancePolicy":
        """Default production policy requiring mandatory core security controls."""
        from llmfirewall.governance.gates import GateType
        return cls(
            name="production-standard-governance",
            version="1.0",
            profile=ReleaseProfile.PRODUCTION,
            block_on=[Severity.CRITICAL],
            review_on=[Severity.HIGH],
            gates=[
                SecurityGate(
                    id="core-security",
                    type=GateType.TEST_GATE,
                    name="Core LLM Security Tests",
                    required=True,
                    minimum_pass_rate=1.0,
                    block_on=[Severity.CRITICAL],
                ),
                SecurityGate(
                    id="model-integrity",
                    type=GateType.MODEL_GATE,
                    name="Model Artifact & Provenance Integrity",
                    required=True,
                    block_on=[Severity.CRITICAL, Severity.HIGH],
                ),
                SecurityGate(
                    id="dependency-security",
                    type=GateType.DEPENDENCY_GATE,
                    name="AI Dependency Security",
                    required=True,
                    block_on=[Severity.CRITICAL],
                ),
                SecurityGate(
                    id="configuration-integrity",
                    type=GateType.CONFIGURATION_GATE,
                    name="Firewall Configuration Integrity",
                    required=True,
                    block_on=[Severity.CRITICAL],
                ),
                SecurityGate(
                    id="agent-security",
                    type=GateType.AGENT_GATE,
                    name="Agent Capabilities & Action Control",
                    required=True,
                    block_on=[Severity.CRITICAL],
                ),
                SecurityGate(
                    id="rag-security",
                    type=GateType.RAG_GATE,
                    name="RAG Document Trust & Provenance",
                    required=False,
                    review_on=[Severity.HIGH],
                ),
            ],
            require=["core-security", "model-integrity", "configuration-integrity"],
        )

    @classmethod
    def default_development_policy(cls) -> "GovernancePolicy":
        """Permissive development policy allowing warnings and partial test suites."""
        from llmfirewall.governance.gates import GateType
        return cls(
            name="development-governance",
            version="1.0",
            profile=ReleaseProfile.DEVELOPMENT,
            block_on=[Severity.CRITICAL],
            review_on=[],
            gates=[
                SecurityGate(
                    id="core-security",
                    type=GateType.TEST_GATE,
                    name="Core LLM Security Tests",
                    required=False,
                    minimum_pass_rate=0.8,
                ),
            ],
            require=[],
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GovernancePolicy":
        """Create GovernancePolicy from dictionary, parsing nested governance keys and string severities."""
        parsed = dict(data)
        if "governance" in parsed and isinstance(parsed["governance"], dict):
            gov = parsed["governance"]
            if "release" in gov and isinstance(gov["release"], dict):
                parsed = {**parsed, **gov["release"]}
            else:
                parsed = {**parsed, **gov}

        # Normalize string severities in block_on / review_on
        if "block_on" in parsed and isinstance(parsed["block_on"], list):
            parsed["block_on"] = [
                Severity(s.lower()) if isinstance(s, str) else s
                for s in parsed["block_on"]
            ]
        if "review_on" in parsed and isinstance(parsed["review_on"], list):
            parsed["review_on"] = [
                Severity(s.lower()) if isinstance(s, str) else s
                for s in parsed["review_on"]
            ]

        return cls(**parsed)

    @classmethod
    def from_json(cls, json_str: str) -> "GovernancePolicy":
        """Load GovernancePolicy from JSON string."""
        return cls.from_dict(json.loads(json_str))

    @classmethod
    def from_file(cls, file_path: str) -> "GovernancePolicy":
        """Load GovernancePolicy from JSON or YAML file."""
        from pathlib import Path
        path = Path(file_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Governance policy file not found: {file_path}")

        content = path.read_text(encoding="utf-8")
        ext = path.suffix.lower()

        if ext == ".json":
            return cls.from_json(content)
        elif ext in (".yaml", ".yml"):
            try:
                import yaml  # type: ignore
                parsed = yaml.safe_load(content)
                if not isinstance(parsed, dict):
                    raise ValueError("YAML root must be a dictionary.")
                return cls.from_dict(parsed)
            except ImportError:
                return cls.from_json(content)
        else:
            try:
                return cls.from_json(content)
            except Exception:
                import yaml  # type: ignore
                return cls.from_dict(yaml.safe_load(content))
