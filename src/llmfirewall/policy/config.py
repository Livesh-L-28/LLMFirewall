"""Policy-as-Code schema, rule models, condition operators, and serialization."""

import json
from enum import Enum
import math
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from llmfirewall.core.exceptions import LLMFirewallError
from llmfirewall.core.models import Action, Finding, RiskScore, Severity, ThreatType
from llmfirewall.policy.redaction_config import RedactionConfig


class PolicyValidationError(LLMFirewallError):
    """Raised when a Policy or PolicyRule fails validation."""
    pass


class LogicalOperator(str, Enum):
    """Logical conjunction for multi-condition evaluation."""
    AND = "and"
    OR = "or"


class RuleCondition(BaseModel):
    """Declarative condition evaluated against security metadata.
    
    Supported condition targets:
    - threat_type: Filter by ThreatType (e.g. 'prompt_injection', 'secret', 'pii')
    - detector: Filter by detector_name (e.g. 'prompt_injection_detector', 'pii')
    - min_severity: Minimum Severity required (e.g. Severity.HIGH)
    - max_severity: Maximum Severity allowed
    - min_risk_score: Composite risk score lower bound in [0.0, 1.0]
    - max_risk_score: Composite risk score upper bound in [0.0, 1.0]
    - min_findings_count: Minimum number of findings required
    - direction: Traffic direction filter ('input' or 'output')
    - category: Specific granular category match (e.g. 'email', 'api_key')
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    threat_type: Optional[ThreatType] = Field(default=None, description="Match specific ThreatType")
    detector: Optional[str] = Field(default=None, description="Match specific detector name")
    category: Optional[str] = Field(default=None, description="Match specific category/rule ID")
    min_severity: Optional[Severity] = Field(default=None, description="Minimum finding severity")
    max_severity: Optional[Severity] = Field(default=None, description="Maximum finding severity")
    min_risk_score: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Minimum composite risk score")
    max_risk_score: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Maximum composite risk score")
    min_findings_count: Optional[int] = Field(default=None, ge=1, description="Minimum number of findings required")
    direction: Optional[str] = Field(default=None, description="'input', 'output', or None for both")
    tool: Optional[str] = Field(default=None, description="Match specific tool name (e.g. 'shell', 'web_fetch')")
    tool_permission: Optional[str] = Field(default=None, description="Match required tool permission (e.g. 'execute', 'network')")
    destination_class: Optional[str] = Field(default=None, description="Match destination classification (e.g. 'private_network', 'localhost')")
    # Phase 27: RAG and Context condition fields
    source_type: Optional[str] = Field(default=None, description="Match context/document source type (e.g. 'retrieved_document', 'memory')")
    trust_level: Optional[str] = Field(default=None, description="Match trust classification (e.g. 'untrusted', 'controlled')")
    source_id: Optional[str] = Field(default=None, description="Match specific source or repository identifier")

    @field_validator("min_risk_score", "max_risk_score")
    @classmethod
    def validate_finite_number(cls, v: Optional[float]) -> Optional[float]:
        if v is not None and (math.isnan(v) or math.isinf(v)):
            raise ValueError("Risk score conditions must be finite numbers, not NaN or Infinity")
        return v

    @field_validator("direction")
    @classmethod
    def validate_direction(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            cleaned = v.strip().lower()
            if cleaned not in ("input", "output"):
                raise ValueError(f"Condition direction must be 'input' or 'output', got '{v}'")
            return cleaned
        return v

    def matches(
        self,
        findings: List[Finding],
        risk_score: RiskScore,
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Evaluate condition against findings, risk score, and scan context."""
        # 1. Direction Filter
        if self.direction is not None and context:
            req_dir = context.get("direction")
            if req_dir and req_dir.lower() != self.direction:
                return False

        # 1b. Tool-level Context Filters
        if self.tool is not None:
            ctx_tool = context.get("tool") if context else None
            if not ctx_tool or str(ctx_tool).strip().lower() != self.tool.strip().lower():
                return False

        if self.tool_permission is not None:
            ctx_perms = context.get("tool_permissions", []) if context else []
            ctx_perms_set = {str(p).strip().lower() for p in ctx_perms}
            if self.tool_permission.strip().lower() not in ctx_perms_set:
                return False

        if self.destination_class is not None:
            ctx_dest = context.get("destination_class") if context else None
            if not ctx_dest or str(ctx_dest).strip().lower() != self.destination_class.strip().lower():
                return False

        # 1c. RAG & Context Filters (Phase 27)
        if self.source_type is not None:
            ctx_st = context.get("source_type") if context else None
            if not ctx_st or str(ctx_st).strip().lower() != self.source_type.strip().lower():
                return False

        if self.trust_level is not None:
            ctx_tl = context.get("trust_level") if context else None
            if not ctx_tl or str(ctx_tl).strip().lower() != self.trust_level.strip().lower():
                return False

        if self.source_id is not None:
            ctx_sid = context.get("source_id") if context else None
            if not ctx_sid or str(ctx_sid).strip().lower() != self.source_id.strip().lower():
                return False

        # 2. Risk Score bounds
        if self.min_risk_score is not None:
            if risk_score.score < self.min_risk_score:
                return False

        if self.max_risk_score is not None:
            if risk_score.score > self.max_risk_score:
                return False

        # 3. Minimum findings count
        if self.min_findings_count is not None:
            if len(findings) < self.min_findings_count:
                return False

        # 4. Finding-level criteria (threat_type, detector, category, severity)
        has_finding_criteria = (
            self.threat_type is not None
            or self.detector is not None
            or self.category is not None
            or self.min_severity is not None
            or self.max_severity is not None
        )

        if has_finding_criteria:
            if not findings:
                return False

            matched_any = False
            for f in findings:
                if self.threat_type is not None and f.threat_type != self.threat_type:
                    continue
                if self.detector is not None and f.detector_name != self.detector:
                    continue
                if self.category is not None:
                    cat = f.metadata.get("pii_category") or f.metadata.get("rule_id") or f.category
                    if cat != self.category:
                        continue
                if self.min_severity is not None and f.severity < self.min_severity:
                    continue
                if self.max_severity is not None and f.severity > self.max_severity:
                    continue

                matched_any = True
                break

            if not matched_any:
                return False

        return True


class PolicyRule(BaseModel):
    """Declarative Policy-as-Code rule mapping conditions to an Action with priority."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(..., min_length=1, max_length=128, description="Unique rule identifier")
    name: Optional[str] = Field(default=None, description="Human-friendly rule name")
    description: str = Field(default="", description="Explanation of security rule intent")
    action: Action = Field(..., description="Action to trigger if conditions match")
    priority: int = Field(default=100, ge=1, le=1000, description="Priority ranking (higher evaluated first)")
    enabled: bool = Field(default=True, description="Whether rule is currently active")

    # Backward-compatible direct conditions
    threat_type: Optional[ThreatType] = Field(default=None, description="Target ThreatType")
    min_severity: Optional[Severity] = Field(default=None, description="Minimum finding severity")
    min_risk_score: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Composite risk threshold")
    direction: Optional[str] = Field(default=None, description="'input', 'output', or None")

    # Advanced multi-condition system
    conditions: List[RuleCondition] = Field(
        default_factory=list,
        description="List of compound conditions for this rule",
    )
    operator: LogicalOperator = Field(
        default=LogicalOperator.AND,
        description="Conjunction used when multiple conditions are defined ('and' or 'or')",
    )

    @field_validator("id")
    @classmethod
    def validate_id_format(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("Rule ID cannot be blank")
        return clean

    def evaluate(
        self,
        findings: List[Finding],
        risk_score: RiskScore,
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Evaluate this rule against scan findings, composite risk, and context."""
        if not self.enabled:
            return False

        # 1. If explicit conditions list is populated, evaluate via operator
        if self.conditions:
            results = [cond.matches(findings, risk_score, context=context) for cond in self.conditions]
            if self.operator == LogicalOperator.AND:
                return all(results)
            return any(results)

        # 2. Fallback to direct fields (backward compatibility with Phase 9)
        direct_condition = RuleCondition(
            threat_type=self.threat_type,
            min_severity=self.min_severity,
            min_risk_score=self.min_risk_score,
            direction=self.direction,
        )
        return direct_condition.matches(findings, risk_score, context=context)


class Policy(BaseModel):
    """Versioned, declarative Policy-as-Code document."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(default="custom_policy", min_length=1, max_length=128, description="Policy name")
    version: str = Field(default="1.0", max_length=32, description="Semantic policy version")
    description: str = Field(default="", description="Purpose and scope of this policy")
    rules: List[PolicyRule] = Field(default_factory=list, description="Declarative security rules")
    allowed_tools: Optional[List[str]] = Field(
        default=None,
        description="Optional tool allowlist. If set, any tool not in this list is blocked.",
    )
    denied_tools: Optional[List[str]] = Field(
        default=None,
        description="Optional tool denylist. Any tool in this list is strictly blocked.",
    )
    default_action: Action = Field(default=Action.ALLOW, description="Fallback action when no rules trigger")
    auto_redact_on_warn: bool = Field(default=True, description="Apply redaction if action is WARN or REDACT")
    redaction_config: Optional[RedactionConfig] = Field(default=None, description="Custom redaction tokens")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadata / author / environment notes")

    @model_validator(mode="after")
    def validate_rules_uniqueness(self) -> "Policy":
        """Verify rule IDs are unique within this policy."""
        seen_ids: Set[str] = set()
        for r in self.rules:
            if r.id in seen_ids:
                raise PolicyValidationError(f"Duplicate rule id '{r.id}' found in policy '{self.name}'.")
            seen_ids.add(r.id)
        return self

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Policy":
        """Load and validate policy from a Python dictionary."""
        try:
            return cls(**data)
        except Exception as exc:
            raise PolicyValidationError(f"Policy validation failed: {exc}") from exc

    @classmethod
    def from_json(cls, json_str: str) -> "Policy":
        """Load and validate policy from a JSON string."""
        try:
            parsed = json.loads(json_str)
            return cls.from_dict(parsed)
        except json.JSONDecodeError as exc:
            raise PolicyValidationError(f"Invalid JSON in policy document: {exc}") from exc

    @classmethod
    def from_file(cls, file_path: Union[str, Path]) -> "Policy":
        """Load and validate policy from a JSON or YAML file safely."""
        path = Path(file_path).resolve()
        if not path.exists():
            raise PolicyValidationError(f"Policy file not found: '{file_path}'")
        if not path.is_file():
            raise PolicyValidationError(f"Path is not a file: '{file_path}'")

        content = path.read_text(encoding="utf-8")
        ext = path.suffix.lower()

        if ext == ".json":
            return cls.from_json(content)
        elif ext in (".yaml", ".yml"):
            try:
                import yaml  # type: ignore
                parsed = yaml.safe_load(content)
                if not isinstance(parsed, dict):
                    raise PolicyValidationError("YAML policy root must be a mapping/dictionary")
                return cls.from_dict(parsed)
            except ImportError:
                # If PyYAML is not installed, parse simple JSON-compatible YAML or guide user
                try:
                    return cls.from_json(content)
                except Exception:
                    raise PolicyValidationError(
                        "YAML parsing requires 'PyYAML'. Install with `pip install PyYAML` or use JSON policy files."
                    )
            except Exception as exc:
                raise PolicyValidationError(f"Failed to parse YAML policy: {exc}") from exc
        else:
            # Attempt JSON first, then YAML
            try:
                return cls.from_json(content)
            except Exception:
                raise PolicyValidationError(
                    f"Unsupported policy format '{ext}'. Supported formats: .json, .yaml, .yml"
                )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize policy to a dictionary."""
        return self.model_dump(mode="json")

    def to_json(self, indent: int = 2) -> str:
        """Serialize policy to formatted JSON."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


# Backward compatibility alias
PolicyConfig = Policy
