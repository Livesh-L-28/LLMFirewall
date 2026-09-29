"""Declarative policy schema, validator, and evaluator for Phase 39: AI Security Runtime Protection."""

from __future__ import annotations

from enum import Enum
import fnmatch
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from llmfirewall.core.exceptions import LLMFirewallError
from llmfirewall.protection.models import PolicyDecision, PolicyMode, RuntimeRequest


class PolicyParseError(LLMFirewallError):
    """Raised when a declarative protection policy fails parsing or validation."""
    pass


class ProtectionCondition(BaseModel):
    """Conditional predicates evaluated against a RuntimeRequest."""
    tool: Optional[Union[str, List[str]]] = None
    agent: Optional[Union[str, List[str]]] = None
    data_classification: Optional[Union[str, List[str]]] = None  # secret, sensitive, internal, public
    max_input_length: Optional[int] = None
    max_rag_chunks: Optional[int] = None
    action_type: Optional[str] = None
    pattern: Optional[str] = None
    custom: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(extra="ignore")


RuleCondition = ProtectionCondition


class ProtectionRule(BaseModel):
    """A discrete policy rule specifying conditions and an enforcement action."""
    name: str
    description: Optional[str] = None
    when: ProtectionCondition = Field(default_factory=ProtectionCondition)
    action: PolicyDecision = PolicyDecision.BLOCK
    reason: Optional[str] = None
    enabled: bool = True

    model_config = ConfigDict(extra="ignore")


    @field_validator("action", mode="before")
    @classmethod
    def normalize_action(cls, val: Any) -> PolicyDecision:
        if isinstance(val, PolicyDecision):
            return val
        s = str(val).upper().strip()
        if s in ("REQUIRE_AUTHORIZATION", "AUTHORIZE", "GATE"):
            return PolicyDecision.REVIEW
        if s in PolicyDecision.__members__:
            return PolicyDecision[s]
        return PolicyDecision.BLOCK


class RateLimitRule(BaseModel):
    """Rate limit configuration within a policy."""
    key_by: str = "user"  # "user", "session", "agent", "tool", "ip", "api_key"
    max_requests: int = 60
    window_seconds: int = 60
    enabled: bool = True

    model_config = ConfigDict(extra="ignore")


class ProtectionPolicy(BaseModel):
    """Declarative runtime protection policy document."""
    id: str
    description: Optional[str] = None
    version: str = "1.0.0"
    mode: PolicyMode = PolicyMode.ENFORCE
    rules: List[ProtectionRule] = Field(default_factory=list)
    rate_limits: List[RateLimitRule] = Field(default_factory=list)
    max_input_length: int = 50000
    inspect_input: bool = True
    inspect_tools: bool = True
    inspect_output: bool = True
    inspect_rag: bool = True
    inspect_memory: bool = True

    model_config = ConfigDict(extra="ignore")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ProtectionPolicy:
        """Parses and validates a policy dictionary."""
        # Check if root has "policy" wrapper key
        if "policy" in data and isinstance(data["policy"], dict):
            pol_data = data["policy"]
            # merge any root rules
            if "rules" in data and "rules" not in pol_data:
                pol_data["rules"] = data["rules"]
            if "rate_limits" in data and "rate_limits" not in pol_data:
                pol_data["rate_limits"] = data["rate_limits"]
            return cls.model_validate(pol_data)
        return cls.model_validate(data)

    @classmethod
    def from_yaml(cls, yaml_content: str) -> ProtectionPolicy:
        """Parses and validates a YAML policy document."""
        try:
            parsed = yaml.safe_load(yaml_content)
            if not isinstance(parsed, dict):
                raise PolicyParseError("Policy YAML must define a dictionary document.")
            return cls.from_dict(parsed)
        except Exception as e:
            raise PolicyParseError(f"Failed to parse protection policy YAML: {e}") from e

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> ProtectionPolicy:
        """Loads and validates a policy from a YAML or JSON file."""
        p = Path(path).resolve()
        if not p.is_file():
            raise PolicyParseError(f"Policy file not found: {p}")
        text = p.read_text(encoding="utf-8")
        return cls.from_yaml(text)

    def validate_policy(self) -> List[str]:
        """Validates policy rules and returns a list of semantic warnings or issues."""
        warnings: List[str] = []
        if not self.id:
            warnings.append("Policy missing unique ID.")
        rule_names = set()
        for rule in self.rules:
            if rule.name in rule_names:
                warnings.append(f"Duplicate rule name: '{rule.name}'.")
            rule_names.add(rule.name)
        return warnings


def get_default_production_policy() -> ProtectionPolicy:
    """Returns a recommended default production protection policy."""
    return ProtectionPolicy(
        id="production-default",
        description="Standard production protection policy with tool authorization, secret blocking, and input inspection.",
        mode=PolicyMode.ENFORCE,
        rules=[
            ProtectionRule(
                name="protect-database-tools",
                description="Require authorization review for privileged database tools.",
                when=RuleCondition(tool=["*database*", "*sql*", "*drop*", "*delete*"]),
                action=PolicyDecision.REVIEW,
                reason="Privileged database capability access requires authorization check.",
            ),
            ProtectionRule(
                name="block-dangerous-exec-tools",
                description="Block dangerous operating system and code execution tools.",
                when=RuleCondition(tool=["*bash*", "*shell*", "*exec*", "*cmd*", "rm", "*rmdir*", "*shutdown*", "*terminate*", "*recursive*"]),
                action=PolicyDecision.BLOCK,
                reason="Direct execution of system shell, admin shutdown, or arbitrary execution tools is prohibited.",
            ),
            ProtectionRule(
                name="block-raw-secrets",
                description="Block output or memory containing raw credentials or secrets.",
                when=RuleCondition(data_classification=["secret", "credential"]),
                action=PolicyDecision.BLOCK,
                reason="Detected prohibited secret or credential in data stream.",
            ),
            ProtectionRule(
                name="redact-sensitive-output",
                description="Redact sensitive PII or data from final output.",
                when=RuleCondition(data_classification=["sensitive", "pii"]),
                action=PolicyDecision.REDACT,
                reason="Redaction applied to protect sensitive PII.",
            ),
        ],
        rate_limits=[
            RateLimitRule(key_by="user", max_requests=100, window_seconds=60),
            RateLimitRule(key_by="agent", max_requests=1000, window_seconds=60),
        ],
        max_input_length=100000,
        inspect_input=True,
        inspect_tools=True,
        inspect_output=True,
        inspect_rag=True,
        inspect_memory=True,
    )
