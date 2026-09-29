"""Strongly typed, validated configuration models for LLMFirewall."""

import logging
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from llmfirewall.core.exceptions import ConfigurationError
from llmfirewall.core.models import Action, Severity, ThreatType
from llmfirewall.policy.config import Policy, PolicyConfig, PolicyRule
from llmfirewall.policy.engine import get_default_policy
from llmfirewall.policy.redaction_config import RedactionConfig
from llmfirewall.risk.config import RiskConfig


class PromptInjectionConfig(BaseModel):
    """Configuration for Prompt Injection and Jailbreak detection."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = Field(
        default=True,
        description="Whether prompt injection and jailbreak detection is active.",
    )
    rules: Optional[List[str]] = Field(
        default=None,
        description="Optional subset of injection rule IDs to activate (e.g. ['instruction_override']).",
    )


class PIIConfig(BaseModel):
    """Configuration for Personally Identifiable Information (PII) detection."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = Field(
        default=True,
        description="Whether PII detection is active.",
    )
    categories: Optional[Set[str]] = Field(
        default=None,
        description="Set of enabled PII categories ('email', 'phone', 'ip', 'payment').",
    )
    store_matched_text: bool = Field(
        default=False,
        description="Whether to store raw matched PII text in findings. Defaults to False for privacy.",
    )

    @field_validator("categories")
    @classmethod
    def validate_categories(cls, v: Optional[Set[str]]) -> Optional[Set[str]]:
        if v is not None:
            valid_categories = {"email", "phone", "ip", "payment"}
            invalid = v - valid_categories
            if invalid:
                raise ValueError(
                    f"Invalid PII category: {invalid}. Supported categories: {valid_categories}"
                )
        return v


class SecretConfig(BaseModel):
    """Configuration for Secret, Token, and Credential detection."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = Field(
        default=True,
        description="Whether secret and credential detection is active.",
    )
    rules: Optional[List[str]] = Field(
        default=None,
        description="Optional subset of secret rule IDs to activate (e.g. ['api_key', 'token']).",
    )


class DetectorConfig(BaseModel):
    """Configuration for all detection modules."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    prompt_injection: PromptInjectionConfig = Field(
        default_factory=PromptInjectionConfig,
        description="Prompt injection detector configuration.",
    )
    pii: PIIConfig = Field(
        default_factory=PIIConfig,
        description="PII detector configuration.",
    )
    secrets: SecretConfig = Field(
        default_factory=SecretConfig,
        description="Secret detector configuration.",
    )
    fail_fast: bool = Field(
        default=False,
        description="If True, halt scan on first detector error; if False, isolate errors.",
    )


class AuditConfig(BaseModel):
    """Configuration for security audit logging and SIEM integration."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = Field(
        default=False,
        description="Whether automatic audit logging is enabled on scans.",
    )
    logger_name: str = Field(
        default="llmfirewall.audit",
        description="Name of the audit logger instance.",
    )
    min_level: str = Field(
        default="INFO",
        description="Minimum logging level string ('DEBUG', 'INFO', 'WARNING', 'ERROR').",
    )
    structured_json: bool = Field(
        default=True,
        description="Whether to format output as structured JSON lines.",
    )
    redact_sensitive_data: bool = Field(
        default=True,
        description="Ensure raw secrets and sensitive values are never logged.",
    )

    @field_validator("min_level")
    @classmethod
    def validate_min_level(cls, v: str) -> str:
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in valid_levels:
            raise ValueError(f"Invalid log level: {v}. Must be one of {valid_levels}")
        return upper

    @field_validator("redact_sensitive_data")
    @classmethod
    def validate_redact_sensitive_data(cls, v: bool) -> bool:
        if not v:
            raise ValueError(
                "AuditConfig security invariant violation: 'redact_sensitive_data' must remain True."
            )
        return v

    def get_logging_level(self) -> int:
        """Convert string log level to standard library logging constant."""
        return getattr(logging, self.min_level, logging.INFO)


class TelemetryConfig(BaseModel):
    """Configuration for operational security metrics, telemetry, and structured events."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = Field(
        default=False,
        description="Whether operational telemetry recording is enabled on scans.",
    )
    events_enabled: bool = Field(
        default=True,
        description="Whether structured security events are captured in telemetry.",
    )
    metrics_enabled: bool = Field(
        default=True,
        description="Whether aggregated metrics counters and latency distributions are recorded.",
    )
    max_buffered_events: int = Field(
        default=1000,
        ge=1,
        description="Maximum number of historical structured events retained in memory.",
    )
    logger_name: Optional[str] = Field(
        default=None,
        description="Optional logger name for streaming telemetry records to Python logging.",
    )
    min_level: str = Field(
        default="INFO",
        description="Minimum logging level string ('DEBUG', 'INFO', 'WARNING', 'ERROR').",
    )

    @field_validator("min_level")
    @classmethod
    def validate_min_level(cls, v: str) -> str:
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in valid_levels:
            raise ValueError(f"Invalid log level: {v}. Must be one of {valid_levels}")
        return upper

    def get_logging_level(self) -> int:
        """Convert string log level to standard library logging constant."""
        return getattr(logging, self.min_level, logging.INFO)


class ObservabilityConfig(BaseModel):
    """Configuration for Production Observability and Security Intelligence (Phase 24)."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = Field(
        default=False,
        description="Whether production observability and intelligence is enabled.",
    )
    backend: str = Field(
        default="memory",
        description="Storage backend type: 'memory', 'sqlite', or 'jsonl'.",
    )
    storage_path: Optional[str] = Field(
        default=None,
        description="Optional file path for sqlite database or jsonl event log.",
    )
    retention_days: int = Field(
        default=30,
        ge=1,
        description="Automatic retention window in days for pruning stale events.",
    )
    store_raw_content: bool = Field(
        default=False,
        description="Explicitly allow raw content logging. Strongly recommended False for privacy.",
    )
    application_id: Optional[str] = Field(
        default=None,
        description="Application identifier for multi-application environments.",
    )
    environment: str = Field(
        default="production",
        description="Deployment environment (development, staging, production).",
    )

    @field_validator("backend")
    @classmethod
    def validate_backend(cls, v: str) -> str:
        valid = {"memory", "sqlite", "jsonl"}
        lower = v.lower()
        if lower not in valid:
            raise ValueError(f"Invalid observability backend: {v}. Must be one of {valid}")
        return lower


class IntegrationsConfig(BaseModel):
    """Configuration for third-party framework integrations (FastAPI, Flask, LangChain, etc.)."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    fastapi_enabled: bool = Field(default=True, description="Enable FastAPI middleware support.")
    input_fields: List[str] = Field(
        default_factory=lambda: ["prompt", "message", "query", "text", "content", "input"],
        description="JSON keys to extract and scan from HTTP request bodies.",
    )
    scan_output: bool = Field(default=False, description="Whether to inspect endpoint responses.")
class RuntimeLimitsConfig(BaseModel):
    """Safety and resource limits for agent reasoning loops."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    max_iterations: int = Field(default=25, ge=1, description="Maximum reasoning loop steps.")
    max_tool_calls: int = Field(default=30, ge=1, description="Maximum total tool invocations per session.")
    max_runtime_seconds: float = Field(default=120.0, ge=1.0, description="Session timeout in seconds.")
    max_repeated_tool_calls: int = Field(default=3, ge=1, description="Threshold for loop/repetition detection.")
    block_on_loop: bool = Field(default=True, description="Whether to block execution on repeated loop detection.")


class RuntimeConfig(BaseModel):
    """Configuration for LLM & Agent Runtime Protection (Phase 26)."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = Field(default=True, description="Enable runtime session and boundary protection.")
    limits: RuntimeLimitsConfig = Field(
        default_factory=RuntimeLimitsConfig,
        description="Operational loop and resource limits.",
    )
    inspect_llm_input: bool = Field(default=True, description="Scan pre-LLM prompt/request text.")
    inspect_llm_output: bool = Field(default=True, description="Scan post-LLM generation text.")
    inspect_tool_calls: bool = Field(default=True, description="Enforce tool permission & security checks.")
    inspect_tool_results: bool = Field(default=True, description="Scan outputs produced by tools.")


class IngestionConfig(BaseModel):
    """Configuration for document ingestion scanning."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    scan_documents: bool = Field(default=True, description="Scan documents upon ingestion.")
    quarantine_on_injection: bool = Field(default=True, description="Quarantine documents with prompt injection findings.")
    deduplicate_chunks: bool = Field(default=True, description="Deduplicate identical chunk contents.")


class ContextBudgetConfig(BaseModel):
    """Resource and safety limits for assembled context."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    max_items: int = Field(default=10, ge=1, description="Maximum retrieved chunks in prompt context.")
    max_tokens: int = Field(default=8000, ge=100, description="Token budget ceiling for assembled context.")
    max_bytes: int = Field(default=100_000, ge=100, description="Byte size ceiling for assembled context.")
    drop_on_overflow: bool = Field(default=True, description="Drop excess low-ranked items when budget is exceeded.")


class RAGConfig(BaseModel):
    """Configuration for Advanced RAG and Context Security (Phase 27)."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = Field(default=True, description="Enable RAG ingestion and context protection.")
    ingestion: IngestionConfig = Field(default_factory=IngestionConfig, description="Ingestion scanning configuration.")
    context: ContextBudgetConfig = Field(default_factory=ContextBudgetConfig, description="Context budget configuration.")
    scan_retrieved: bool = Field(default=True, description="Scan chunks immediately upon retrieval.")
    enable_cache: bool = Field(default=True, description="Enable hash-based security scan cache.")
    cache_ttl_seconds: float = Field(default=3600.0, ge=60.0, description="TTL for security scan cache in seconds.")


class ModelSecurityConfig(BaseModel):
    """Configuration for model artifact integrity, provenance, and safe loading."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    require_hash: bool = Field(default=True, description="Require cryptographic hash pinning for local models.")
    allow_unknown_source: bool = Field(default=False, description="Whether to allow models from unverified/unknown sources.")
    allow_unsafe_serialization: bool = Field(default=False, description="Whether to allow pickle/torch-checkpoint serialization.")
    allowed_sources: Optional[List[str]] = Field(default=None, description="Allowlist of approved model sources or registries.")


class DependencySecurityConfig(BaseModel):
    """Configuration for dependency scanning, allowlists, and vulnerability rules."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = Field(default=True, description="Enable dependency inventory and supply-chain evaluation.")
    allowed_packages: Optional[List[str]] = Field(default=None, description="Optional allowlist of permitted packages.")
    blocked_packages: Optional[List[str]] = Field(default=None, description="Blocklist of forbidden packages.")


class SupplyChainConfig(BaseModel):
    """Master configuration for AI Supply-Chain & Model Security (Phase 28)."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = Field(default=True, description="Enable supply-chain security and artifact verification.")
    models: ModelSecurityConfig = Field(default_factory=ModelSecurityConfig, description="Model security settings.")
    dependencies: DependencySecurityConfig = Field(default_factory=DependencySecurityConfig, description="Dependency settings.")
    detect_config_drift: bool = Field(default=True, description="Detect security configuration and policy drift.")


class AgentCapabilitiesConfig(BaseModel):
    """Configuration for Agent Capability Security & Action Control (Phase 29)."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = Field(default=True, description="Enable capability security, grants, and action budgets.")
    default_agent_capabilities: List[str] = Field(
        default_factory=lambda: ["filesystem.read"],
        description="Default capability grants for unconfigured agents (least privilege).",
    )
    max_delegation_depth: int = Field(default=3, ge=1, description="Maximum agent-to-agent delegation nesting depth.")
    max_action_depth: int = Field(default=20, ge=1, description="Maximum nested action execution depth.")
    default_max_actions: int = Field(default=50, ge=1, description="Default session action budget ceiling.")
    default_max_runtime_seconds: float = Field(default=300.0, ge=1.0, description="Default session timeout.")


class FirewallConfig(BaseModel):
    """Master configuration for LLMFirewall orchestrator.
    
    Serves as the single source of truth for runtime behavior:
      - detectors: Enables/disables and tunes detector rules
      - risk: Configures weights, multipliers, decay, and risk thresholds
      - policy: Defines declarative enforcement rules and fallback actions
      - redaction: Configures custom replacement token templates
      - audit: Configures security audit logging
      - telemetry: Configures operational metrics and structured events
      - observability: Configures security intelligence and event store
      - integrations: Configures framework and middleware adapters
      - runtime: Configures agent runtime loop guards and boundary checks
      - rag: Configures document ingestion, context trust, and retrieval security
      - supply_chain: Configures model verification, dependencies, and configuration drift (Phase 28)
      - capabilities: Configures agent capability security, budgets, and action control (Phase 29)
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    detectors: DetectorConfig = Field(
        default_factory=DetectorConfig,
        description="Detector engine configuration.",
    )
    risk: RiskConfig = Field(
        default_factory=RiskConfig,
        description="Risk engine scoring and threshold configuration.",
    )
    policy: Policy = Field(
        default_factory=get_default_policy,
        description="Policy engine decision rules configuration.",
    )
    redaction: RedactionConfig = Field(
        default_factory=RedactionConfig,
        description="Redaction token configuration.",
    )
    audit: AuditConfig = Field(
        default_factory=AuditConfig,
        description="Audit logging configuration.",
    )
    telemetry: TelemetryConfig = Field(
        default_factory=TelemetryConfig,
        description="Operational security telemetry and metrics configuration.",
    )
    observability: ObservabilityConfig = Field(
        default_factory=ObservabilityConfig,
        description="Production observability and security intelligence configuration.",
    )
    integrations: IntegrationsConfig = Field(
        default_factory=IntegrationsConfig,
        description="Framework and ecosystem integrations configuration.",
    )
    runtime: RuntimeConfig = Field(
        default_factory=RuntimeConfig,
        description="LLM & Agent runtime boundary protection and loop safety configuration.",
    )
    rag: RAGConfig = Field(
        default_factory=RAGConfig,
        description="Advanced RAG and context security configuration (Phase 27).",
    )
    supply_chain: SupplyChainConfig = Field(
        default_factory=SupplyChainConfig,
        description="AI Supply-Chain & Model Security configuration (Phase 28).",
    )
    capabilities: AgentCapabilitiesConfig = Field(
        default_factory=AgentCapabilitiesConfig,
        description="Agent Capability Security & Action Control configuration (Phase 29).",
    )

    @model_validator(mode="after")
    def validate_threshold_ordering(self) -> "FirewallConfig":
        """Verify that risk threshold boundaries maintain monotonic non-decreasing order."""
        r = self.risk
        if not (
            r.info_threshold
            <= r.low_threshold
            <= r.medium_threshold
            <= r.high_threshold
            <= r.critical_threshold
        ):
            raise ValueError(
                f"Risk thresholds must be monotonically non-decreasing: "
                f"info({r.info_threshold}) <= low({r.low_threshold}) <= "
                f"medium({r.medium_threshold}) <= high({r.high_threshold}) <= "
                f"critical({r.critical_threshold})"
            )
        return self
