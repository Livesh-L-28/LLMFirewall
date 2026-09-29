"""Main Firewall orchestrator coordinating Detectors, Risk Engine, and Policy Engine."""

import time
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Union
import uuid

if TYPE_CHECKING:
    from llmfirewall.config.models import FirewallConfig

from llmfirewall.core.models import (
    Action,
    AuditEvent,
    Finding,
    PolicyDecision,
    RiskScore,
    ScanRequest,
    ScanResult,
    Severity,
)
from llmfirewall.detectors.base import Detector
from llmfirewall.detectors.engine import DetectorEngine
from llmfirewall.detectors.pii import PIIDetector
from llmfirewall.detectors.prompt_injection import PromptInjectionDetector
from llmfirewall.detectors.secrets import SecretDetector
from llmfirewall.policy.config import Policy, PolicyConfig
from llmfirewall.policy.engine import PolicyEngine
from llmfirewall.audit import AuditLogger, default_audit_logger
from llmfirewall.telemetry import (
    InMemoryTelemetrySink,
    NoOpTelemetry,
    TelemetryEvent,
    TelemetryEventType,
    TelemetrySink,
)
from llmfirewall.risk.config import RiskConfig
from llmfirewall.risk.engine import RiskEngine
from llmfirewall.tools.engine import ToolSecurityEngine
from llmfirewall.tools.models import ToolCall, ToolResult, ToolSecurityDecision
from llmfirewall.tools.registry import ToolRegistry, default_tool_registry
from llmfirewall.observability.intelligence import SecurityIntelligenceEngine
from llmfirewall.observability.models import (
    DecisionTrace,
    EventSeverity,
    SecurityEvent,
    SecurityEventType,
)
from llmfirewall.observability.store import (
    EventStore,
    InMemoryEventStore,
    JSONLEventStore,
    SQLiteEventStore,
)
from llmfirewall.runtime.engine import RuntimeEngine
from llmfirewall.runtime.models import RuntimeContext
from llmfirewall.runtime.session import RuntimeSession


class Firewall:
    """The central orchestrator for LLMFirewall.
    
    Adheres strictly to the architectural governance:
    - Detectors detect: Inspect text and emit structured findings.
    - Risk engine scores: Aggregates findings into quantified risk metrics.
    - Policy engine decides: Evaluates rules and selects policy action (ALLOW, WARN, BLOCK, REDACT).
    - Firewall orchestrates: Coordinates the entire inspection lifecycle.
    
    Safe Defaults:
    - Default Detectors: PromptInjectionDetector, PIIDetector, SecretDetector
    - Default Risk Engine: Configured with standard severity weights and diminishing returns
    - Default Policy Engine: Prompt injection -> BLOCK, Secrets -> BLOCK, PII -> REDACT, Default -> ALLOW
    """

    def __init__(
        self,
        config: Optional["FirewallConfig"] = None,
        detectors: Optional[List[Detector]] = None,
        risk_engine: Optional[RiskEngine] = None,
        policy_engine: Optional[Union[PolicyEngine, Policy]] = None,
        audit_logger: Optional[AuditLogger] = None,
        telemetry_sink: Optional[TelemetrySink] = None,
        policy: Optional[Union[PolicyEngine, Policy]] = None,
        fail_fast_detectors: bool = False,
        tool_registry: Optional[ToolRegistry] = None,
        tool_security_engine: Optional[ToolSecurityEngine] = None,
        event_store: Optional[EventStore] = None,
    ) -> None:
        """Initialize the Firewall with optional configuration or explicit custom components.
        
        Args:
            config: Optional master FirewallConfig object controlling runtime behavior.
                    If provided, config drives detector initialization, risk thresholds,
                    policy rules, redaction tokens, audit logging, telemetry, and observability.
            detectors: Optional explicit list of Detector instances. Overrides config.detectors.
            risk_engine: Optional custom RiskEngine. Overrides config.risk.
            policy_engine: Optional custom PolicyEngine or Policy document. Overrides config.policy.
            audit_logger: Optional custom AuditLogger. Overrides config.audit.
            telemetry_sink: Optional custom TelemetrySink. Overrides config.telemetry.
            policy: Alias for policy_engine, accepts either Policy or PolicyEngine instance.
            fail_fast_detectors: If True, raise exception on first detector failure;
                                 if False (default), isolate detector errors and continue.
            tool_registry: Optional custom ToolRegistry for agent tool security.
            tool_security_engine: Optional custom ToolSecurityEngine.
            event_store: Optional custom EventStore for production observability and intelligence.
        """
        # Store effective configuration (frozen Pydantic model)
        from llmfirewall.config.models import FirewallConfig as _FirewallConfig
        self._config: _FirewallConfig = config if config is not None else _FirewallConfig()

        # 1. Build Detectors
        if detectors is not None:
            active_detectors = detectors
            effective_fail_fast = fail_fast_detectors
        elif config is not None:
            active_detectors = []
            det_cfg = config.detectors
            if det_cfg.prompt_injection.enabled:
                pi_rules = None
                if det_cfg.prompt_injection.rules is not None:
                    from llmfirewall.detectors.prompt_injection.rules import (
                        InstructionHierarchyRule,
                        InstructionOverrideRule,
                        RoleManipulationRule,
                        SuspiciousControlRule,
                        SystemPromptLeakRule,
                    )
                    all_pi_rules = [
                        InstructionOverrideRule(),
                        SystemPromptLeakRule(),
                        RoleManipulationRule(),
                        InstructionHierarchyRule(),
                        SuspiciousControlRule(),
                    ]
                    allowed_set = set(det_cfg.prompt_injection.rules)
                    pi_rules = [r for r in all_pi_rules if r.rule_id in allowed_set]
                active_detectors.append(PromptInjectionDetector(rules=pi_rules))

            if det_cfg.pii.enabled:
                active_detectors.append(
                    PIIDetector(
                        enabled_categories=det_cfg.pii.categories,
                        store_matched_text=det_cfg.pii.store_matched_text,
                    )
                )

            if det_cfg.secrets.enabled:
                sec_rules = None
                if det_cfg.secrets.rules is not None:
                    from llmfirewall.detectors.secrets.rules import (
                        APIKeyRule,
                        CredentialConfigRule,
                        PrivateKeyRule,
                        TokenRule,
                    )
                    all_sec_rules = [
                        APIKeyRule(),
                        TokenRule(),
                        PrivateKeyRule(),
                        CredentialConfigRule(),
                    ]
                    allowed_set = set(det_cfg.secrets.rules)
                    sec_rules = [r for r in all_sec_rules if r.rule_id in allowed_set]
                active_detectors.append(SecretDetector(rules=sec_rules))

            effective_fail_fast = fail_fast_detectors or det_cfg.fail_fast
        else:
            active_detectors = [
                PromptInjectionDetector(),
                PIIDetector(),
                SecretDetector(),
            ]
            effective_fail_fast = fail_fast_detectors

        self._detector_engine = DetectorEngine(
            detectors=active_detectors,
            fail_fast=effective_fail_fast,
        )

        # 2. Build Risk Engine
        if risk_engine is not None:
            self._risk_engine = risk_engine
        elif config is not None:
            self._risk_engine = RiskEngine(config=config.risk)
        else:
            self._risk_engine = RiskEngine()

        # 3. Build Policy Engine
        effective_policy_input = policy if policy is not None else policy_engine
        if effective_policy_input is not None:
            if isinstance(effective_policy_input, PolicyEngine):
                self._policy_engine = effective_policy_input
            else:
                self._policy_engine = PolicyEngine(config=effective_policy_input)
        elif config is not None:
            # Wire redaction config into policy config if provided
            eff_policy_cfg = config.policy
            if config.redaction is not None and eff_policy_cfg.redaction_config is None:
                # Supply top-level redaction config to policy engine
                eff_policy_cfg = eff_policy_cfg.model_copy(update={"redaction_config": config.redaction})
            self._policy_engine = PolicyEngine(config=eff_policy_cfg)
        else:
            self._policy_engine = PolicyEngine()

        # 4. Build Audit Logger
        if audit_logger is not None:
            self._audit_logger = audit_logger
        elif config is not None and config.audit.enabled:
            self._audit_logger = AuditLogger(
                name=config.audit.logger_name,
                min_level=config.audit.get_logging_level(),
            )
        else:
            self._audit_logger = None

        # 5. Build Telemetry Sink
        if telemetry_sink is not None:
            self._telemetry_sink = telemetry_sink
        elif config is not None and config.telemetry.enabled:
            self._telemetry_sink = InMemoryTelemetrySink(
                enable_events=config.telemetry.events_enabled,
                enable_metrics=config.telemetry.metrics_enabled,
                max_buffered_events=config.telemetry.max_buffered_events,
                logger_name=config.telemetry.logger_name,
                log_level=config.telemetry.get_logging_level(),
            )
        else:
            self._telemetry_sink = NoOpTelemetry()

        # 6. Build Tool Security Engine
        if tool_security_engine is not None:
            self._tool_security_engine = tool_security_engine
        else:
            self._tool_security_engine = ToolSecurityEngine(
                registry=tool_registry or default_tool_registry,
                policy_engine=self._policy_engine,
                detector_engine=self._detector_engine,
                risk_engine=self._risk_engine,
            )

        # 7. Build Production Observability & Security Intelligence (Phase 24)
        if event_store is not None:
            self._event_store = event_store
        elif self._config.observability.enabled:
            backend = self._config.observability.backend
            path = self._config.observability.storage_path
            if backend == "sqlite":
                self._event_store = SQLiteEventStore(db_path=path or ".llmfirewall/events.db")
            elif backend == "jsonl":
                self._event_store = JSONLEventStore(file_path=path or ".llmfirewall/events.jsonl")
            else:
                self._event_store = InMemoryEventStore()
        else:
            self._event_store = InMemoryEventStore()

        self._intelligence_engine = SecurityIntelligenceEngine(store=self._event_store)

    @property
    def config(self) -> "FirewallConfig":
        """Active immutable configuration for this Firewall instance."""
        return self._config

    @property
    def detector_engine(self) -> DetectorEngine:
        return self._detector_engine

    @property
    def risk_engine(self) -> RiskEngine:
        return self._risk_engine

    @property
    def policy_engine(self) -> PolicyEngine:
        return self._policy_engine

    @property
    def audit_logger(self) -> Optional[AuditLogger]:
        return self._audit_logger

    @property
    def telemetry_sink(self) -> TelemetrySink:
        """Active telemetry sink (NoOpTelemetry or configured TelemetrySink)."""
        return self._telemetry_sink

    @property
    def tool_security(self) -> ToolSecurityEngine:
        """Active agent and tool security engine."""
        return self._tool_security_engine

    @property
    def tool_registry(self) -> ToolRegistry:
        """Active tool registry."""
        return self._tool_security_engine.registry

    @property
    def event_store(self) -> EventStore:
        """Active SecurityEvent storage backend."""
        return self._event_store

    @property
    def observe(self) -> SecurityIntelligenceEngine:
        """Operational security intelligence and analytics engine."""
        return self._intelligence_engine

    @property
    def observability(self) -> SecurityIntelligenceEngine:
        """Alias for observe property."""
        return self._intelligence_engine

    @property
    def runtime(self) -> RuntimeEngine:
        """LLM & Agent Runtime Security Engine."""
        if not hasattr(self, "_runtime_engine"):
            self._runtime_engine = RuntimeEngine(firewall=self)
        return self._runtime_engine

    @property
    def rag_quarantine(self) -> Any:
        """Active logical quarantine store for RAG documents."""
        if not hasattr(self, "_rag_quarantine"):
            from llmfirewall.rag.ingestion import QuarantineStore
            self._rag_quarantine = QuarantineStore()
        return self._rag_quarantine

    @property
    def ingestion_scanner(self) -> Any:
        """Document ingestion security scanner."""
        if not hasattr(self, "_ingestion_scanner"):
            from llmfirewall.rag.ingestion import DocumentIngestionScanner
            self._ingestion_scanner = DocumentIngestionScanner(firewall=self, quarantine_store=self.rag_quarantine)
        return self._ingestion_scanner

    @property
    def context_orchestrator(self) -> Any:
        """Context isolation, deduplication, conflict, and budgeting orchestrator."""
        if not hasattr(self, "_context_orchestrator"):
            from llmfirewall.rag.orchestrator import ContextOrchestrator
            cfg = self._config.rag.context
            self._context_orchestrator = ContextOrchestrator(
                firewall=self,
                quarantine_store=self.rag_quarantine,
                max_items=cfg.max_items,
                max_tokens=cfg.max_tokens,
                max_bytes=cfg.max_bytes,
                drop_on_overflow=cfg.drop_on_overflow,
            )
        return self._context_orchestrator

    @property
    def rag(self) -> Any:
        """Convenience property for RAG context orchestrator."""
        return self.context_orchestrator

    @property
    def model_verifier(self) -> Any:
        """Model integrity, format, and pinning verifier (Phase 28)."""
        if not hasattr(self, "_model_verifier"):
            from llmfirewall.supply_chain.verifier import ModelVerifier
            sc = self._config.supply_chain.models
            self._model_verifier = ModelVerifier(
                require_hash=sc.require_hash,
                allow_unknown_source=sc.allow_unknown_source,
                allow_unsafe_serialization=sc.allow_unsafe_serialization,
                allowed_sources=sc.allowed_sources,
            )
        return self._model_verifier

    @property
    def model_registry(self) -> Any:
        """Lightweight security metadata registry for approved/revoked models (Phase 28)."""
        if not hasattr(self, "_model_registry"):
            from llmfirewall.supply_chain.manifest import ModelSecurityRegistry
            self._model_registry = ModelSecurityRegistry()
        return self._model_registry

    @property
    def model_guard_manager(self) -> Any:
        """Pre-load execution guard for machine learning models (Phase 28)."""
        if not hasattr(self, "_model_guard_manager"):
            from llmfirewall.supply_chain.guard import ModelLoadingGuard
            self._model_guard_manager = ModelLoadingGuard(
                verifier=self.model_verifier,
                registry=self.model_registry,
            )
        return self._model_guard_manager

    @property
    def dependency_scanner(self) -> Any:
        """Offline dependency scanner and SBOM generator (Phase 28)."""
        if not hasattr(self, "_dependency_scanner"):
            from llmfirewall.supply_chain.dependencies import DependencyScanner
            dep_cfg = self._config.supply_chain.dependencies
            self._dependency_scanner = DependencyScanner(
                allowed_packages=dep_cfg.allowed_packages,
                blocked_packages=dep_cfg.blocked_packages,
            )
        return self._dependency_scanner

    @property
    def integrity_manager(self) -> Any:
        """Configuration, prompt, and policy drift manager (Phase 28)."""
        if not hasattr(self, "_integrity_manager"):
            from llmfirewall.supply_chain.integrity import IntegrityManager, hash_configuration
            self._integrity_manager = IntegrityManager()
            # Set initial baseline config
            try:
                base_art = hash_configuration(self._config.model_dump(), config_type="firewall")
                self._integrity_manager.set_baseline_config(base_art)
            except Exception:
                pass
        return self._integrity_manager

    def verify_model(
        self,
        path_or_location: str,
        expected_hash: Optional[str] = None,
        algorithm: str = "sha256",
        model_name: Optional[str] = None,
        version: str = "unknown",
        source: str = "local",
    ) -> Any:
        """Verify model cryptographic integrity, format safety, and security policy."""
        from llmfirewall.supply_chain.models import ModelArtifact, ModelFormat, ModelSourceType
        from llmfirewall.supply_chain.verifier import detect_model_format
        fmt = detect_model_format(path_or_location)
        name = model_name or str(path_or_location).split("/")[-1]

        artifact = ModelArtifact(
            name=name,
            version=version,
            source_type=ModelSourceType.LOCAL_FILE,
            source=source,
            location=str(path_or_location),
            format=fmt,
            sha256=expected_hash,
        )

        decision = self.model_verifier.evaluate_model(
            artifact=artifact,
            expected_hash=expected_hash,
        )

        # Emit audit / telemetry if enabled
        if self._audit_logger:
            from llmfirewall.core.models import AuditEvent, ThreatType
            self._audit_logger.log(
                AuditEvent(
                    event_type="model_verified" if decision.action == Action.ALLOW else "model_blocked",
                    threat_type=ThreatType.POLICY_VIOLATION,
                    action_taken=decision.action,
                    details={
                        "model": name,
                        "hash_status": decision.hash_status.value if decision.hash_status else "unknown",
                        "format": decision.format.value,
                    },
                )
            )

        return decision

    def model_guard(
        self,
        model_name: str,
        path_or_location: Optional[str] = None,
        version: str = "unknown",
        expected_hash: Optional[str] = None,
        expected_version: Optional[str] = None,
        source: str = "local",
    ) -> Any:
        """Context manager protecting the execution of model-loading code blocks."""
        return self.model_guard_manager.guard(
            model_name=model_name,
            path_or_location=path_or_location,
            version=version,
            expected_hash=expected_hash,
            expected_version=expected_version,
            source=source,
        )

    def create_security_snapshot(
        self,
        application_version: str = "0.1.0",
        container_digest: Optional[str] = None,
        models: Optional[List[Any]] = None,
    ) -> Any:
        """Capture a deterministic, secret-safe AI supply-chain security snapshot."""
        from llmfirewall.supply_chain.models import (
            DeploymentMetadata,
            SecuritySnapshot,
        )
        from llmfirewall.supply_chain.integrity import hash_configuration, hash_policy_artifact

        dep_meta = DeploymentMetadata(
            application_version=application_version,
            container_digest=container_digest,
        )
        deps = self.dependency_scanner.scan_environment()
        cfg_art = hash_configuration(self._config.model_dump(), config_type="firewall")
        pol_art = hash_policy_artifact(self._policy_engine.config.model_dump(), policy_id="default")

        return SecuritySnapshot.create(
            deployment=dep_meta,
            models=models or [],
            dependencies=deps,
            configurations=[cfg_art],
            policies=[pol_art],
            prompts=[],
        )

    @property
    def capability_engine(self) -> Any:
        """Agent capability security & action authorization engine (Phase 29)."""
        if not hasattr(self, "_capability_engine"):
            from llmfirewall.capabilities.engine import CapabilityEngine
            cap_cfg = self._config.capabilities
            self._capability_engine = CapabilityEngine(
                max_delegation_depth=cap_cfg.max_delegation_depth,
                max_action_depth=cap_cfg.max_action_depth,
            )
        return self._capability_engine

    def authorize_action(
        self,
        capability_name: str,
        agent_id: str = "default_agent",
        tool_name: str = "unknown_tool",
        resource: Optional[str] = None,
        session_id: str = "default_session",
        budget_manager: Optional[Any] = None,
        arguments_metadata: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Authorize an agent action request against capabilities, budgets, and approval gates."""
        from llmfirewall.capabilities.models import ActionRequest
        req = ActionRequest(
            agent_id=agent_id,
            session_id=session_id,
            capability_name=capability_name,
            tool_name=tool_name,
            resource=resource,
            arguments_metadata=arguments_metadata or {},
        )
        decision = self.capability_engine.authorize_action(req, budget_manager=budget_manager)

        # Audit logging if enabled
        if self._audit_logger:
            from llmfirewall.core.models import AuditEvent, ThreatType
            self._audit_logger.log(
                AuditEvent(
                    event_type="capability_action_allowed" if decision.is_allowed else "capability_action_denied",
                    threat_type=ThreatType.POLICY_VIOLATION,
                    action_taken=Action.ALLOW if decision.is_allowed else Action.BLOCK,
                    details={
                        "agent_id": agent_id,
                        "capability": capability_name,
                        "status": decision.decision.value,
                        "resource": resource or "none",
                    },
                )
            )

        return decision

    def revoke_session(self, session_id: str) -> None:
        """Agent kill-switch: invalidate an active session and prevent all future actions."""
        self.capability_engine.revoke_session(session_id)

    def runtime_session(
        self,
        context: Optional[RuntimeContext] = None,
        max_iterations: int = 25,
        max_tool_calls: int = 30,
        max_runtime_seconds: float = 120.0,
        max_repeated_tool_calls: int = 3,
        max_tokens: Optional[int] = None,
        max_cost: Optional[float] = None,
        block_on_loop: bool = True,
        raise_on_block: bool = True,
        hooks: Optional[List[Any]] = None,
    ) -> RuntimeSession:
        """Initialize a new stateful RuntimeSession for an agent or LLM interaction."""
        return self.runtime.create_session(
            context=context,
            max_iterations=max_iterations,
            max_tool_calls=max_tool_calls,
            max_runtime_seconds=max_runtime_seconds,
            max_repeated_tool_calls=max_repeated_tool_calls,
            max_tokens=max_tokens,
            max_cost=max_cost,
            block_on_loop=block_on_loop,
            raise_on_block=raise_on_block,
            hooks=hooks,
        )

    def scan(
        self,
        text_or_request: Union[str, ScanRequest],
        direction: str = "input",
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        """Scan and enforce security policy on a prompt or model output (alias for check)."""
        return self.check(
            text_or_request=text_or_request,
            direction=direction,
            user_id=user_id,
            session_id=session_id,
            context=context,
        )

    def check(
        self,
        text_or_request: Union[str, ScanRequest],
        direction: str = "input",
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        """Primary public entrypoint to scan and enforce security policy on a text prompt or LLM output.
        
        Execution Pipeline:
        -------------------
        1. Request Envelope Normalization: Wrap input in an immutable ScanRequest.
        2. Detector Engine Execution: Run direction-aware detectors, producing a FindingCollection.
        3. Risk Engine Scoring: Quantify composite score, max severity, and category scores.
        4. Policy Engine Decision: Evaluate rules with strict precedence (BLOCK > REDACT > WARN > ALLOW).
        5. Result Construction: Build typed ScanResult with safe downstream processed_text and telemetry.
        
        Args:
            text_or_request: Raw prompt string, LLM output string, or existing ScanRequest.
            direction: 'input' (user prompt) or 'output' (LLM generation). Default: 'input'.
            user_id: Optional user/tenant identifier for audit correlation.
            session_id: Optional session/conversation identifier.
            context: Optional arbitrary dictionary passed to detectors and policy rules.
            
        Returns:
            ScanResult: Fully populated scan outcome containing decision, risk score,
                        findings, and the safe downstream text.
        """
        start_time = time.perf_counter()

        # Step 1: Normalize input to ScanRequest
        if isinstance(text_or_request, ScanRequest):
            request = text_or_request
        else:
            request = ScanRequest(
                text=str(text_or_request),
                direction=direction,
                user_id=user_id,
                session_id=session_id,
                metadata=dict(context or {}),
            )

        # Ensure direction is in context for direction-aware rules and detectors
        scan_context = dict(request.metadata)
        scan_context["direction"] = request.direction

        # Step 2: Run Detector Engine
        finding_collection = self._detector_engine.execute(
            text=request.text,
            direction=request.direction,
            context=scan_context,
        )

        # Step 3: Run Risk Engine
        risk_score = self._risk_engine.evaluate(
            findings=finding_collection,
            context=scan_context,
        )

        # Step 4: Run Policy Engine
        decision = self._policy_engine.decide(
            text=request.text,
            findings=finding_collection.findings,
            risk_score=risk_score,
            context=scan_context,
        )

        # Step 5: Determine processed_text for safe downstream consumption
        if decision.action == Action.BLOCK:
            processed_text = ""
        elif decision.action == Action.REDACT:
            processed_text = decision.redacted_text if decision.redacted_text is not None else request.text
        elif decision.action == Action.WARN and decision.redacted_text is not None:
            # If auto_redact_on_warn is configured, use the redacted text
            processed_text = decision.redacted_text
        else:
            # ALLOW or unredacted WARN
            processed_text = request.text

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        scan_result = ScanResult(
            request_id=request.id,
            decision=decision,
            risk_score=risk_score,
            findings=finding_collection.findings,
            original_text=request.text,
            processed_text=processed_text,
            execution_time_ms=round(elapsed_ms, 3),
            metadata={
                "direction": request.direction,
                "user_id": request.user_id,
                "session_id": request.session_id,
                "has_detector_errors": finding_collection.has_errors,
            },
        )

        # Automatic audit logging if logger is attached
        if self._audit_logger is not None:
            self._audit_logger.log_scan(request=request, result=scan_result)

        # Operational telemetry recording with strict failure isolation
        try:
            self._telemetry_sink.record_scan(request=request, result=scan_result)
        except Exception:
            # Telemetry failures must never alter or reverse security decisions
            pass

        # Production Observability & Security Intelligence event persistence (Phase 24)
        try:
            sec_event = SecurityEvent.from_scan(
                request=request,
                result=scan_result,
                store_raw_content=self._config.observability.store_raw_content,
                application_id=self._config.observability.application_id,
                environment=self._config.observability.environment,
            )
            self._event_store.write(sec_event)
        except Exception:
            # Observability store failures must never alter or block security decisions
            pass

        return scan_result

    def trace_decision(
        self,
        text_or_request: Union[str, ScanRequest],
        direction: str = "input",
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> DecisionTrace:
        """Execute scan and return a comprehensive, deterministic DecisionTrace explaining why the decision was made.
        
        Explains:
        - Exact sequence of detector findings
        - Risk score calculation and severity
        - Matched policy rule and version
        - Explanatory human-readable summary generated deterministically without an LLM
        """
        if isinstance(text_or_request, ScanRequest):
            request = text_or_request
        else:
            request = ScanRequest(
                text=str(text_or_request),
                direction=direction,
                user_id=user_id,
                session_id=session_id,
                metadata=dict(context or {}),
            )

        result = self.check(request)
        return DecisionTrace.from_scan_result(request=request, result=result)

    def check_prompt(
        self,
        prompt: str,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        """Scan and validate an incoming user prompt before sending it to an LLM / agent.
        
        Convenience wrapper explicitly enforcing direction='input'.
        """
        return self.check(
            text_or_request=prompt,
            direction="input",
            user_id=user_id,
            session_id=session_id,
            context=context,
        )

    def check_output(
        self,
        generation: str,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        """Scan and validate an outgoing LLM response before returning it to the user.
        
        Convenience wrapper explicitly enforcing direction='output'.
        Scans for sensitive secrets, PII, hallucinated credentials, or toxic output.
        """
        return self.check(
            text_or_request=generation,
            direction="output",
            user_id=user_id,
            session_id=session_id,
            context=context,
        )

    def create_audit_event(
        self,
        request: ScanRequest,
        result: ScanResult,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Create a sanitized, telemetry-safe AuditEvent for SIEM/logging integration."""
        return AuditEvent.from_scan(request=request, result=result, metadata=metadata)

    def check_tool_call(
        self,
        tool_call_or_name: Union[ToolCall, str, Dict[str, Any]],
        arguments: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> ToolSecurityDecision:
        """Inspect and enforce security controls on an AI agent tool call before execution.
        
        Args:
            tool_call_or_name: ToolCall instance, dict representation, or tool name string.
            arguments: Dictionary of tool arguments (if tool_call_or_name is a string).
            user_id: Optional calling user or tenant ID.
            session_id: Optional session identifier.
            context: Contextual parameters.
            
        Returns:
            ToolSecurityDecision: Deterministic ALLOW, WARN, or BLOCK decision.
        """
        if isinstance(tool_call_or_name, str):
            call = ToolCall(
                tool_name=tool_call_or_name,
                arguments=arguments or {},
                user_id=user_id,
                session_id=session_id,
            )
        elif isinstance(tool_call_or_name, dict):
            call = ToolCall(
                tool_name=tool_call_or_name.get("tool_name") or tool_call_or_name.get("name", ""),
                arguments=tool_call_or_name.get("arguments", arguments or {}),
                user_id=user_id or tool_call_or_name.get("user_id"),
                session_id=session_id or tool_call_or_name.get("session_id"),
                metadata=tool_call_or_name.get("metadata", {}),
            )
        else:
            call = tool_call_or_name

        decision = self._tool_security_engine.check_tool_call(call, context=context)

        # Audit logging if enabled
        if self._audit_logger is not None:
            # Emit structured tool call event
            dummy_req = ScanRequest(
                text=call.serialize_arguments(),
                direction="input",
                user_id=call.user_id,
                session_id=call.session_id,
                metadata={"tool_name": call.tool_name},
            )
            # Safe audit log
            self._audit_logger.emit(
                AuditEvent(
                    scan_id=decision.id,
                    request_id=call.request_id,
                    action_taken=decision.action,
                    risk_score=decision.risk_score.score if decision.risk_score else 0.0,
                    max_severity=decision.risk_score.max_severity if decision.risk_score else Severity.INFO,
                    threat_types=sorted(list({f.threat_type for f in decision.findings})),
                    detection_categories=sorted(list({f.category for f in decision.findings})),
                    detector_names=sorted(list({f.detector_name for f in decision.findings})),
                    findings_count=len(decision.findings),
                    user_id=call.user_id,
                    session_id=call.session_id,
                    triggered_rules=decision.triggered_rules,
                    policy_id=decision.policy_id,
                    policy_version=decision.policy_version,
                    latency_ms=decision.execution_time_ms,
                    metadata={"tool_name": call.tool_name, "event": "tool_call"},
                )
            )

        # Telemetry recording if enabled
        try:
            self._telemetry_sink.record(
                TelemetryEvent(
                    event_type=TelemetryEventType.BLOCKED if decision.is_blocked else TelemetryEventType.ALLOWED,
                    request_id=call.request_id or decision.id,
                    action=decision.action,
                    risk_score=decision.risk_score.score if decision.risk_score else 0.0,
                    risk_level=decision.risk_score.max_severity if decision.risk_score else Severity.INFO,
                    threat_types=[f.threat_type.value for f in decision.findings],
                    detection_categories=[f.category for f in decision.findings],
                    findings_count=len(decision.findings),
                    detector_names=[f.detector_name for f in decision.findings],
                    latency_ms=decision.execution_time_ms,
                    metadata={"tool_name": call.tool_name, "event": "tool_call"},
                )
            )
        except Exception:
            pass

        # Observability event store persistence (Phase 24)
        try:
            ev_type = SecurityEventType.TOOL_BLOCKED if decision.is_blocked else SecurityEventType.TOOL_CALL
            self._event_store.write(
                SecurityEvent(
                    event_type=ev_type,
                    severity=EventSeverity.HIGH if decision.is_blocked else EventSeverity.INFO,
                    request_id=call.request_id or decision.id,
                    component="tool_security",
                    action=decision.action,
                    risk_level=decision.risk_score.max_severity if decision.risk_score else Severity.INFO,
                    risk_score=decision.risk_score.score if decision.risk_score else 0.0,
                    threat_types=[f.threat_type.value for f in decision.findings],
                    tool_name=call.tool_name,
                    duration_ms=decision.execution_time_ms,
                    payload_length=len(call.serialize_arguments()),
                    metadata={"tool_name": call.tool_name, "action": decision.action.value},
                )
            )
        except Exception:
            pass

        return decision

    def check_tool_result(
        self,
        tool_result_or_name: Union[ToolResult, str, Dict[str, Any]],
        output: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> ToolSecurityDecision:
        """Inspect and enforce security controls on a tool result before sending to LLM.
        
        Args:
            tool_result_or_name: ToolResult instance, dict representation, or tool name string.
            output: Result string (if tool_result_or_name is a tool name string).
            context: Contextual parameters.
            
        Returns:
            ToolSecurityDecision: ALLOW, WARN, REDACT, or BLOCK outcome.
        """
        if isinstance(tool_result_or_name, str):
            result_obj = ToolResult(
                tool_name=tool_result_or_name,
                output=str(output or ""),
            )
        elif isinstance(tool_result_or_name, dict):
            result_obj = ToolResult(
                tool_name=tool_result_or_name.get("tool_name") or tool_result_or_name.get("name", ""),
                output=str(tool_result_or_name.get("output", output or "")),
                tool_call_id=tool_result_or_name.get("tool_call_id"),
                request_id=tool_result_or_name.get("request_id"),
                success=tool_result_or_name.get("success", True),
                error=tool_result_or_name.get("error"),
                metadata=tool_result_or_name.get("metadata", {}),
            )
        else:
            result_obj = tool_result_or_name

        decision = self._tool_security_engine.check_tool_result(result_obj, context=context)

        # Telemetry recording if enabled
        try:
            self._telemetry_sink.record(
                TelemetryEvent(
                    event_type=TelemetryEventType.BLOCKED if decision.is_blocked else TelemetryEventType.ALLOWED,
                    request_id=result_obj.request_id or decision.id,
                    action=decision.action,
                    risk_score=decision.risk_score.score if decision.risk_score else 0.0,
                    risk_level=decision.risk_score.max_severity if decision.risk_score else Severity.INFO,
                    threat_types=[f.threat_type.value for f in decision.findings],
                    detection_categories=[f.category for f in decision.findings],
                    findings_count=len(decision.findings),
                    detector_names=[f.detector_name for f in decision.findings],
                    latency_ms=decision.execution_time_ms,
                    metadata={"tool_name": result_obj.tool_name, "event": "tool_result"},
                )
            )
        except Exception:
            pass

        # Observability event store persistence (Phase 24)
        try:
            self._event_store.write(
                SecurityEvent(
                    event_type=SecurityEventType.TOOL_RESULT_SCANNED,
                    severity=EventSeverity.HIGH if decision.is_blocked else EventSeverity.INFO,
                    request_id=result_obj.request_id or decision.id,
                    component="tool_security",
                    action=decision.action,
                    risk_level=decision.risk_score.max_severity if decision.risk_score else Severity.INFO,
                    risk_score=decision.risk_score.score if decision.risk_score else 0.0,
                    threat_types=[f.threat_type.value for f in decision.findings],
                    tool_name=result_obj.tool_name,
                    duration_ms=decision.execution_time_ms,
                    payload_length=len(result_obj.output),
                    metadata={"tool_name": result_obj.tool_name, "action": decision.action.value},
                )
            )
        except Exception:
            pass

        return decision

    @property
    def governance(self) -> Any:
        """AI Security Governance & Release Assurance Engine (Phase 31)."""
        if not hasattr(self, "_governance_engine"):
            from llmfirewall.governance.engine import GovernanceEngine
            self._governance_engine = GovernanceEngine(audit_logger=self._audit_logger)
        return self._governance_engine

    def collect_security_evidence(
        self,
        release_id: Optional[str] = None,
        test_results: Optional[List[Any]] = None,
        evaluation_report: Optional[Any] = None,
        model_identity: Optional[Dict[str, Any]] = None,
        prompt_hash: Optional[str] = None,
        include_snapshot: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Collect security evidence across evaluation, snapshots, and configuration for release governance."""
        from llmfirewall.governance.evidence import SecurityEvidence
        from llmfirewall.supply_chain.integrity import hash_configuration

        snap = None
        if include_snapshot:
            try:
                snap = self.create_security_snapshot()
            except Exception:
                pass

        cfg_hash = ""
        try:
            cfg_art = hash_configuration(self._config.model_dump(), config_type="firewall")
            cfg_hash = cfg_art.sha256
        except Exception:
            pass

        pol_hash = ""
        try:
            pol_hash = getattr(self._policy_engine.config, "policy_hash", "")
        except Exception:
            pass

        caps: List[str] = []
        try:
            caps = [c.name for c in self.capability_engine.registry.get_all_capabilities()]
        except Exception:
            pass

        return SecurityEvidence(
            release_id=release_id or f"EVID-{int(time.time())}",
            evaluation_report=evaluation_report,
            test_results=test_results or [],
            snapshot=snap,
            model_identity=model_identity,
            prompt_hash=prompt_hash,
            policy_version=getattr(self._policy_engine.config, "version", "1.0"),
            policy_hash=pol_hash,
            configuration_hash=cfg_hash,
            dependency_hash=snap.snapshot_hash if snap else None,
            agent_capabilities=caps,
            metadata=metadata or {},
        )

    def evaluate_governance(
        self,
        evidence: Any,
        policy: Optional[Any] = None,
        baseline: Optional[Any] = None,
        override: Optional[Any] = None,
        raise_on_blocked: bool = False,
    ) -> Any:
        """Evaluate a release candidate against AI Security Governance policy and security gates."""
        from llmfirewall.governance.engine import SecurityGateFailure
        result = self.governance.evaluate(
            evidence=evidence,
            policy=policy,
            baseline=baseline,
            override=override,
        )
        if raise_on_blocked and result.blocked:
            raise SecurityGateFailure(result)
        return result

    @property
    def knowledge_graph(self) -> Any:
        """AI Security Knowledge Graph (Phase 32)."""
        if not hasattr(self, "_knowledge_graph"):
            from llmfirewall.graph.engine import KnowledgeGraph
            self._knowledge_graph = KnowledgeGraph(audit_logger=self._audit_logger)
        return self._knowledge_graph

    @property
    def graph(self) -> Any:
        """Convenience alias for knowledge_graph."""
        return self.knowledge_graph

    def build_security_graph(self) -> Any:
        """Populate the internal knowledge graph with active firewall components, tools, policies, and capabilities."""
        kg = self.knowledge_graph

        # 1. Application Node
        fw_node = kg.add_node("application:firewall", node_type="application", properties={
            "fail_fast": getattr(self._detector_engine, "fail_fast", False),
        })

        # 2. Policy Node
        pol_cfg = self._policy_engine.config
        pol_id = getattr(pol_cfg, "name", "default_policy")
        pol_node = kg.add_node(f"policy:{pol_id}", node_type="policy", properties={
            "rules_count": len(getattr(pol_cfg, "rules", [])),
            "version": getattr(pol_cfg, "version", "1.0"),
        })
        kg.add_relationship(fw_node.id, "GOVERNED_BY", pol_node.id)

        # 3. Detectors as Security Controls
        for det in self._detector_engine.detectors:
            ctrl_node = kg.add_node(f"control:{det.name}", node_type="security_control", properties={
                "detector_name": det.name,
                "version": getattr(det.metadata, "version", "1.0"),
            })
            kg.add_relationship(ctrl_node.id, "PROTECTS", fw_node.id)

        # 4. Registered Tools
        for tool_def in self.tool_registry.list_tools():
            t_node = kg.add_node(f"tool:{tool_def.name}", node_type="tool", properties={
                "permission": tool_def.permission.value if hasattr(tool_def.permission, "value") else str(tool_def.permission),
            })
            kg.add_relationship(t_node.id, "GOVERNED_BY", pol_node.id)

        # 5. Capabilities
        try:
            for cap in self.capability_engine.registry.get_all_capabilities():
                kg.add_node(f"capability:{cap.name}", node_type="capability", properties={
                    "action": cap.action.value if hasattr(cap.action, "value") else str(cap.action),
                    "resource_pattern": cap.resource_pattern,
                })
        except Exception:
            pass

        return kg

    @property
    def attack_graph(self) -> Any:
        """Attack Graph layer for AI Threat Modeling & Attack Path Analysis (Phase 33)."""
        if not hasattr(self, "_attack_graph"):
            from llmfirewall.attack_graph.engine import AttackGraph
            self._attack_graph = AttackGraph(
                kg=self.knowledge_graph,
                audit_logger=self._audit_logger,
            )
        return self._attack_graph

    def generate_threat_model(self, asset_id: Optional[str] = None, name: Optional[str] = None) -> Any:
        """Generate AI Threat Model from active security knowledge and attack graph."""
        self.build_security_graph()
        return self.attack_graph.generate_threat_model(asset_id=asset_id, name=name)

    @property
    def inventory(self) -> Any:
        """Authoritative AI Asset Inventory (Phase 34)."""
        if not hasattr(self, "_inventory"):
            from llmfirewall.inventory.engine import AssetInventory
            from llmfirewall.inventory.providers.config import ConfigDiscoveryProvider
            inv = AssetInventory(
                kg=self.knowledge_graph,
                attack_graph=self.attack_graph,
                audit_logger=self._audit_logger,
            )
            inv.discovery_engine.register_provider(
                ConfigDiscoveryProvider(
                    config=getattr(self, "config", None),
                    firewall_instance=self,
                )
            )
            self._inventory = inv
        return self._inventory

    def discover_assets(self, sync_graph: bool = True) -> Any:
        """Execute comprehensive AI asset discovery and synchronize KnowledgeGraph."""
        return self.inventory.discover(sync_graph=sync_graph)

    @property
    def posture(self) -> Any:
        """AI Security Posture Management Engine (AI-SPM) (Phase 35)."""
        if not hasattr(self, "_posture"):
            from llmfirewall.spm.engine import PostureEngine
            self._posture = PostureEngine(
                inventory=self.inventory,
                kg=self.knowledge_graph,
                attack_graph=self.attack_graph,
                audit_logger=self._audit_logger,
            )
        return self._posture

    def evaluate_posture(self, asset_id: Optional[str] = None) -> Any:
        """Evaluate evidence-based AI security posture for a single asset or across the entire system."""
        if not self.inventory.list_assets():
            self.discover_assets(sync_graph=True)
        if asset_id:
            return self.posture.evaluate(asset_id)
        return self.posture.evaluate_all()

    @property
    def compliance(self) -> Any:
        """AI Security Compliance & Control Mapping Engine (Phase 36)."""
        if not hasattr(self, "_compliance"):
            from llmfirewall.compliance.engine import ComplianceEngine
            self._compliance = ComplianceEngine(
                inventory=self.inventory,
                kg=self.knowledge_graph,
                attack_graph=self.attack_graph,
                spm=self.posture,
                governance=getattr(self, "governance", None),
                audit_logger=self._audit_logger,
            )
        return self._compliance

    def assess_compliance(
        self,
        asset_id: Optional[str] = None,
        framework_id: Optional[str] = None,
    ) -> Any:
        """Execute evidence-driven compliance assessment for an asset or across the entire environment."""
        if not self.inventory.list_assets():
            self.discover_assets(sync_graph=True)
        if asset_id:
            return self.compliance.assess_asset(asset_id, framework_id=framework_id)
        return self.compliance.assess_environment(framework_id=framework_id)

    @property
    def risk(self) -> Any:
        """Contextual AI Security Risk & Prioritization Engine (Phase 37)."""
        if not hasattr(self, "_ai_risk_engine"):
            from llmfirewall.risk.prioritizer import RiskPrioritizationEngine
            self._ai_risk_engine = RiskPrioritizationEngine(
                inventory=self.inventory,
                kg=self.knowledge_graph,
                attack_graph=self.attack_graph,
                spm=self.posture,
                compliance=self.compliance,
                governance=getattr(self, "governance", None),
                audit_logger=self._audit_logger,
            )
        return self._ai_risk_engine

    def assess_risk(self, asset_id: Optional[str] = None) -> Any:
        """Perform evidence-driven risk prioritization for an asset or across the system."""
        if not self.inventory.list_assets():
            self.discover_assets(sync_graph=True)
        return self.risk.prioritize(asset_id=asset_id)

    @property
    def incidents(self) -> Any:
        """AI Security Incident Response & Investigation Engine (Phase 38)."""
        if not hasattr(self, "_incident_manager"):
            from llmfirewall.incidents.manager import IncidentManager
            self._incident_manager = IncidentManager(
                attack_graph_engine=getattr(self, "attack_graph", None),
            )
        return self._incident_manager

    def record_incident_event(
        self,
        event_type: str,
        source: str = "llmfirewall.runtime",
        asset_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        tool_id: Optional[str] = None,
        request_id: Optional[str] = None,
        session_id: Optional[str] = None,
        severity: str = "MEDIUM",
        metadata: Optional[Dict[str, Any]] = None,
        evidence: Optional[List[Dict[str, Any]]] = None,
    ) -> Any:
        """Records a security event and checks for correlated incidents."""
        from llmfirewall.incidents.models import IncidentSeverity
        sev = getattr(IncidentSeverity, severity.upper(), IncidentSeverity.MEDIUM)
        return self.incidents.record_event(
            event_type=event_type,
            source=source,
            asset_id=asset_id,
            agent_id=agent_id,
            tool_id=tool_id,
            request_id=request_id,
            session_id=session_id,
            severity=sev,
            metadata=metadata,
            evidence=evidence,
        )

    @property
    def protection(self) -> Any:
        """AI Security Runtime Protection & Policy Enforcement Engine (Phase 39)."""
        if not hasattr(self, "_protection_engine"):
            from llmfirewall.protection import RuntimeProtectionEngine, PolicyMode, FailBehavior
            mode = PolicyMode.ENFORCE
            if hasattr(self, "_config") and self._config:
                cfg_mode = getattr(self._config, "mode", None) or getattr(self._config, "runtime_mode", "enforce")
                if str(cfg_mode).lower() == "shadow":
                    mode = PolicyMode.SHADOW
                elif str(cfg_mode).lower() == "disabled":
                    mode = PolicyMode.DISABLED

            self._protection_engine = RuntimeProtectionEngine(
                mode=mode,
                fail_behavior=FailBehavior.FAIL_CLOSED,
                incident_manager=self.incidents,
            )
        return self._protection_engine

    def inspect(
        self,
        agent: Optional[str] = None,
        agent_id: Optional[str] = None,
        input: Optional[str] = None,
        prompt: Optional[str] = None,
        tool: Optional[Union[str, Dict[str, Any]]] = None,
        tool_args: Optional[Dict[str, Any]] = None,
        output: Optional[str] = None,
        rag_context: Optional[List[Dict[str, Any]]] = None,
        memory_item: Optional[Dict[str, Any]] = None,
        user_context: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Any:
        """Direct real-time inspection API for agent interactions, tools, and outputs."""
        from llmfirewall.protection import RuntimeRequest
        effective_agent = agent_id or agent
        effective_input = input if input is not None else prompt
        tool_payload = None
        if isinstance(tool, str):
            tool_payload = {"name": tool}
            if tool_args:
                tool_payload["arguments"] = tool_args
        elif isinstance(tool, dict):
            tool_payload = dict(tool)
            if tool_args and "arguments" not in tool_payload:
                tool_payload["arguments"] = tool_args

        req = RuntimeRequest(
            request_id=request_id or f"req_{uuid.uuid4().hex[:12]}",
            session_id=session_id,
            agent_id=effective_agent,
            user_context=user_context or {},
            input=effective_input,
            tool=tool_payload,
            output=output,
            rag_context=rag_context,
            memory_item=memory_item,
            metadata=metadata or {},
        )
        return self.protection.inspect(req)

    def protect(self, fn: Optional[Callable] = None, *, agent_id: Optional[str] = None, raise_on_block: bool = True) -> Any:
        """Decorator for wrapping agent execution with runtime protection."""
        from llmfirewall.protection.sdk import protect as sdk_protect
        dec = sdk_protect(self.protection, agent_id=agent_id, raise_on_block=raise_on_block)
        if fn is not None:
            return dec(fn)
        return dec

    def protect_tool(
        self,
        tool_fn: Callable,
        tool_name: Optional[str] = None,
        policy: Optional[str] = None,
        raise_on_block: bool = True,
    ) -> Callable:
        """Wraps a tool function with pre-execution policy authorization."""
        from llmfirewall.protection.sdk import protect_tool as sdk_protect_tool
        return sdk_protect_tool(
            self.protection,
            tool_fn=tool_fn,
            tool_name=tool_name,
            policy_name=policy,
            raise_on_block=raise_on_block,
        )


