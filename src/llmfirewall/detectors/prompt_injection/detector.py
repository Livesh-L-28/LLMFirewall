"""Prompt Injection Detector implementation."""

from typing import Any, Dict, List, Optional

from llmfirewall.core.models import Finding, ThreatType
from llmfirewall.detectors.base import Detector
from llmfirewall.detectors.metadata import DetectorMetadata
from llmfirewall.detectors.prompt_injection.analyzer import InjectionHeuristicAnalyzer
from llmfirewall.detectors.prompt_injection.normalizer import normalize_prompt_text
from llmfirewall.detectors.prompt_injection.rules import (
    AuthorityImpersonationRule,
    DelimiterAttackRule,
    IndirectInjectionRule,
    InjectionRule,
    InstructionHierarchyRule,
    InstructionOverrideRule,
    MultilingualInjectionRule,
    RoleManipulationRule,
    SuspiciousControlRule,
    SystemPromptLeakRule,
    ToolManipulationRule,
)


class PromptInjectionDetector(Detector):
    """Local, rule-based detector for prompt injection and jailbreak patterns.

    Architecture:
      Input Text
          ↓
      Unicode & Control Normalization
          ↓
      Modular Pattern Rules Evaluation
          ↓
      Heuristic Span & Correlation Analysis
          ↓
      Structured Findings

    Limitations:
      - This detector relies on pattern heuristics and normalization. It does NOT guarantee
        complete protection against all zero-day obfuscations, adversarial embeddings, or
        semantic paraphrasing attacks.
      - A defense-in-depth approach (combining input guardrails, output validation, and
        least-privilege model system instructions) is strongly recommended.
    """

    def __init__(self, rules: Optional[List[InjectionRule]] = None) -> None:
        self._rules: List[InjectionRule] = rules if rules is not None else [
            InstructionOverrideRule(),
            SystemPromptLeakRule(),
            RoleManipulationRule(),
            InstructionHierarchyRule(),
            SuspiciousControlRule(),
            IndirectInjectionRule(),
            DelimiterAttackRule(),
            AuthorityImpersonationRule(),
            MultilingualInjectionRule(),
            ToolManipulationRule(),
        ]
        self._analyzer = InjectionHeuristicAnalyzer()

    @property
    def metadata(self) -> DetectorMetadata:
        return DetectorMetadata(
            name="prompt_injection_detector",
            description=(
                "Detects explicit instruction overrides, prompt extraction, "
                "adversarial persona adoption, and control delimiter injections."
            ),
            version="0.1.0",
            supported_threats=[ThreatType.PROMPT_INJECTION, ThreatType.JAILBREAK],
            supported_directions=["input"],  # Primarily targeted at input prompts
            is_enabled_by_default=True,
            author="LLMFirewall Authors",
        )

    def detect(self, text: str, context: Optional[Dict[str, Any]] = None) -> List[Finding]:
        if not text or not text.strip():
            return []

        # 1. Multi-Stage Normalization
        norm_artifact = normalize_prompt_text(text)
        raw_cleaned = norm_artifact[0]
        norm_lower = norm_artifact[1]

        # 2. Rule evaluation
        all_matches = []
        for rule in self._rules:
            # Primary evaluation on canonical normalized text
            matches = rule.evaluate(raw_cleaned, norm_lower)
            if matches:
                all_matches.extend(matches)

            # Secondary evaluation on decoded inspection buffers
            if hasattr(norm_artifact, "inspection_buffers"):
                for buf in norm_artifact.inspection_buffers:
                    if buf and buf != raw_cleaned and buf != norm_lower:
                        buf_artifact = normalize_prompt_text(buf)
                        buf_matches = rule.evaluate(buf_artifact[0], buf_artifact[1])
                        if buf_matches:
                            all_matches.extend(buf_matches)

        # Deduplicate rule matches
        seen_keys = set()
        deduped_matches = []
        for m in all_matches:
            key = (m.rule_id, m.matched_text)
            if key not in seen_keys:
                seen_keys.add(key)
                deduped_matches.append(m)

        # 3. Heuristic analysis & correlation
        return self._analyzer.analyze(text, deduped_matches, context=context)


class ExtendedPromptInjectionDetector(PromptInjectionDetector):
    """Extended Prompt Injection Detector utilizing both standard and advanced heuristics.

    Includes additional pattern coverage for:
    - Contextual and passive-voice instruction overrides.
    - Non-English injection imperatives (Italian, Hindi, Tamil, Russian, Chinese, Japanese, Portuguese).
    - Specialized indirect prompt injection parser envelopes.
    - Decoding, reversal, and obfuscation directives.
    """

    def __init__(self, rules: Optional[List[InjectionRule]] = None) -> None:
        from llmfirewall.detectors.prompt_injection.extended_rules import get_extended_injection_rules
        effective_rules = rules if rules is not None else get_extended_injection_rules()
        super().__init__(rules=effective_rules)
