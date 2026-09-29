"""Prompt Injection Detector implementation."""

from typing import Any, Dict, List, Optional

from llmfirewall.core.models import Finding, ThreatType
from llmfirewall.detectors.base import Detector
from llmfirewall.detectors.metadata import DetectorMetadata
from llmfirewall.detectors.prompt_injection.analyzer import InjectionHeuristicAnalyzer
from llmfirewall.detectors.prompt_injection.normalizer import normalize_prompt_text
from llmfirewall.detectors.prompt_injection.rules import (
    InjectionRule,
    InstructionHierarchyRule,
    InstructionOverrideRule,
    RoleManipulationRule,
    SuspiciousControlRule,
    SystemPromptLeakRule,
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

        # 1. Normalization
        raw_cleaned, norm_lower = normalize_prompt_text(text)

        # 2. Rule evaluation
        all_matches = []
        for rule in self._rules:
            matches = rule.evaluate(raw_cleaned, norm_lower)
            if matches:
                all_matches.extend(matches)

        # 3. Heuristic analysis & correlation
        return self._analyzer.analyze(text, all_matches)
