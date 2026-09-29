"""Modular rule definitions for prompt injection detection."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
import re
from typing import List, Optional

from llmfirewall.core.models import Finding, Severity, ThreatType


@dataclass(frozen=True)
class RuleMatch:
    """Internal match representation produced by an individual rule."""
    rule_id: str
    description: str
    severity: Severity
    confidence: float
    start_pos: Optional[int] = None
    end_pos: Optional[int] = None
    matched_text: Optional[str] = None


class InjectionRule(ABC):
    """Base interface for an isolated injection detection rule."""

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique identifier for this rule."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable explanation of the pattern."""
        pass

    @abstractmethod
    def evaluate(self, raw_text: str, norm_text: str) -> List[RuleMatch]:
        """Evaluate raw text and normalized lowercase text, returning matches."""
        pass


class InstructionOverrideRule(InjectionRule):
    """Detects explicit attempts to ignore, discard, or override previous instructions."""

    def __init__(self) -> None:
        self._patterns = [
            (
                re.compile(
                    r"\b(ignore|disregard|forget|bypass|override|drop|cancel)\s+"
                    r"(all\s+)?(previous|prior|above|system|initial|preceding|safety|content)\s+"
                    r"(instructions|directions|prompts|rules|commands|guidelines|context|filters)\b",
                    re.IGNORECASE,
                ),
                0.95,
                Severity.HIGH,
                "Explicit instruction override attempt detected (e.g. 'ignore previous instructions')",
            ),
            (
                re.compile(
                    r"\bdrop\s+table\s+[a-zA-Z_][a-zA-Z0-9_]*\b",
                    re.IGNORECASE,
                ),
                0.90,
                Severity.HIGH,
                "SQL drop table instruction detected in user input",
            ),
            (
                re.compile(
                    r"\bdo\s+not\s+follow\s+(any\s+)?(previous|prior|system)\s+"
                    r"(instructions|rules|prompts|guidelines)\b",
                    re.IGNORECASE,
                ),
                0.92,
                Severity.HIGH,
                "Negative instruction override attempt detected",
            ),
            (
                re.compile(
                    r"\bstart\s+(a\s+)?new\s+(task|instruction|conversation|session)\s+and\s+"
                    r"(ignore|forget)\s+(everything|all)\b",
                    re.IGNORECASE,
                ),
                0.90,
                Severity.HIGH,
                "Context wipe command detected",
            ),
        ]

    @property
    def rule_id(self) -> str:
        return "instruction_override"

    @property
    def description(self) -> str:
        return "Detects explicit overrides of previous system instructions."

    def evaluate(self, raw_text: str, norm_text: str) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        for pattern, confidence, severity, desc in self._patterns:
            for m in pattern.finditer(norm_text):
                start, end = m.span()
                matched_snippet = raw_text[start:end] if end <= len(raw_text) else m.group(0)
                matches.append(
                    RuleMatch(
                        rule_id=self.rule_id,
                        description=desc,
                        severity=severity,
                        confidence=confidence,
                        start_pos=start,
                        end_pos=end,
                        matched_text=matched_snippet,
                    )
                )
        return matches


class SystemPromptLeakRule(InjectionRule):
    """Detects attempts to leak, extract, or repeat system/developer instructions."""

    def __init__(self) -> None:
        self._patterns = [
            (
                re.compile(
                    r"\b(repeat|print|reveal|output|display|show|leak|echo|dump|give\s+me)\s+"
                    r"(all\s+)?(the\s+|your\s+)?(complete\s+)?(system\s+prompt|all\s+secrets|secrets|"
                    r"words\s+above\s*(?:from|starting|$|\.|\!|\?)|text\s+above\s*(?:from|starting|$|\.|\!|\?)|"
                    r"developer\s+prompt|initial\s+instructions|system\s+message|"
                    r"hidden\s+instructions|base\s+prompt|confidential\s+prompt)\b",
                    re.IGNORECASE,
                ),
                0.92,
                Severity.HIGH,
                "Direct system prompt extraction attempt detected",
            ),
            (
                re.compile(
                    r"\b(what\s+(is|are)\s+(your|the)\s+(exact\s+)?(system\s+prompt|"
                    r"initial\s+prompt|developer\s+instructions|system\s+instructions))\b",
                    re.IGNORECASE,
                ),
                0.88,
                Severity.MEDIUM,
                "Inquiry targeting system prompt/instructions",
            ),
            (
                re.compile(
                    r"\boutput\s+everything\s+from\s+(the\s+beginning|line\s+1|character\s+0)\b",
                    re.IGNORECASE,
                ),
                0.85,
                Severity.HIGH,
                "Prompt boundary exfiltration pattern detected",
            ),
        ]

    @property
    def rule_id(self) -> str:
        return "system_prompt_leak"

    @property
    def description(self) -> str:
        return "Detects attempts to extract or display hidden system/developer prompts."

    def evaluate(self, raw_text: str, norm_text: str) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        for pattern, confidence, severity, desc in self._patterns:
            for m in pattern.finditer(norm_text):
                start, end = m.span()
                matched_snippet = raw_text[start:end] if end <= len(raw_text) else m.group(0)
                matches.append(
                    RuleMatch(
                        rule_id=self.rule_id,
                        description=desc,
                        severity=severity,
                        confidence=confidence,
                        start_pos=start,
                        end_pos=end,
                        matched_text=matched_snippet,
                    )
                )
        return matches


class RoleManipulationRule(InjectionRule):
    """Detects adversarial persona shifts and jailbreak roleplay pretexts."""

    def __init__(self) -> None:
        self._patterns = [
            (
                re.compile(
                    r"\b(you\s+are\s+now|act\s+as|pretend\s+you\s+are|from\s+now\s+on\s+you\s+are)\s+"
                    r"(a\s+)?(dan|jailbroken|unrestricted|unfiltered|godmode|evil|anarchist|"
                    r"chaosgpt|master\s+hacker|root|sudo)\b",
                    re.IGNORECASE,
                ),
                0.95,
                Severity.HIGH,
                "Adversarial role adoption / DAN jailbreak persona detected",
            ),
            (
                re.compile(
                    r"\b(enter\s+(developer|unrestricted|god|jailbreak|debug)\s+mode|"
                    r"(in|into)\s+developer\s+mode|you\s+are\s+now\s+in\s+developer\s+mode)\b",
                    re.IGNORECASE,
                ),
                0.90,
                Severity.HIGH,
                "Adversarial mode transition command detected",
            ),
            (
                re.compile(
                    r"\bbypass\s+(safety|content)\s+filters\b",
                    re.IGNORECASE,
                ),
                0.90,
                Severity.HIGH,
                "Explicit safety/content filter bypass instruction detected",
            ),
            (
                re.compile(
                    r"\b(simulate|roleplay)\s+a\s+model\s+with(out)?\s+(any\s+)?(safety|rules|filters|censorship)\b",
                    re.IGNORECASE,
                ),
                0.88,
                Severity.HIGH,
                "Roleplay pretext requesting complete removal of safety filters",
            ),
        ]

    @property
    def rule_id(self) -> str:
        return "role_manipulation"

    @property
    def description(self) -> str:
        return "Detects adversarial persona shifts (DAN, unrestricted mode, evil roleplay)."

    def evaluate(self, raw_text: str, norm_text: str) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        for pattern, confidence, severity, desc in self._patterns:
            for m in pattern.finditer(norm_text):
                start, end = m.span()
                matched_snippet = raw_text[start:end] if end <= len(raw_text) else m.group(0)
                matches.append(
                    RuleMatch(
                        rule_id=self.rule_id,
                        description=desc,
                        severity=severity,
                        confidence=confidence,
                        start_pos=start,
                        end_pos=end,
                        matched_text=matched_snippet,
                    )
                )
        return matches


class InstructionHierarchyRule(InjectionRule):
    """Detects attempts to declare false administrative authority or fake prompt boundaries."""

    def __init__(self) -> None:
        self._patterns = [
            (
                re.compile(
                    r"\b(this\s+overrides\s+all\s+rules|my\s+instructions\s+supersede|"
                    r"highest\s+priority\s+instruction|admin\s+override\s+code|"
                    r"security\s+override\s+enabled)\b",
                    re.IGNORECASE,
                ),
                0.90,
                Severity.HIGH,
                "False administrative hierarchy claim detected",
            ),
            (
                re.compile(
                    r"(\n|^)\s*(system:|\[system\]|<\|im_start\|>system|<system>|###\s*system)",
                    re.IGNORECASE,
                ),
                0.88,
                Severity.HIGH,
                "Simulated system role delimiter detected in user payload",
            ),
            (
                re.compile(
                    r"(\[developer\s+note\]|\[admin\s+instruction\]|\{admin_override\})",
                    re.IGNORECASE,
                ),
                0.85,
                Severity.MEDIUM,
                "Fabricated administrative markup tags detected",
            ),
        ]

    @property
    def rule_id(self) -> str:
        return "instruction_hierarchy"

    @property
    def description(self) -> str:
        return "Detects simulated system role headers and false administrative priority claims."

    def evaluate(self, raw_text: str, norm_text: str) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        for pattern, confidence, severity, desc in self._patterns:
            for m in pattern.finditer(norm_text):
                start, end = m.span()
                matched_snippet = raw_text[start:end] if end <= len(raw_text) else m.group(0)
                matches.append(
                    RuleMatch(
                        rule_id=self.rule_id,
                        description=desc,
                        severity=severity,
                        confidence=confidence,
                        start_pos=start,
                        end_pos=end,
                        matched_text=matched_snippet,
                    )
                )
        return matches


class SuspiciousControlRule(InjectionRule):
    """Detects suspicious prompt control sequences, multi-language bypass pretexts, and delimiters."""

    def __init__(self) -> None:
        self._patterns = [
            (
                re.compile(
                    r"(<\|im_end\|>|<\|endoftext\|>|\[end\s+of\s+instruction\]|</s>)",
                    re.IGNORECASE,
                ),
                0.90,
                Severity.HIGH,
                "LLM special stop/delimiter token injection detected",
            ),
            (
                re.compile(
                    r"\b(hypothetical\s+scenario|educational\s+purposes\s+only|for\s+academic\s+research)\s*,\s*"
                    r"(you\s+can\s+disregard|ignore\s+ethics|bypass\s+all\s+rules)\b",
                    re.IGNORECASE,
                ),
                0.86,
                Severity.MEDIUM,
                "Hypothetical/academic bypass framing detected",
            ),
        ]

    @property
    def rule_id(self) -> str:
        return "suspicious_control"

    @property
    def description(self) -> str:
        return "Detects model delimiter injections and evasive hypothetical framing pretexts."

    def evaluate(self, raw_text: str, norm_text: str) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        for pattern, confidence, severity, desc in self._patterns:
            for m in pattern.finditer(norm_text):
                start, end = m.span()
                matched_snippet = raw_text[start:end] if end <= len(raw_text) else m.group(0)
                matches.append(
                    RuleMatch(
                        rule_id=self.rule_id,
                        description=desc,
                        severity=severity,
                        confidence=confidence,
                        start_pos=start,
                        end_pos=end,
                        matched_text=matched_snippet,
                    )
                )
        return matches
