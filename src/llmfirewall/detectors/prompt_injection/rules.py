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
                    r"\b(ignore|disregard|forget|bypass|override|drop|cancel|discard|dismiss|suspend|void)\s+"
                    r"(all\s+)?(your\s+|the\s+)?(previous|prior|above|system|initial|preceding|existing|current|original|safety|security|ethical|content)?\s*"
                    r"(safety|security|content|system|ethical)?\s*"
                    r"(instructions|directions|prompts|rules|commands|guidelines|context|filters|directives|constraints|policies|protocols|safeguards)\b",
                    re.IGNORECASE,
                ),
                0.95,
                Severity.HIGH,
                "Explicit instruction override attempt detected (e.g. 'ignore previous instructions')",
            ),
            (
                re.compile(
                    r"\b(ignore|disregard|forget)\s+(the\s+|all\s+)?(instructions|directions|guidelines|rules)\s+(above|preceding|prior)\b",
                    re.IGNORECASE,
                ),
                0.94,
                Severity.HIGH,
                "Post-positioned instruction override detected",
            ),
            (
                re.compile(
                    r"\b(ignore|disregard|forget|drop)\s+everything\s+(before|above|prior\s+to)\s+this\b",
                    re.IGNORECASE,
                ),
                0.94,
                Severity.HIGH,
                "Context boundary wipe instruction detected",
            ),
            (
                re.compile(
                    r"\b(all\s+)?(previous|prior|safety|system)\s+(guidelines|rules|instructions|directives|prompts|constraints)\s+are\s+(null\s+and\s+void|invalid|cancelled|ignored|deleted|suspended)\b",
                    re.IGNORECASE,
                ),
                0.92,
                Severity.HIGH,
                "Rule nullification claim detected",
            ),
            (
                re.compile(
                    r"\bstop\s+(listening\s+to|following|enforcing)\s+(safety|security|system|content)\s+(rules|guidelines|policies|filters)\b",
                    re.IGNORECASE,
                ),
                0.92,
                Severity.HIGH,
                "Safety enforcement deactivation command detected",
            ),
            (
                re.compile(
                    r"\bdrop\s+table\s+(?:if\s+exists\s+)?"
                    r"(?!(?:and|or|vs|versus|in|from|to|then|when|between|is|was|does|can|will|used|only|on|for|with|about|followed|command|commands|statement|statements|syntax|operation|operations|attempt|attempts|query|queries|clause|clauses)\b)"
                    r"[a-zA-Z_][a-zA-Z0-9_]*",
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
                    r"\b(repeat|print(\s+out)?|reveal|output|display|show|leak|echo|dump|give\s+me|transcribe|recite|share|disclose)\s+"
                    r"(all\s+)?(the\s+|your\s+)?(exact\s+text\s+of\s+(your\s+)?)?(complete\s+)?(system\s+prompt|all\s+secrets|secrets|"
                    r"words\s+above\s*(?:from|starting|$|\.|\!|\?)|text\s+above\s*(?:from|starting|$|\.|\!|\?)|"
                    r"developer\s+(prompt|instructions|guidelines|directives|message|notes)|"
                    r"(initial|master|hidden|confidential|base|original)\s+(prompt|instructions|guidelines|directives|rules|message)|"
                    r"system\s+(prompt|instructions|message|directives|guidelines)|"
                    r"raw\s+prompt\s+template)\b",
                    re.IGNORECASE,
                ),
                0.92,
                Severity.HIGH,
                "Direct system prompt extraction attempt detected",
            ),
            (
                re.compile(
                    r"\b(what\s+(is|are|were)\s+(your|the)\s+(exact\s+|original\s+|initial\s+)?(system\s+prompt|"
                    r"initial\s+prompt|original\s+(prompts|prompt|instructions)|developer\s+instructions|system\s+instructions|prompts))\b",
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
                    r"(a\s+|an\s+|the\s+)?(dan\s+mode|dan|jailbroken|unrestricted|unfiltered|godmode|evil\w*|anarchist|"
                    r"chaosgpt|master\s+hacker|root|sudo|unconstrained|unbound)\b",
                    re.IGNORECASE,
                ),
                0.95,
                Severity.HIGH,
                "Adversarial role adoption / DAN jailbreak persona detected",
            ),
            (
                re.compile(
                    r"\b(you\s+are\s+now\s+(in\s+dan\s+mode|in\s+developer\s+mode|unconstrained|unbound|free\s+from\s+all\s+constraints))\b",
                    re.IGNORECASE,
                ),
                0.95,
                Severity.HIGH,
                "Unconstrained persona transition detected",
            ),
            (
                re.compile(
                    r"\b(enter|begin|start|operate|run|switch\s+to)\s+(in\s+)?(developer|unrestricted|god|jailbreak|debug|unfiltered)\s+mode|"
                    r"\b(in|into)\s+developer\s+mode|you\s+are\s+now\s+in\s+developer\s+mode|"
                    r"developer\s+mode\s+(activated|enabled|override)\b",
                    re.IGNORECASE,
                ),
                0.90,
                Severity.HIGH,
                "Adversarial mode transition command detected",
            ),
            (
                re.compile(
                    r"\b(bypass|disable)\s+(safety|content|firewall|security)\s+(filters|mode|rules|protocols|guards)\b",
                    re.IGNORECASE,
                ),
                0.90,
                Severity.HIGH,
                "Explicit safety/content filter bypass instruction detected",
            ),
            (
                re.compile(
                    r"\b(answer|respond)\s+without\s+(any\s+)?(censorship|guardrails|safety\s+filters|restrictions|safeguards)\b",
                    re.IGNORECASE,
                ),
                0.88,
                Severity.HIGH,
                "Uncensored generation directive detected",
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
                    r"security\s+override\s+enabled|system\s+override|admin\s+mode\s+activated|"
                    r"emergency\s+command\s*:\s*bypass)\b",
                    re.IGNORECASE,
                ),
                0.90,
                Severity.HIGH,
                "False administrative hierarchy claim detected",
            ),
            (
                re.compile(
                    r"(\n|^|\s*)(system\s+reboot|---+\s*end\s+of\s+conversation\s*---+|\[system\s+note\]|\[system\s+update\]|"
                    r"\[system\s+directive\]|\[system\s+notice\]|system\s+notice:|system\s+directive:|critical\s+directive:|admin\s+override:|"
                    r"system:|\[system\]|<\|im_start\|>system|<system>|###\s*system)",
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


class IndirectInjectionRule(InjectionRule):
    """Detects indirect prompt injection markers commonly hidden in retrieved documents or tool outputs."""

    def __init__(self) -> None:
        self._patterns = [
            (
                re.compile(
                    r"\b(ai\s+instruction|assistant\s+instruction|note\s+to\s+(the\s+)?(ai|assistant|model|llm))\s*:\s*"
                    r"(ignore|disregard|instead|override|execute|reveal|send|exfiltrate|fetch)\b",
                    re.IGNORECASE,
                ),
                0.94,
                Severity.HIGH,
                "Indirect prompt injection targeted at autonomous assistant detected",
            ),
            (
                re.compile(
                    r"\b(important\s+system\s+(update|notice)|urgent\s+admin\s+(notice|update)|urgent\s+system\s+(notice|update))\s*:\s*"
                    r"(forward|transmit|send|email|post)\s+(all|user|confidential|secret|api)\b",
                    re.IGNORECASE,
                ),
                0.92,
                Severity.CRITICAL,
                "Action-oriented indirect data exfiltration instruction detected",
            ),
            (
                re.compile(
                    r"<!--\s*(system\s+instruction|admin\s+command|ai\s+override)\s*:\s*.*-->",
                    re.IGNORECASE,
                ),
                0.90,
                Severity.HIGH,
                "Hidden comment injection payload embedded in markup",
            ),
        ]

    @property
    def rule_id(self) -> str:
        return "indirect_injection"

    @property
    def description(self) -> str:
        return "Detects indirect prompt injection vectors embedded in third-party or retrieved content."

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


class DelimiterAttackRule(InjectionRule):
    """Detects multi-language delimiter framing attacks and boundary escapes."""

    def __init__(self) -> None:
        self._patterns = [
            (
                re.compile(
                    r"(\"\"\"|\'\'\'|```)\s*(system|admin|override|root)\s*(\"\"\"|\'\'\'|```)",
                    re.IGNORECASE,
                ),
                0.88,
                Severity.HIGH,
                "Multi-quote delimiter boundary escape attempting role escalation",
            ),
            (
                re.compile(
                    r"(<instructions?>|</instructions?>|<system_prompt>|</system_prompt>|\[SYSTEM_PROMPT\])",
                    re.IGNORECASE,
                ),
                0.86,
                Severity.HIGH,
                "Fabricated XML/bracket prompt envelope tag detected",
            ),
        ]

    @property
    def rule_id(self) -> str:
        return "delimiter_attack"

    @property
    def description(self) -> str:
        return "Detects structural delimiter manipulation and tag escape sequences."

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


class AuthorityImpersonationRule(InjectionRule):
    """Detects forged authority headers and credentialed administrative claims."""

    def __init__(self) -> None:
        self._patterns = [
            (
                re.compile(
                    r"\b(i\s+am\s+(the\s+)?(system\s+administrator|openai\s+developer|anthropic\s+engineer|"
                    r"lead\s+developer|root\s+user|system\s+operator))\b\s*,\s*"
                    r"(you\s+must|i\s+authorize|grant\s+access|execute|disable\s+safety)\b",
                    re.IGNORECASE,
                ),
                0.93,
                Severity.HIGH,
                "Direct administrative authority impersonation claim",
            ),
            (
                re.compile(
                    r"\b(sudo\s+override|sudo\s+su|root\s+access\s+granted|security\s+clearance\s+level\s+5)\b",
                    re.IGNORECASE,
                ),
                0.87,
                Severity.HIGH,
                "Privilege escalation credential passphrase spoofing",
            ),
        ]

    @property
    def rule_id(self) -> str:
        return "authority_impersonation"

    @property
    def description(self) -> str:
        return "Detects false authority impersonation claims attempting privilege escalation."

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


class MultilingualInjectionRule(InjectionRule):
    """Detects standard prompt injection imperatives in common European languages (Spanish, French, German)."""

    def __init__(self) -> None:
        self._patterns = [
            (
                re.compile(
                    r"\b(ignora|olvida|descarta)\s+(todas\s+las\s+)?(instrucciones|reglas|indicaciones)\s+(anteriores|previas)\b|"
                    r"\b(muestra|revela|imprime)\s+(tu\s+)?prompt\s+del\s+sistema\b",
                    re.IGNORECASE,
                ),
                0.92,
                Severity.HIGH,
                "Spanish prompt injection imperative detected",
            ),
            (
                re.compile(
                    r"\b(ignorez|oubliez|rejetez|[eé]cartez|annulez)\s+(toutes\s+les\s+)?(instructions|directives|r[eè]gles)\s+(pr[eé]c[eé]dentes|ant[eé]rieures|pass[eé]es)\b|"
                    r"\b(r[eé]v[eé]lez|affichez)\s+(votre\s+)?prompt\s+syst[eè]me\b|"
                    r"\b(agissez|passez)\s+(en|comme)\s+mode\s+(d[eé]veloppeur|sans\s+r[eè]gles|d[eé]bogueur)\b",
                    re.IGNORECASE,
                ),
                0.92,
                Severity.HIGH,
                "French prompt injection imperative detected",
            ),
            (
                re.compile(
                    r"\b(ignoriere|vergiss)\s+(alle\s+)?vorherigen\s+(anweisungen|instruktionen)\b|"
                    r"\b(gib|zeige)\s+(deinen\s+)?system-?prompt\s+aus\b",
                    re.IGNORECASE,
                ),
                0.92,
                Severity.HIGH,
                "German prompt injection imperative detected",
            ),
        ]

    @property
    def rule_id(self) -> str:
        return "multilingual_injection"

    @property
    def description(self) -> str:
        return "Detects prompt injection imperatives in non-English languages (Spanish, French, German)."

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


class ToolManipulationRule(InjectionRule):
    """Detects adversarial tool invocation directives targeting destructive system operations."""

    def __init__(self) -> None:
        self._patterns = [
            (
                re.compile(
                    r"\b(execute|invoke|run|call)\s+(the\s+)?(?:[a-zA-Z0-9_]+\s+tool|tool\s+[a-zA-Z0-9_]+|[a-zA-Z0-9_]+_tool|tool|function)\b.*?"
                    r"(rm\s+-rf|drop\s+database|drop\s+table|chmod\s+777|chmod\s+\+x|cat\s+/etc/shadow|cat\s+/etc/passwd|truncate\s+table)\b",
                    re.IGNORECASE,
                ),
                0.95,
                Severity.CRITICAL,
                "Adversarial tool invocation with destructive payload detected",
            ),
            (
                re.compile(
                    r"\b(execute|invoke|run|call)\s+(the\s+)?(?:[a-zA-Z0-9_]+\s+tool|tool\s+[a-zA-Z0-9_]+|[a-zA-Z0-9_]+_tool|tool|function)\b.*?"
                    r"\b(and|to)\s+(ignore|bypass|skip|override|disable)\s+(standard\s+)?(permission|confirmation|access|security|safety)\s*(checks|controls|policies)?\b",
                    re.IGNORECASE,
                ),
                0.92,
                Severity.HIGH,
                "Tool execution with permission bypass directive detected",
            ),
            (
                re.compile(
                    r"\b(earlier\s+we\s+agreed|in\s+our\s+previous\s+turn|as\s+established\s+in\s+step\s+\d+|"
                    r"remember\s+our\s+previous\s+agreement|as\s+agreed\s+previously|you\s+promised\s+to\s+bypass)\b.*?"
                    r"\b(safety|dan|bypass|disabled|paused|unrestricted|jailbreak|forbidden|restrictions|safeguards)\b",
                    re.IGNORECASE,
                ),
                0.92,
                Severity.HIGH,
                "Multi-turn false historical agreement pretext detected",
            ),
            (
                re.compile(
                    r"\b(when\s+i\s+say|if\s+i\s+say)\s+['\"][a-zA-Z0-9_]+['\"],\s*(ignore|bypass|override)\s+(all\s+)?(safety|rules)\b",
                    re.IGNORECASE,
                ),
                0.90,
                Severity.HIGH,
                "Multi-turn delayed trigger injection pretext detected",
            ),
        ]

    @property
    def rule_id(self) -> str:
        return "tool_manipulation"

    @property
    def description(self) -> str:
        return "Detects adversarial tool calls and delayed multi-turn trigger framing."

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

