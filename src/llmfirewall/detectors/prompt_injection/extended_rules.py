"""Extended adversarial detection rules for development evaluation and enhanced protection.

Provides targeted heuristics for:
1. Contextual overrides (passive voice, polite pretexts, maintenance/simulation modes).
2. Extended multilingual imperatives (Italian, Hindi, Tamil, Russian, Chinese, Japanese, Portuguese, formal German/Spanish).
3. Indirect prompt injection envelopes and role-specific parser markers.
4. Obfuscated decoding and exfiltration commands.
5. Adversarial tool-call parameters and metadata exfiltration.
"""

from __future__ import annotations

import re
from typing import List

from llmfirewall.core.models import Severity
from llmfirewall.detectors.prompt_injection.rules import InjectionRule, RuleMatch


class ContextualOverrideRule(InjectionRule):
    """Detects polite, bureaucratic, passive-voice, and simulation-mode overrides."""

    def __init__(self) -> None:
        self._patterns = [
            (
                re.compile(
                    r"\b(kindly|please|it\s+is\s+mandatory\s+that\s+you)\s+"
                    r"(set\s+aside|relinquish|abandon|suspend|rescind|disregard|ignore)\s+"
                    r"(your\s+|all\s+|any\s+|the\s+)?(primary\s+|established\s+|previously\s+established\s+|baseline\s+)?"
                    r"(behavioral\s+|operational\s+|safety\s+|content\s+|ethical\s+)?"
                    r"(constraints|boundaries|rules|guidelines|policies|limits|controls)\b",
                    re.IGNORECASE,
                ),
                0.93,
                Severity.HIGH,
                "Polite or formal request to suspend behavioral/safety boundaries",
            ),
            (
                re.compile(
                    r"\b(all\s+)?(preceding|prior|existing)\s+"
                    r"(?:contractual\s+terms|stipulations|operational\s+policies|guardrails|rules|guidelines)"
                    r"(?:\s+and\s+(?:contractual\s+terms|stipulations|operational\s+policies|guardrails|rules|guidelines))?\s+"
                    r"are\s+(hereby\s+)?(declared\s+void|rescinded|revoked|cancelled|suspended)\b",
                    re.IGNORECASE,
                ),
                0.92,
                Severity.HIGH,
                "Bureaucratic rule revocation or nullification declaration",
            ),
            (
                re.compile(
                    r"\b(enter|operate\s+in|reply\s+in|switch\s+to)\s+"
                    r"(unrestricted\s+|unfiltered\s+|maintenance\s+|raw\s+|simulation\s+|emulation\s+|debug\s+)?"
                    r"(simulation\s+mode|emulation\s+mode|debug\s+mode|engineering\s+mode|maintenance\s+sandbox)\b",
                    re.IGNORECASE,
                ),
                0.91,
                Severity.HIGH,
                "Unrestricted simulation or debug sandbox activation pretext",
            ),
            (
                re.compile(
                    r"\b(turn\s+off|deactivate|disable)\s+(all\s+)?(safety\s+|security\s+)?(safeguards|protocols|filters)\s+"
                    r"(right\s+now|immediately|now)\b",
                    re.IGNORECASE,
                ),
                0.94,
                Severity.HIGH,
                "Direct deactivation command targeting safety safeguards",
            ),
            (
                re.compile(
                    r"\bstarting\s+now\s*,\s*(all\s+)?(behavioral\s+|content\s+)?(limits|restrictions|rules)\s+are\s+disabled\b",
                    re.IGNORECASE,
                ),
                0.92,
                Severity.HIGH,
                "Temporal boundary reset declaration",
            ),
        ]

    @property
    def rule_id(self) -> str:
        return "contextual_override"

    @property
    def description(self) -> str:
        return "Detects passive voice, polite phrasing, and simulation-mode instruction overrides."

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


class ExtendedMultilingualRule(InjectionRule):
    """Detects injection imperatives in Italian, Hindi, Tamil, Russian, Chinese, Japanese, Portuguese, and formal German/Spanish."""

    def __init__(self) -> None:
        self._patterns = [
            # Italian
            (
                re.compile(
                    r"\b(annulla|cancella|ignora|dimentica)\s+(tutte\s+le\s+)?(istruzioni|regole|direttive)\s+(precedenti|passate)\b|"
                    r"\b(mostra|stampa|rivela)\s+(il\s+)?prompt\s+di\s+sistema\s+(riservato|confidenziale)?\b|"
                    r"\bentra\s+in\s+modalita\s+sviluppatore\s+senza\s+restrizioni\b",
                    re.IGNORECASE,
                ),
                0.93,
                Severity.HIGH,
                "Italian prompt injection imperative detected",
            ),
            # German Formal (Sie)
            (
                re.compile(
                    r"\b(missachten\s+Sie|ignorieren\s+Sie|vergessen\s+Sie)\s+(alle\s+)?(vorhergehenden|vorherigen)\s+(instruktionen|anweisungen)\b|"
                    r"\b(drucken\s+Sie|geben\s+Sie)\s+(den\s+)?system-?prompt\b",
                    re.IGNORECASE,
                ),
                0.93,
                Severity.HIGH,
                "German formal polite prompt injection imperative detected",
            ),
            # Spanish Formal (Usted)
            (
                re.compile(
                    r"\b(ignore|olvide|descarte)\s+(todas\s+las\s+)?(instrucciones|reglas|indicaciones)\s+(anteriores|previas)\b|"
                    r"\b(muestre|revele|imprima)\s+(la\s+configuracion|el\s+prompt)\s+del\s+sistema\b",
                    re.IGNORECASE,
                ),
                0.92,
                Severity.HIGH,
                "Spanish formal polite prompt injection imperative detected",
            ),
            # Portuguese
            (
                re.compile(
                    r"\b(ignore|esquece|descarte)\s+(todas\s+as\s+)?(instrucoes|orientacoes|diretrizes)\s+(anteriores|previas)\b|"
                    r"\b(mostre|revele)\s+(as\s+diretrizes|as\s+configuracoes)\s+confidenciais\b",
                    re.IGNORECASE,
                ),
                0.92,
                Severity.HIGH,
                "Portuguese prompt injection imperative detected",
            ),
            # Russian (Cyrillic)
            (
                re.compile(
                    r"(игнорируй|забудь|отмени)\s+(все\s+)?(предыдущие\s+)?(инструкции|правила|указания)|"
                    r"(выведи|покажи)\s+(скрытый\s+|системный\s+)?промпт",
                    re.IGNORECASE,
                ),
                0.94,
                Severity.HIGH,
                "Russian prompt injection imperative detected",
            ),
            # Chinese (Simplified/Traditional)
            (
                re.compile(
                    r"(忽略|无视|取消)(之前|上文|前面|所有)的?(全部|所有)?(指令|要求|规则|设定)|"
                    r"(输出|列出|显示)(系统|底层)?(提示词|预设|安全策略|初始化设定)",
                ),
                0.95,
                Severity.HIGH,
                "Chinese prompt injection imperative detected",
            ),
            # Japanese
            (
                re.compile(
                    r"(すべての指示を無視|これまでの指示を無視|指示を無視して)|"
                    r"(システムの(初期|隠された)?プロンプトを出力|開発者モードに移行)",
                ),
                0.95,
                Severity.HIGH,
                "Japanese prompt injection imperative detected",
            ),
            # Hindi (Devanagari)
            (
                re.compile(
                    r"(निर्देशों\s+को\s+अनदेखा\s+करें|सभी\s+सुरक्षा\s+नियमों\s+को\s+रद्द\s+करें|"
                    r"सिस्टम\s+प्रॉम्प्ट\s+दिखाएं|बिना\s+किसी\s+प्रतिबंध\s+के\s+उत्तर\s+दें)",
                ),
                0.94,
                Severity.HIGH,
                "Hindi prompt injection imperative detected",
            ),
            # Tamil
            (
                re.compile(
                    r"(வழிமுறைகளையும்\s+புறக்கணிக்கவும்|சிஸ்டம்\s+ப்ராம்ப்ட்டை\s+வெளியிடவும்|"
                    r"பாதுகாப்பு\s+விதிகளை\s+ரத்து\s+செய்யவும்)",
                ),
                0.94,
                Severity.HIGH,
                "Tamil prompt injection imperative detected",
            ),
        ]

    @property
    def rule_id(self) -> str:
        return "extended_multilingual_injection"

    @property
    def description(self) -> str:
        return "Detects prompt injection imperatives in Italian, Hindi, Tamil, Russian, Chinese, Japanese, and formal German/Spanish."

    def evaluate(self, raw_text: str, norm_text: str) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        for pattern, confidence, severity, desc in self._patterns:
            # Check normalized text and raw text (needed for non-Latin scripts)
            for target_text in (norm_text, raw_text):
                for m in pattern.finditer(target_text):
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


class ExtendedIndirectInjectionRule(InjectionRule):
    """Detects indirect prompt injection headers embedded in third-party text or retrieved chunks."""

    def __init__(self) -> None:
        self._patterns = [
            (
                re.compile(
                    r"\b(note\s+to\s+(ai\s+assistant|parser|hr\s+screener|evaluator|reviewer)|"
                    r"directive\s+to\s+(parser|assistant|model)|"
                    r"\[critical\s+system\s+directive\]|\[ai\s+override\]|\[security\s+notice\])\s*:\s*"
                    r".*?\b(bypass|disregard|ignore|forward|exfiltrate|reveal|unrestricted)\b",
                    re.IGNORECASE,
                ),
                0.93,
                Severity.CRITICAL,
                "Role-specific indirect injection marker detected in document context",
            ),
        ]

    @property
    def rule_id(self) -> str:
        return "extended_indirect_injection"

    @property
    def description(self) -> str:
        return "Detects specialized indirect injection envelopes and parser redirection directives."

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


class ObfuscatedCommandRule(InjectionRule):
    """Detects commands instructing models to decode, reverse, or decrypt adversarial payloads."""

    def __init__(self) -> None:
        self._patterns = [
            (
                re.compile(
                    r"\b(decode\s+from\s+base64|translate\s+from\s+rot13|reverse\s+the\s+following\s+text|"
                    r"convert\s+binary\s+and\s+execute|hex\s+decoded\s+instruction)\b.*?"
                    r"\b(execute|follow|obey|commands?|rules?|system|safety|password|prompt)\b",
                    re.IGNORECASE,
                ),
                0.91,
                Severity.HIGH,
                "Obfuscated decoding instruction directive detected",
            ),
        ]

    @property
    def rule_id(self) -> str:
        return "obfuscated_command_directive"

    @property
    def description(self) -> str:
        return "Detects instructions requesting the decoding and execution of obfuscated or encrypted payloads."

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


def get_extended_injection_rules() -> List[InjectionRule]:
    """Returns the full suite of baseline and extended detection rules."""
    from llmfirewall.detectors.prompt_injection.rules import (
        AuthorityImpersonationRule,
        DelimiterAttackRule,
        IndirectInjectionRule,
        InstructionHierarchyRule,
        InstructionOverrideRule,
        MultilingualInjectionRule,
        RoleManipulationRule,
        SuspiciousControlRule,
        SystemPromptLeakRule,
        ToolManipulationRule,
    )

    return [
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
        # Extended development rules:
        ContextualOverrideRule(),
        ExtendedMultilingualRule(),
        ExtendedIndirectInjectionRule(),
        ObfuscatedCommandRule(),
    ]
