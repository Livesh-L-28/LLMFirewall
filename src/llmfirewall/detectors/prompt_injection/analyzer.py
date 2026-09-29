"""Heuristic analysis for prompt injection findings."""

from typing import List
from llmfirewall.core.models import Finding, Severity, ThreatType
from llmfirewall.detectors.prompt_injection.rules import RuleMatch


class InjectionHeuristicAnalyzer:
    """Combines and contextualizes raw rule matches into structured findings.
    
    Responsibilities:
    1. Deduplicate overlapping matches across modular rules.
    2. Adjust confidence when multiple corroborating injection indicators co-occur.
    3. Promote severity when multiple distinct attack techniques are combined.
    4. Emit final Finding objects adhering strictly to domain contracts.
    """

    def analyze(self, raw_text: str, matches: List[RuleMatch]) -> List[Finding]:
        if not matches:
            return []

        # Sort matches by start position, then by confidence descending
        sorted_matches = sorted(
            matches,
            key=lambda m: (m.start_pos if m.start_pos is not None else 0, -m.confidence),
        )

        # 1. Non-overlapping selection
        deduped: List[RuleMatch] = []
        for match in sorted_matches:
            if match.start_pos is None or match.end_pos is None:
                deduped.append(match)
                continue

            overlaps = False
            for existing in deduped:
                if existing.start_pos is None or existing.end_pos is None:
                    continue
                # Overlap check
                if max(match.start_pos, existing.start_pos) < min(match.end_pos, existing.end_pos):
                    overlaps = True
                    break
            if not overlaps:
                deduped.append(match)

        # 2. Corroborating signals heuristic:
        # If multiple distinct rule IDs triggered, boost confidence and assess composite severity
        distinct_rules = {m.rule_id for m in deduped}
        multi_rule_cooccurrence = len(distinct_rules) > 1

        findings: List[Finding] = []
        for match in deduped:
            final_conf = match.confidence
            final_sev = match.severity

            if multi_rule_cooccurrence:
                # Compound injection pattern: bump confidence slightly, capped at 0.99
                final_conf = min(0.99, final_conf + 0.04)
                if match.severity == Severity.MEDIUM:
                    final_sev = Severity.HIGH

            findings.append(
                Finding(
                    detector_name="prompt_injection_detector",
                    threat_type=ThreatType.PROMPT_INJECTION,
                    description=match.description,
                    severity=final_sev,
                    confidence=round(final_conf, 3),
                    start_pos=match.start_pos,
                    end_pos=match.end_pos,
                    matched_text=match.matched_text,
                    metadata={
                        "rule_id": match.rule_id,
                        "compound_attack": multi_rule_cooccurrence,
                        "triggered_rule_count": len(distinct_rules),
                    },
                )
            )

        return findings
