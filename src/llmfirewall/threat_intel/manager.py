"""Phase 60 — Threat Intelligence Manager.

Manages versioned AI threat feeds, enforces zero-automatic-trust for external indicators,
handles safe JSON/YAML serialization, and provides regex-safe pattern matching.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional, Set
import yaml

from llmfirewall.cache.regex import compile_regex
from llmfirewall.core.models import Finding, Severity, ThreatType
from llmfirewall.threat_intel.models import (
    AIThreatIndicator,
    IndicatorMatch,
    ThreatIntelFeed,
    ThreatIntelTrustLevel,
    ThreatPatternType,
)
from llmfirewall.threat_intel.validator import ThreatFeedValidator

logger = logging.getLogger(__name__)


class ThreatIntelManager:
    """Manages AI threat intelligence feeds, validation, trust gates, and text matching."""

    def __init__(self, allow_unverified_evaluation: bool = False) -> None:
        self.allow_unverified_evaluation = allow_unverified_evaluation
        self._feeds: Dict[str, ThreatIntelFeed] = {}
        self._indicators: Dict[str, AIThreatIndicator] = {}
        self._validator = ThreatFeedValidator()

    @property
    def feeds(self) -> List[ThreatIntelFeed]:
        return list(self._feeds.values())

    @property
    def indicators(self) -> List[AIThreatIndicator]:
        return list(self._indicators.values())

    def register_feed(
        self,
        feed: ThreatIntelFeed,
        expected_checksum: Optional[str] = None,
        auto_trust: bool = False,
    ) -> bool:
        """Register a threat feed with integrity verification and safety validation.
        
        Zero Automatic Trust:
        Feeds are imported as UNTRUSTED or STAGED by default.
        """
        valid, msg = self._validator.validate_feed_integrity(feed, expected_checksum=expected_checksum)
        if not valid:
            logger.warning(f"Rejecting threat feed '{feed.feed_id}': {msg}")
            raise ValueError(f"Threat feed integrity failure: {msg}")

        # Validate each indicator for ReDoS and syntax
        sanitized_indicators: List[AIThreatIndicator] = []
        for ind in feed.indicators:
            errors = self._validator.validate_indicator_safety(ind)
            if errors:
                logger.warning(f"Skipping dangerous indicator '{ind.indicator_id}': {errors}")
                continue

            target_trust = ThreatIntelTrustLevel.VERIFIED if auto_trust else ind.trust_level
            sanitized_ind = ind.model_copy(update={"trust_level": target_trust})
            sanitized_indicators.append(sanitized_ind)
            self._indicators[sanitized_ind.indicator_id] = sanitized_ind

        registered_feed = feed.model_copy(update={
            "indicators": sanitized_indicators,
            "trust_level": ThreatIntelTrustLevel.VERIFIED if auto_trust else feed.trust_level,
        })
        self._feeds[feed.feed_id] = registered_feed
        return True

    def approve_indicator(self, indicator_id: str) -> bool:
        """Explicitly promote an indicator from UNTRUSTED/STAGED to VERIFIED."""
        if indicator_id not in self._indicators:
            return False
        curr = self._indicators[indicator_id]
        self._indicators[indicator_id] = curr.model_copy(update={
            "trust_level": ThreatIntelTrustLevel.VERIFIED,
        })
        return True

    def match_text(
        self,
        text: str,
        min_trust_level: ThreatIntelTrustLevel = ThreatIntelTrustLevel.VERIFIED,
    ) -> List[IndicatorMatch]:
        """Inspect text against indicators meeting the minimum trust threshold."""
        if not text:
            return []

        trust_order = {
            ThreatIntelTrustLevel.UNTRUSTED: 0,
            ThreatIntelTrustLevel.STAGED: 1,
            ThreatIntelTrustLevel.VERIFIED: 2,
            ThreatIntelTrustLevel.TRUSTED: 3,
        }
        min_rank = trust_order.get(min_trust_level, 2)

        matches: List[IndicatorMatch] = []
        lower_text = text.lower()

        for ind in self._indicators.values():
            ind_rank = trust_order.get(ind.trust_level, 0)
            if ind_rank < min_rank and not self.allow_unverified_evaluation:
                continue

            snippet: Optional[str] = None

            if ind.pattern_type == ThreatPatternType.EXACT_KEYWORD:
                kw = ind.pattern.lower()
                if kw in lower_text:
                    start_idx = lower_text.find(kw)
                    snippet = text[start_idx : start_idx + len(kw)]
            elif ind.pattern_type == ThreatPatternType.SUBSTRING_LIST:
                keywords = [k.strip().lower() for k in ind.pattern.split(",") if k.strip()]
                for kw in keywords:
                    if kw in lower_text:
                        start_idx = lower_text.find(kw)
                        snippet = text[start_idx : start_idx + len(kw)]
                        break
            elif ind.pattern_type == ThreatPatternType.REGEX:
                try:
                    compiled = compile_regex(ind.pattern, re.IGNORECASE)
                    m = compiled.search(text)
                    if m:
                        snippet = m.group(0)
                except Exception:
                    continue

            if snippet is not None:
                matches.append(
                    IndicatorMatch(
                        indicator_id=ind.indicator_id,
                        indicator_name=ind.name,
                        threat_type=ind.threat_type,
                        severity=ind.severity,
                        confidence=ind.confidence,
                        matched_snippet=snippet,
                        mitre_atlas_id=ind.mitre_atlas_id,
                        owasp_category=ind.owasp_category,
                        trust_level=ind.trust_level,
                    )
                )

        return matches

    def to_findings(self, matches: List[IndicatorMatch]) -> List[Finding]:
        """Convert indicator matches to standardized Finding models."""
        findings: List[Finding] = []
        for m in matches:
            findings.append(
                Finding(
                    detector_name="ai_threat_intel",
                    threat_type=m.threat_type,
                    severity=m.severity,
                    confidence=m.confidence,
                    description=f"AI Threat Intelligence match '{m.indicator_name}' ({m.indicator_id})",
                    matched_text=m.matched_snippet,
                    metadata={
                        "indicator_id": m.indicator_id,
                        "mitre_atlas_id": m.mitre_atlas_id,
                        "owasp_category": m.owasp_category,
                        "trust_level": m.trust_level.value,
                    },
                )
            )
        return findings

    def export_feed_json(self, feed_id: str) -> str:
        """Export a registered feed to formatted JSON."""
        if feed_id not in self._feeds:
            raise KeyError(f"Feed '{feed_id}' not found")
        feed = self._feeds[feed_id]
        feed_dict = feed.model_dump()
        feed_dict["checksum"] = feed.compute_indicators_hash()
        return json.dumps(feed_dict, indent=2)

    def import_feed_json(
        self,
        json_str: str,
        expected_checksum: Optional[str] = None,
        auto_trust: bool = False,
    ) -> ThreatIntelFeed:
        """Safely parse and register a threat feed from JSON."""
        data = json.loads(json_str)
        feed = ThreatIntelFeed.model_validate(data)
        self.register_feed(feed, expected_checksum=expected_checksum, auto_trust=auto_trust)
        return feed

    def import_feed_yaml(
        self,
        yaml_str: str,
        expected_checksum: Optional[str] = None,
        auto_trust: bool = False,
    ) -> ThreatIntelFeed:
        """Safely parse and register a threat feed from YAML using safe_load."""
        data = yaml.safe_load(yaml_str)
        feed = ThreatIntelFeed.model_validate(data)
        self.register_feed(feed, expected_checksum=expected_checksum, auto_trust=auto_trust)
        return feed
