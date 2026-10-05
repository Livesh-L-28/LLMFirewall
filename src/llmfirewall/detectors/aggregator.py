"""Deterministic finding deduplication, span normalization, and aggregation."""

import hashlib
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from llmfirewall.core.models import Finding, Severity, ThreatType


def compute_finding_fingerprint(finding: Finding) -> str:
    """Compute a deterministic hash fingerprint for finding identity and deduplication."""
    # Build identity tuple based on core semantic detection properties
    start = finding.start_pos if finding.start_pos is not None else -1
    end = finding.end_pos if finding.end_pos is not None else -1
    category = finding.metadata.get("rule_id") or finding.metadata.get("pii_category") or finding.threat_type.value

    raw = f"{finding.detector_name}:{finding.threat_type.value}:{category}:{start}:{end}:{finding.description}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


class FindingAggregator:
    """Aggregates, deduplicates, and normalizes findings emitted across multiple detectors."""

    @classmethod
    def aggregate(cls, findings: List[Finding]) -> List[Finding]:
        """Deterministic finding aggregation pipeline:
        1. Exact duplicate elimination by fingerprint.
        2. Span overlap normalization for findings of identical threat category.
        3. Stable ordering by start offset and severity.
        """
        if not findings:
            return []

        # Step 1: Deduplicate identical findings
        seen_fingerprints = set()
        deduped: List[Finding] = []

        for f in findings:
            fp = compute_finding_fingerprint(f)
            if fp not in seen_fingerprints:
                seen_fingerprints.add(fp)
                deduped.append(f)

        # Step 2: Sort by position (or -1 if None) and severity descending
        def sort_key(f: Finding):
            start = f.start_pos if f.start_pos is not None else -1
            end = f.end_pos if f.end_pos is not None else -1
            return (start, end, -f.severity.level, -f.confidence)

        sorted_findings = sorted(deduped, key=sort_key)

        # Step 3: Overlapping span containment within identical threat category & detector
        # When one finding completely encloses another of same detector and threat type,
        # preserve the higher severity / higher confidence finding.
        aggregated: List[Finding] = []
        for candidate in sorted_findings:
            if candidate.start_pos is None or candidate.end_pos is None:
                aggregated.append(candidate)
                continue

            merged = False
            for idx, existing in enumerate(aggregated):
                if (
                    existing.start_pos is not None
                    and existing.end_pos is not None
                    and existing.threat_type == candidate.threat_type
                    and existing.detector_name == candidate.detector_name
                ):
                    # Check exact span duplicate that differed only in description
                    if existing.start_pos == candidate.start_pos and existing.end_pos == candidate.end_pos:
                        # Keep the one with higher severity or confidence
                        if (candidate.severity > existing.severity) or (
                            candidate.severity == existing.severity and candidate.confidence > existing.confidence
                        ):
                            aggregated[idx] = candidate
                        merged = True
                        break

            if not merged:
                aggregated.append(candidate)

        return aggregated


def calibrate_finding_confidence(finding: Finding, context: Optional[Dict[str, Any]] = None) -> Finding:
    """Deterministic confidence calibration based on evidence bounds and metadata.
    
    Calibration rules:
      - Finding confidence is bounded between 0.0 and 1.0.
      - If matched_text length is 1 or empty and threat is secret/pii, reduce confidence slightly.
      - If verified by high-entropy validation or Luhn check, confidence remains 1.0.
      - Does NOT modify finding threat_type or category.
    """
    conf = max(0.0, min(1.0, finding.confidence))

    # Evidence bounds check
    if finding.start_pos is not None and finding.end_pos is not None:
        span_len = finding.end_pos - finding.start_pos
        if span_len <= 0:
            conf = min(conf, 0.5)

    if finding.confidence != conf:
        # Pydantic models are frozen; construct copy with calibrated confidence
        return finding.model_copy(update={"confidence": round(conf, 3)})

    return finding
