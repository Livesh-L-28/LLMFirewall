"""Phase 60 — AI Threat Intelligence models and schemas.

Structured, versioned intelligence for AI-specific threats with cryptographic
provenance, strict schema validation, trust tiers, and safe import/export.
"""

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
import time
from typing import Any, Dict, List, Optional, Set
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator

from llmfirewall.core.models import Severity, ThreatType


class ThreatIntelTrustLevel(str, Enum):
    """Trust hierarchy for threat intelligence feeds and indicators.
    
    Invariants:
    - Never automatically trust externally supplied feeds.
    - External feeds default to UNTRUSTED or STAGED until explicitly verified.
    """
    UNTRUSTED = "UNTRUSTED"
    STAGED = "STAGED"
    VERIFIED = "VERIFIED"
    TRUSTED = "TRUSTED"


class ThreatPatternType(str, Enum):
    """Type of threat detection pattern inside an indicator."""
    EXACT_KEYWORD = "EXACT_KEYWORD"
    REGEX = "REGEX"
    SUBSTRING_LIST = "SUBSTRING_LIST"
    BEHAVIORAL_HEURISTIC = "BEHAVIORAL_HEURISTIC"


class AIThreatIndicator(BaseModel):
    """Structured atomic indicator of an AI-specific threat."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    indicator_id: str = Field(default_factory=lambda: f"ind-{uuid.uuid4().hex[:10]}", description="Unique indicator ID")
    name: str = Field(..., max_length=200, description="Readable indicator title")
    description: str = Field(..., max_length=1000, description="Detailed explanation of the threat indicator")
    threat_type: ThreatType = Field(..., description="Target threat category")
    pattern_type: ThreatPatternType = Field(default=ThreatPatternType.EXACT_KEYWORD, description="Pattern evaluation type")
    pattern: str = Field(..., max_length=2000, description="Pattern string (keyword, regex, or comma-separated list)")
    severity: Severity = Field(default=Severity.HIGH, description="Default severity if matched")
    confidence: float = Field(default=0.85, ge=0.0, le=1.0, description="Calibrated confidence")
    trust_level: ThreatIntelTrustLevel = Field(default=ThreatIntelTrustLevel.UNTRUSTED, description="Trust tier of indicator")
    mitre_atlas_id: Optional[str] = Field(default=None, description="Correlating MITRE ATLAS technique ID (e.g. AML.T0054)")
    owasp_category: Optional[str] = Field(default=None, description="OWASP Top 10 for LLM identifier (e.g. LLM01:2025)")
    tags: List[str] = Field(default_factory=list, description="Categorization tags")
    created_at: float = Field(default_factory=time.time, description="Epoch timestamp of creation")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Safe auxiliary metadata")

    @field_validator("name", "description", "pattern")
    @classmethod
    def validate_non_empty(cls, v: str) -> str:
        s = v.strip()
        if not s:
            raise ValueError("Field cannot be empty or whitespace only")
        return s


class ThreatIntelFeed(BaseModel):
    """A versioned package of structured AI threat intelligence."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    feed_id: str = Field(..., max_length=100, description="Unique feed identifier (e.g. org.llmfirewall.threat-feed-core)")
    version: str = Field(..., max_length=50, description="Semantic version string of the feed")
    publisher: str = Field(..., max_length=200, description="Publisher or signing entity")
    description: str = Field(default="", max_length=1000, description="Feed summary description")
    published_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="ISO UTC timestamp")
    trust_level: ThreatIntelTrustLevel = Field(default=ThreatIntelTrustLevel.UNTRUSTED, description="Feed trust level")
    checksum: Optional[str] = Field(default=None, description="SHA-256 digest of indicators payload")
    signature: Optional[str] = Field(default=None, description="Cryptographic signature or HMAC digest")
    indicators: List[AIThreatIndicator] = Field(default_factory=list, description="List of packaged indicators")

    def compute_indicators_hash(self) -> str:
        """Calculate canonical deterministic SHA-256 digest over contained indicators."""
        canonical_entries = []
        for ind in sorted(self.indicators, key=lambda x: x.indicator_id):
            canonical_entries.append({
                "id": ind.indicator_id,
                "name": ind.name,
                "pattern_type": ind.pattern_type.value,
                "pattern": ind.pattern,
                "threat_type": ind.threat_type.value,
            })
        encoded = json.dumps(canonical_entries, sort_keys=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


class IndicatorMatch(BaseModel):
    """Result of an indicator matching against inspected text."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    indicator_id: str
    indicator_name: str
    threat_type: ThreatType
    severity: Severity
    confidence: float
    matched_snippet: str
    mitre_atlas_id: Optional[str] = None
    owasp_category: Optional[str] = None
    trust_level: ThreatIntelTrustLevel
