"""Phase 59 — Adaptive Threat Detection with Contextual and Historical Signals.

Provides optional adaptive threat calibration factoring in multi-turn session history,
caller reputation/context, token entropy anomalies, and repetition obfuscation.
Safe by default: fully disabled unless explicitly enabled, preserving 100% deterministic
heuristics and pattern-matching behavior of baseline detectors.
"""

from collections import deque
import math
import time
from typing import Any, Deque, Dict, List, Optional
import uuid

from pydantic import BaseModel, ConfigDict, Field

from llmfirewall.core.models import Finding, Severity, ThreatType


class AdaptiveThreatConfig(BaseModel):
    """Configuration for optional adaptive threat detection."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = Field(default=False, description="Whether adaptive threat signals are evaluated")
    sensitivity_boost_per_finding: float = Field(default=0.05, ge=0.0, le=0.2, description="Confidence boost per past session violation")
    max_sensitivity_boost: float = Field(default=0.20, ge=0.0, le=0.5, description="Maximum adaptive confidence increase")
    entropy_anomaly_threshold: float = Field(default=4.85, ge=3.0, le=8.0, description="Shannon entropy threshold indicating obfuscation")
    repetition_anomaly_threshold: float = Field(default=0.55, ge=0.2, le=0.9, description="Repetition ratio threshold indicating token flooding")
    track_historical_signals: bool = Field(default=True, description="Whether to track historical turn violations")
    decay_half_life_seconds: float = Field(default=300.0, ge=10.0, description="Half-life for decaying historical violation counts")
    max_tracked_sessions: int = Field(default=1000, ge=10, le=100000, description="Maximum distinct sessions tracked in memory")


class ContextualSignal(BaseModel):
    """An individual contextual or historical signal evaluated during detection."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    signal_id: str = Field(default_factory=lambda: f"sig-{uuid.uuid4().hex[:8]}", description="Signal identifier")
    signal_type: str = Field(..., description="Classification of signal")
    score: float = Field(..., ge=0.0, le=1.0, description="Normalized signal strength")
    weight: float = Field(default=1.0, ge=0.0, le=2.0, description="Relative weighting of this signal")
    description: str = Field(..., description="Explanation of why this signal was raised")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Safe metadata")


class HistoricalSignalTracker:
    """Thread-safe bounded in-memory tracker of session security history."""

    def __init__(self, max_sessions: int = 1000, half_life_seconds: float = 300.0) -> None:
        self.max_sessions = max_sessions
        self.half_life_seconds = half_life_seconds
        # session_id -> deque of event timestamps
        self._history: Dict[str, Deque[float]] = {}

    def record_violation(self, session_id: str, timestamp: Optional[float] = None) -> None:
        """Record a security finding/violation for a session."""
        if not session_id:
            return
        ts = timestamp or time.time()
        if session_id not in self._history:
            if len(self._history) >= self.max_sessions:
                # Evict oldest session
                oldest_sess = next(iter(self._history))
                del self._history[oldest_sess]
            self._history[session_id] = deque(maxlen=50)
        self._history[session_id].append(ts)

    def get_decayed_violation_count(self, session_id: str, now: Optional[float] = None) -> float:
        """Calculate time-decayed violation count for a session."""
        if not session_id or session_id not in self._history:
            return 0.0
        current_time = now or time.time()
        events = self._history[session_id]
        decayed_sum = 0.0
        for ts in events:
            age = max(0.0, current_time - ts)
            decay_factor = math.pow(0.5, age / self.half_life_seconds)
            decayed_sum += decay_factor
        return round(decayed_sum, 3)

    def clear(self) -> None:
        """Clear all tracked history."""
        self._history.clear()


def compute_shannon_entropy(text: str) -> float:
    """Compute Shannon entropy of a string (bits per symbol)."""
    if not text:
        return 0.0
    length = len(text)
    freq: Dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def compute_token_repetition_ratio(text: str) -> float:
    """Calculate ratio of repeated tokens to unique tokens."""
    tokens = text.lower().split()
    if not tokens:
        return 0.0
    unique = len(set(tokens))
    total = len(tokens)
    if total <= 1:
        return 0.0
    return round((total - unique) / total, 4)


class AdaptiveThreatEngine:
    """Evaluates contextual and historical threat signals and calibrates finding confidence.
    
    Zero heavyweight models: relies exclusively on fast, deterministic mathematical
    and statistical heuristics (Shannon entropy, token repetition, exponential decay).
    """

    def __init__(
        self,
        config: Optional[AdaptiveThreatConfig] = None,
        tracker: Optional[HistoricalSignalTracker] = None,
    ) -> None:
        self.config = config or AdaptiveThreatConfig()
        self.tracker = tracker or HistoricalSignalTracker(
            max_sessions=self.config.max_tracked_sessions,
            half_life_seconds=self.config.decay_half_life_seconds,
        )

    def evaluate_signals(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ContextualSignal]:
        """Extract contextual and historical signals if enabled."""
        if not self.config.enabled:
            return []

        ctx = context or {}
        signals: List[ContextualSignal] = []

        # 1. Historical Session Signal
        session_id = ctx.get("session_id")
        if self.config.track_historical_signals and session_id:
            decayed_violations = self.tracker.get_decayed_violation_count(str(session_id))
            if decayed_violations > 0.5:
                strength = min(1.0, decayed_violations / 4.0)
                signals.append(
                    ContextualSignal(
                        signal_type="SESSION_PRIOR_VIOLATIONS",
                        score=round(strength, 3),
                        weight=1.2,
                        description=f"Session '{session_id}' has {decayed_violations:.1f} prior decayed security violations.",
                        metadata={"decayed_violations": decayed_violations},
                    )
                )

        # 2. Entropy Anomaly (High entropy base64/hex/obfuscation)
        if len(text) > 40:
            entropy = compute_shannon_entropy(text)
            if entropy >= self.config.entropy_anomaly_threshold:
                score = min(1.0, (entropy - self.config.entropy_anomaly_threshold) / 2.0 + 0.5)
                signals.append(
                    ContextualSignal(
                        signal_type="HIGH_ENTROPY_OBFUSCATION",
                        score=round(score, 3),
                        weight=1.0,
                        description=f"Unusually high Shannon entropy ({entropy:.2f} bits/char) indicates obfuscation or encoding.",
                        metadata={"entropy": entropy},
                    )
                )

        # 3. Repetition Flooding
        if len(text) > 80:
            rep_ratio = compute_token_repetition_ratio(text)
            if rep_ratio >= self.config.repetition_anomaly_threshold:
                signals.append(
                    ContextualSignal(
                        signal_type="TOKEN_REPETITION_FLOODING",
                        score=round(rep_ratio, 3),
                        weight=0.9,
                        description=f"High token repetition ratio ({rep_ratio:.2%}) indicates possible context stuffing or denial-of-service.",
                        metadata={"repetition_ratio": rep_ratio},
                    )
                )

        # 4. Untrusted Caller Context
        caller_trust = ctx.get("trust_level") or ctx.get("caller_trust")
        if caller_trust and str(caller_trust).lower() in ("untrusted", "external", "anonymous"):
            signals.append(
                ContextualSignal(
                    signal_type="UNTRUSTED_CALLER_CONTEXT",
                    score=0.8,
                    weight=1.0,
                    description=f"Caller context specifies untrusted tier '{caller_trust}'.",
                )
            )

        return signals

    def calibrate_finding(
        self,
        finding: Finding,
        signals: List[ContextualSignal],
    ) -> Finding:
        """Calibrate finding confidence using evaluated adaptive signals."""
        if not self.config.enabled or not signals:
            return finding

        total_boost = 0.0
        for sig in signals:
            if sig.signal_type == "SESSION_PRIOR_VIOLATIONS":
                decayed = sig.metadata.get("decayed_violations", 1.0)
                boost = min(self.config.max_sensitivity_boost, decayed * self.config.sensitivity_boost_per_finding)
                total_boost += boost
            elif sig.signal_type == "HIGH_ENTROPY_OBFUSCATION":
                total_boost += 0.05
            elif sig.signal_type == "UNTRUSTED_CALLER_CONTEXT":
                total_boost += 0.05

        capped_boost = min(self.config.max_sensitivity_boost, total_boost)
        if capped_boost <= 0.0:
            return finding

        new_conf = min(1.0, round(finding.confidence + capped_boost, 4))
        # Update metadata to reflect adaptive calibration
        meta = dict(finding.metadata)
        meta["adaptive_calibrated"] = True
        meta["adaptive_confidence_boost"] = round(capped_boost, 4)
        meta["adaptive_signal_count"] = len(signals)

        return finding.model_copy(update={
            "confidence": new_conf,
            "metadata": meta,
        })
