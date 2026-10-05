"""Multi-Turn Session Risk Tracking with Exponential Decay for LLMFirewall v1.1.0 (Phase 50).

Detects slow-drip probing attacks, accumulates multi-turn threat signals,
and applies temporal decay to historical risk scores.
"""

import math
import threading
import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from llmfirewall.core.models import Finding, Severity


class SessionTurnRecord(BaseModel):
    """Record of an individual turn in a multi-turn session."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    turn_number: int = Field(..., ge=1)
    timestamp: float = Field(default_factory=time.time)
    risk_score: float = Field(..., ge=0.0, le=1.0)
    findings_count: int = Field(default=0)
    max_severity: Severity = Field(default=Severity.INFO)


class SessionRiskSummary(BaseModel):
    """Aggregate multi-turn risk status for a user session."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    session_id: str = Field(...)
    total_turns: int = Field(default=0)
    raw_cumulative_score: float = Field(default=0.0, ge=0.0)
    decayed_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Temporally decayed composite session risk")
    peak_turn_score: float = Field(default=0.0, ge=0.0, le=1.0)
    is_probe_attack: bool = Field(default=False, description="True if repeated low/medium risk indicates low-and-slow probing")
    alert_level: Severity = Field(default=Severity.INFO)
    recommendation: str = Field(default="Normal session traffic.")


class SessionRiskTracker:
    """Thread-safe multi-turn session risk tracker with exponential temporal decay."""

    def __init__(
        self,
        decay_half_life_seconds: float = 300.0,  # 5 minutes half-life
        probe_turn_threshold: int = 3,
        probe_score_threshold: float = 0.65,
    ) -> None:
        self.decay_half_life = max(1.0, decay_half_life_seconds)
        self.decay_lambda = math.log(2.0) / self.decay_half_life
        self.probe_turn_threshold = probe_turn_threshold
        self.probe_score_threshold = probe_score_threshold
        self._lock = threading.RLock()
        self._sessions: Dict[str, List[SessionTurnRecord]] = {}

    def record_turn(
        self,
        session_id: str,
        findings: List[Finding],
        risk_score: float,
        timestamp: Optional[float] = None,
    ) -> SessionRiskSummary:
        """Record an interaction turn and compute updated session risk posture."""
        t = timestamp if timestamp is not None else time.time()
        max_sev = max((f.severity for f in findings), default=Severity.INFO)
        score = min(1.0, max(0.0, risk_score))

        with self._lock:
            history = self._sessions.setdefault(session_id, [])
            turn_num = len(history) + 1
            record = SessionTurnRecord(
                turn_number=turn_num,
                timestamp=t,
                risk_score=score,
                findings_count=len(findings),
                max_severity=max_sev,
            )
            history.append(record)
            return self._compute_summary(session_id, history, current_time=t)

    def get_session_risk(
        self,
        session_id: str,
        current_time: Optional[float] = None,
    ) -> SessionRiskSummary:
        """Evaluate session risk with temporal decay as of current_time."""
        t = current_time if current_time is not None else time.time()
        with self._lock:
            history = self._sessions.get(session_id, [])
            if not history:
                return SessionRiskSummary(session_id=session_id)
            return self._compute_summary(session_id, history, current_time=t)

    def _compute_summary(
        self,
        session_id: str,
        history: List[SessionTurnRecord],
        current_time: float,
    ) -> SessionRiskSummary:
        total_turns = len(history)
        peak_score = max((r.risk_score for r in history), default=0.0)
        raw_sum = sum(r.risk_score for r in history)

        # Apply exponential decay based on delta from turn timestamp to current_time
        # Decayed contribution = score * e^(-lambda * dt)
        decayed_sum = 0.0
        for r in history:
            dt = max(0.0, current_time - r.timestamp)
            weight = math.exp(-self.decay_lambda * dt)
            decayed_sum += r.risk_score * weight

        # Normalized bounded decayed session score [0.0, 1.0] using diminishing returns
        # 1 - e^(-decayed_sum)
        normalized_decayed = min(1.0, max(0.0, 1.0 - math.exp(-decayed_sum)))

        # Detect low-and-slow probing: >= 3 turns with non-trivial score, but peak < 0.70 individually
        suspicious_turns = [r for r in history if r.risk_score >= 0.25]
        is_probe = len(suspicious_turns) >= self.probe_turn_threshold and normalized_decayed >= self.probe_score_threshold

        if normalized_decayed >= 0.85 or is_probe:
            alert = Severity.CRITICAL
            recommendation = "High risk session threshold breached. Block or throttle session immediately."
        elif normalized_decayed >= 0.65:
            alert = Severity.HIGH
            recommendation = "Session accumulating significant risk. Require step-up verification."
        elif normalized_decayed >= 0.35:
            alert = Severity.MEDIUM
            recommendation = "Elevated risk signals across turns; monitor session."
        else:
            alert = Severity.LOW
            recommendation = "Normal session traffic."

        return SessionRiskSummary(
            session_id=session_id,
            total_turns=total_turns,
            raw_cumulative_score=round(raw_sum, 4),
            decayed_score=round(normalized_decayed, 4),
            peak_turn_score=round(peak_score, 4),
            is_probe_attack=is_probe,
            alert_level=alert,
            recommendation=recommendation,
        )

    def reset(self, session_id: str) -> None:
        """Reset history for a given session ID."""
        with self._lock:
            self._sessions.pop(session_id, None)

    def clear(self) -> None:
        """Clear all active session tracking state."""
        with self._lock:
            self._sessions.clear()
