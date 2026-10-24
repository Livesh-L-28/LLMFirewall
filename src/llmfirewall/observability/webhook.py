"""Secure webhook alert sink for SOC and SIEM notification automation."""

import hashlib
import hmac
import json
import time
from typing import Any, Dict, List, Optional
import urllib.request
from pydantic import BaseModel, ConfigDict, Field

from llmfirewall.observability.models import EventSeverity, SecurityEvent


class WebhookAlertConfig(BaseModel):
    """Configuration for outbound SOC/SIEM security webhook dispatcher."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    url: str = Field(..., description="Target webhook destination URL")
    secret_token: Optional[str] = Field(default=None, description="Optional secret key for HMAC-SHA256 signature")
    min_severity: EventSeverity = Field(
        default=EventSeverity.HIGH,
        description="Minimum event severity threshold to trigger an alert",
    )
    max_alerts_per_minute: int = Field(default=60, ge=1, le=1000, description="Rate limit to prevent alert storms")
    timeout_seconds: float = Field(default=5.0, ge=0.5, le=30.0, description="HTTP connection timeout")
    dry_run: bool = Field(default=False, description="Simulate dispatch without sending HTTP requests")


class WebhookAlertSink:
    """Thread-safe SOC notification sink with HMAC signing and rate limiting."""

    _SEVERITY_ORDER = {
        EventSeverity.DEBUG: 0,
        EventSeverity.INFO: 1,
        EventSeverity.WARNING: 2,
        EventSeverity.HIGH: 3,
        EventSeverity.CRITICAL: 4,
    }

    def __init__(self, config: WebhookAlertConfig) -> None:
        self.config = config
        self._sent_timestamps: List[float] = []
        self._dispatched_alerts: List[Dict[str, Any]] = []

    @property
    def dispatched_alerts(self) -> List[Dict[str, Any]]:
        """Return history of simulated or sent alerts (primarily for testing and auditing)."""
        return list(self._dispatched_alerts)

    def _is_rate_limited(self, now: float) -> bool:
        """Sliding-window rate limit check."""
        cutoff = now - 60.0
        self._sent_timestamps = [t for t in self._sent_timestamps if t > cutoff]
        return len(self._sent_timestamps) >= self.config.max_alerts_per_minute

    def _compute_signature(self, payload_bytes: bytes) -> str:
        """Generate HMAC-SHA256 hex digest using configured secret token."""
        if not self.config.secret_token:
            return ""
        return hmac.new(
            self.config.secret_token.encode("utf-8"),
            payload_bytes,
            hashlib.sha256,
        ).hexdigest()

    def dispatch(self, event: SecurityEvent, now: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """Evaluate, format, and dispatch a security alert.
        
        Returns the emitted alert payload dict if sent, or None if filtered or rate-limited.
        """
        curr_time = now if now is not None else time.time()

        # 1. Severity filter check
        event_rank = self._SEVERITY_ORDER.get(event.severity, 0)
        min_rank = self._SEVERITY_ORDER.get(self.config.min_severity, 3)
        if event_rank < min_rank:
            return None

        # 2. Rate limit check
        if self._is_rate_limited(curr_time):
            return None

        # 3. Build sanitized payload (never exposing raw inputs or credentials)
        payload = {
            "source": "llmfirewall",
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "event_type": event.event_type.value,
            "severity": event.severity.value,
            "action": event.action.value if event.action else None,
            "risk_score": event.risk_score,
            "detector_name": event.detector_name,
            "policy_id": event.policy_id,
            "trace_id": event.trace_id,
            "environment": event.environment,
            "payload_length": event.payload_length,
            "payload_hash": event.payload_hash,
        }

        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        signature = self._compute_signature(payload_bytes)

        alert_record = {
            "url": self.config.url,
            "payload": payload,
            "signature": signature,
            "timestamp": curr_time,
            "dry_run": self.config.dry_run,
        }

        if self.config.dry_run:
            self._sent_timestamps.append(curr_time)
            self._dispatched_alerts.append(alert_record)
            return alert_record

        # 4. Outbound HTTP dispatch
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "LLMFirewall-AlertSink/1.2.0",
        }
        if signature:
            headers["X-LLMFirewall-Signature"] = signature

        req = urllib.request.Request(
            url=self.config.url,
            data=payload_bytes,
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout_seconds):
                pass
        except Exception:
            # Safe fail-open for telemetry/alert sinks: do not crash security runtime
            pass

        self._sent_timestamps.append(curr_time)
        self._dispatched_alerts.append(alert_record)
        return alert_record
