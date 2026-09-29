"""Structured audit logging implementation for security, compliance, and SIEM."""

import json
import logging
import sys
from typing import Any, Callable, Dict, List, Optional, TextIO

from llmfirewall.core.models import Action, AuditEvent, ScanRequest, ScanResult


class AuditLogger:
    """Security audit logger producing structured JSON telemetry.
    
    Security & Compliance Invariants:
    1. Zero Raw Secret Exposure: Credentials and private keys are NEVER logged.
    2. Zero Unmasked PII by Default: Customer emails, phones, and cards are never logged.
    3. Dedicated Separation: Audit logging is decoupled from detector and policy logic.
    4. Deterministic JSON: Output is strictly valid JSON Lines (JSONL) suitable for Splunk,
       Datadog, AWS CloudWatch, Elastic, or local file rotation.
    """

    def __init__(
        self,
        name: str = "llmfirewall.audit",
        sink: Optional[TextIO] = None,
        min_level: int = logging.INFO,
        formatter: Optional[Callable[[Dict[str, Any]], str]] = None,
    ) -> None:
        """
        Args:
            name: Logger name.
            sink: Stream output sink (defaults to sys.stdout).
            min_level: Standard logging level (logging.INFO, logging.WARNING, etc.).
            formatter: Optional custom serializer callable.
        """
        self._logger = logging.getLogger(name)
        self._logger.setLevel(min_level)
        self._sink = sink or sys.stdout
        self._custom_formatter = formatter

        # In-memory buffer for programmatic testing/retrieval
        self._buffered_events: List[AuditEvent] = []
        self._buffered_json_lines: List[str] = []

    @property
    def buffered_events(self) -> List[AuditEvent]:
        return list(self._buffered_events)

    @property
    def buffered_lines(self) -> List[str]:
        return list(self._buffered_json_lines)

    def clear(self) -> None:
        """Clear the in-memory event buffer."""
        self._buffered_events.clear()
        self._buffered_json_lines.clear()

    def log_scan(
        self,
        request: ScanRequest,
        result: ScanResult,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Construct, format, and emit a structured audit event from a scan.
        
        Args:
            request: The client's scan request envelope.
            result: The completed firewall scan outcome.
            metadata: Additional sanitized operational metadata (e.g. env, host).
            
        Returns:
            AuditEvent: The emitted immutable audit event.
        """
        event = AuditEvent.from_scan(request=request, result=result, metadata=metadata)
        self.emit(event)
        return event

    def emit(self, event: AuditEvent) -> None:
        """Serialize and write an AuditEvent to the configured sink and internal buffer."""
        raw_dict = event.model_dump(mode="json")

        if self._custom_formatter:
            line = self._custom_formatter(raw_dict)
        else:
            line = json.dumps(raw_dict, sort_keys=True)

        self._buffered_events.append(event)
        self._buffered_json_lines.append(line)

        # Write to stream sink
        try:
            self._sink.write(line + "\n")
            self._sink.flush()
        except Exception as exc:
            self._logger.error("Failed to write audit event to sink: %s", exc)


# Global default audit logger
default_audit_logger = AuditLogger()
